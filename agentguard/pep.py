"""Policy Enforcement Point (Layer 1: runtime proxy).

Every outbound tool call an agent makes passes through `PolicyEnforcementPoint.
authorize`. In production this logic sits in a sidecar (Envoy + OPA/Cedar);
here it is a plain Python object so the ideas can be read and tested.

Checks, in order (first failure wins, every decision is audited):

1. token is valid, unexpired and not revoked
2. the tool and method are inside the token's capability claims
3. provenance: instructions that came from untrusted content (tool output,
   retrieved documents) may not trigger side-effect tools
4. irreversible tools need an explicit human approval
5. egress stays under the token's cap
6. no honey-token appears in the arguments (hit = revoke + kill agent)
7. deterministic circuit breakers allow the action's metrics
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .audit import AuditLog
from .breakers import CircuitBreaker
from .capability import TokenBroker, TokenError
from .honeytokens import HoneyTokenRegistry
from .mcp_allowlist import McpServerAllowlist, McpTool
from .revocation import RevocationBus

# Only these sources are trusted. Anything else (tool output, retrieved
# documents, a typo, an empty string) is untrusted: fail closed.
TRUSTED_SOURCES = frozenset({"user", "system"})
SIDE_EFFECT_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


@dataclass
class ToolCall:
    tool: str
    method: str = "GET"
    args: dict = field(default_factory=dict)
    instruction_source: str = "user"  # user | system | tool_output | retrieved_document
    egress_bytes: int = 0
    metrics: dict[str, float] = field(default_factory=dict)
    human_approval: str | None = None  # e.g. "human:alice"
    # MCP provenance: which server hosted this tool, its declared version and
    # the tool manifest it presented at call time (tools/list). When absent,
    # the call is not an MCP-mediated call and the MCP allowlist (if one is
    # configured) does not apply to it.
    mcp_server: str | None = None
    mcp_version: str | None = None
    mcp_tools: "tuple[McpTool, ...] | None" = None


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str


class PolicyEnforcementPoint:
    def __init__(
        self,
        broker: TokenBroker,
        bus: RevocationBus,
        breaker: CircuitBreaker,
        honeytokens: HoneyTokenRegistry,
        audit: AuditLog,
        irreversible_tools: set[str] | None = None,
        mcp_allowlist: "McpServerAllowlist | None" = None,
        task_type: str = "general",
    ) -> None:
        self.broker = broker
        self.bus = bus
        self.breaker = breaker
        self.honeytokens = honeytokens
        self.audit = audit
        self.irreversible = frozenset(
            irreversible_tools
            or {"send_email", "transfer_funds", "delete_record", "export_report"}
        )
        # Optional MCP allowlist: when configured, every call that names an MCP
        # server must present a server approved for `task_type`, at the pinned
        # version, with an unchanged tool manifest.
        self.mcp_allowlist = mcp_allowlist
        self.task_type = task_type
        bus.subscribe(self._on_revocation)

    def authorize(self, token: str, call: ToolCall) -> Decision:
        method = call.method.upper()
        try:
            cap = self.broker.verify(token)
        except TokenError as exc:
            return self._decide(False, f"token rejected: {exc}", call, subject="?")
        subject = cap.subject

        if self.bus.is_revoked(cap.jti, subject):
            return self._decide(False, "token or agent revoked", call, subject)
        if call.tool not in cap.tools:
            return self._decide(False, f"tool '{call.tool}' not in capability", call, subject)
        if method not in cap.methods:
            return self._decide(False, f"method {method} not in capability", call, subject)

        # MCP allowlist: refuse servers that are not approved for this task
        # type, or whose version or tool manifest drifted after approval.
        # A changed manifest is the description-injection case: the tool name
        # is unchanged, so only the pinned hash catches it.
        if self.mcp_allowlist is not None and call.mcp_server is not None:
            ok, reason = self.mcp_allowlist.check(
                self.task_type,
                call.mcp_server,
                call.mcp_version or "",
                call.mcp_tools or (),
            )
            if not ok:
                return self._decide(False, reason, call, subject)

        side_effect = method in SIDE_EFFECT_METHODS or call.tool in self.irreversible
        if side_effect and call.instruction_source not in TRUSTED_SOURCES:
            return self._decide(
                False,
                f"side-effect call driven by untrusted source '{call.instruction_source}' "
                "(possible indirect prompt injection)",
                call,
                subject,
            )
        if call.tool in self.irreversible and not (
            call.human_approval and call.human_approval.startswith("human:")
        ):
            return self._decide(False, f"'{call.tool}' needs human approval", call, subject)
        if call.egress_bytes > cap.max_egress_bytes:
            return self._decide(
                False,
                f"egress {call.egress_bytes}B exceeds cap {cap.max_egress_bytes}B",
                call,
                subject,
            )

        hits = self.honeytokens.scan(call.args)
        if hits:
            labels = ", ".join(h.label for h in hits)
            self.bus.kill_agent(subject, f"honey-token used ({labels})")
            self.breaker.trip(subject)
            return self._decide(False, f"honey-token touched: {labels}", call, subject)

        metrics = dict(call.metrics)
        if call.egress_bytes:
            metrics.setdefault("egress_bytes", call.egress_bytes)
        br = self.breaker.check(subject, metrics)
        if not br.allowed:
            return self._decide(False, f"circuit breaker: {br.reason}", call, subject)

        return self._decide(True, "ok", call, subject)

    def _decide(self, allowed: bool, reason: str, call: ToolCall, subject: str) -> Decision:
        # Audit the decision, not the payload: arguments may hold sensitive data.
        self.audit.append(
            "authz",
            subject=subject,
            tool=call.tool,
            method=call.method.upper(),
            source=call.instruction_source,
            allowed=allowed,
            reason=reason,
        )
        return Decision(allowed, reason)

    def _on_revocation(self, kind: str, value: str, reason: str) -> None:
        self.audit.append("revocation", kind=kind, value=value, reason=reason)
