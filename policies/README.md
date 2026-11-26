# Agent tool-call policy (OPA / Rego)

`agent_tools.rego` is the Policy Enforcement Point logic from Layer 1 of the architecture. A sidecar evaluates it for every outbound tool call an agent makes, and the call goes through only if the policy allows it.

## What it enforces

1. **Task allowlists.** Each task type may call only the tools listed for it. A summarizer can read and search documents, nothing else. Unknown task types are denied.
2. **Provenance rule against indirect prompt injection.** If the instruction to call a tool came from untrusted content (`tool_output` or `retrieved_document`), any side effect is denied. Side effects are the tools `send_reply`, `export_report`, `delete_record`, `transfer_funds`, or any `POST`, `PUT`, `PATCH` or `DELETE`. Reads from untrusted context are still allowed.
3. **Human approval for irreversible actions.** High-risk agents need at least one approval starting with `human:` before calling an irreversible tool. Approvals from other agents (for example `agent:reviewer-bot`) do not count.
4. **Egress caps by risk tier.** Low 1,000,000 bytes, medium 100,000, high 10,000. Unknown tiers are denied.
5. **MCP server allowlist (issue #10).** When the call names an MCP server (`mcp_server` set), the server must be approved for the task type in `mcp_server_allowlist`, at the pinned version, with an unchanged tool-manifest hash. A server that keeps its tool names but edits a description to inject instructions presents the same tools and a different hash — the hash pin refuses it. Calls without MCP provenance are governed by the rules above unchanged. See docs/mcp-server-allowlist.md for how to approve a server and re-approve a new version.

The policy is deny by default. `deny` collects human-readable reasons, `allow` is true only when `deny` is empty and the tool is permitted, and `decision` returns both.

## Input shape

```json
{
  "agent":     {"subject": "spiffe://lab/agent/x", "risk_tier": "low|medium|high"},
  "task":      {"type": "summarize|support_reply|finance_report"},
  "call":      {"tool": "send_reply", "method": "POST", "egress_bytes": 2048,
                "instruction_source": "user|system|tool_output|retrieved_document",
                "mcp_server": "docs-server",           // optional — MCP provenance
                "mcp_version": "1.2.0",                // optional — required for MCP calls
                "mcp_manifest_sha256": "c80acc22…"     // optional — hash of tools/list at call time
  },
  "approvals": ["human:alice"]
}
```

`instruction_source` is the hard part in practice. Your agent runtime has to tag where each instruction came from, and the tag must be set by the runtime, never by the model.

## Run it

Install OPA 1.x (a single static binary from the OPA releases page), then:

```bash
opa test policies/ -v          # run the unit tests
opa check policies/            # type and syntax check
opa fmt --diff policies/       # formatting check

echo '{"agent":{"subject":"spiffe://lab/agent/x","risk_tier":"low"},
       "task":{"type":"support_reply"},
       "call":{"tool":"send_reply","method":"POST","egress_bytes":500,
               "instruction_source":"retrieved_document"},
       "approvals":[]}' > /tmp/input.json

opa eval -d policies/agent_tools.rego -i /tmp/input.json 'data.agentguard.tools.decision'
```

The example is denied: a retrieved document tried to make the agent send a reply.

## Wiring it into Envoy

In the full design, each agent pod runs an Envoy sidecar with the `ext_authz` filter pointed at OPA (the `opa-envoy-plugin` build). Envoy forwards request attributes to OPA, and the agent's SPIFFE identity arrives through the mTLS peer certificate. You map those into the input shape above with a thin wrapper rule, for example:

```rego
package envoy.authz

import data.agentguard.tools

default allow := false

allow if tools.allow with input as {
	"agent": {"subject": input.attributes.source.principal, "risk_tier": data.tiers[input.attributes.source.principal]},
	"task": {"type": input.attributes.request.http.headers["x-task-type"]},
	"call": {
		"tool": input.parsed_path[1],
		"method": input.attributes.request.http.method,
		"egress_bytes": to_number(object.get(input.attributes.request.http.headers, "content-length", "0")),
		"instruction_source": input.attributes.request.http.headers["x-instruction-source"],
	},
	"approvals": [],
}
```

Headers like `x-instruction-source` must be set by a trusted runtime component and stripped from anything the model can write, otherwise an injected prompt could simply claim to be `user`. This wrapper is a sketch and is not covered by the tests here.

## Limits worth knowing

* **Fail closed on provenance.** Only `user` and `system` count as trusted instruction sources. A missing, misspelled or unknown source is treated as untrusted, so it cannot trigger side effects.
* **Provenance is only as honest as whoever sets it.** In the Envoy sketch above, `x-instruction-source` is a header the agent's own runtime sends, so a fully compromised runtime could lie. The stronger pattern is to have the orchestrator (not the model) tag each instruction's origin and sign it, then have the sidecar verify that signature. This is an open problem and a good place to contribute.
