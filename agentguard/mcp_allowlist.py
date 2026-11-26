"""MCP server allowlist with version and manifest pinning (Layer 1: identity).

The blueprint red-teams MCP tool servers, but does not control which servers
an agent may connect to. A malicious or silently updated MCP server can change
tool descriptions to inject instructions into the agent: the tool names stay
the same, so nothing downstream notices.

This module pins, per task type, which MCP servers are approved — and *what*
was approved:

- the server's declared version, and
- the SHA-256 hash of its tool manifest (names, descriptions, input schemas).

A call is refused when the server is not approved for the task type, when the
presented version differs from the pinned one, or when the manifest hash
changed — the "tool description changed after approval" case, which is exactly
how description-based instruction injection ships undetected.

Hash is over canonical JSON (sorted keys, no whitespace) of the manifest's
tool list, so the same manifest always yields the same hash across languages
and processes.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field


@dataclass(frozen=True)
class McpTool:
    """One tool as exposed by an MCP server (from tools/list)."""

    name: str
    description: str
    input_schema: dict = field(default_factory=dict)


@dataclass(frozen=True)
class ToolManifest:
    """The full tool surface of one MCP server at one point in time."""

    server: str
    version: str
    tools: tuple[McpTool, ...]

    def canonical_tools(self) -> str:
        """Canonical JSON of the tool list: order-independent, no whitespace."""
        items = [
            {"name": t.name, "description": t.description, "input_schema": t.input_schema}
            for t in self.tools
        ]
        items.sort(key=lambda item: item["name"])
        return json.dumps(items, sort_keys=True, separators=(",", ":"))

    def manifest_hash(self) -> str:
        """SHA-256 of the canonical tool list, hex encoded."""
        return hashlib.sha256(self.canonical_tools().encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class ServerPin:
    """What was approved for one server under one task type."""

    server: str
    version: str
    manifest_hash: str


class McpServerAllowlist:
    """Approved MCP servers per task type, pinned by version and manifest hash.

    Fail closed: a server that is not explicitly approved for the task type is
    refused; an approved server whose version or manifest hash drifted is
    refused until someone re-approves it (see docs/mcp-server-allowlist.md).
    """

    def __init__(self) -> None:
        # task_type -> server -> ServerPin
        self._pins: dict[str, dict[str, ServerPin]] = {}

    def approve(
        self,
        task_type: str,
        server: str,
        version: str,
        tools: tuple[McpTool, ...] | list[McpTool],
    ) -> ServerPin:
        """Approve `server` at `version` with this exact tool manifest."""
        manifest = ToolManifest(server=server, version=version, tools=tuple(tools))
        pin = ServerPin(server=server, version=version, manifest_hash=manifest.manifest_hash())
        self._pins.setdefault(task_type, {})[server] = pin
        return pin

    def is_approved(self, task_type: str, server: str) -> bool:
        return server in self._pins.get(task_type, {})

    def pin(self, task_type: str, server: str) -> ServerPin | None:
        return self._pins.get(task_type, {}).get(server)

    def check(
        self,
        task_type: str,
        server: str,
        version: str,
        tools: tuple[McpTool, ...] | list[McpTool],
    ) -> tuple[bool, str]:
        """Return (allowed, reason). Empty reason means allowed.

        Every refusal names what drifted, so the fix (re-approve a reviewed
        update) is never a guess.
        """
        pin = self.pin(task_type, server)
        if pin is None:
            return False, (
                f"mcp server '{server}' is not approved for task type '{task_type}' "
                "(allowlist is deny-by-default)"
            )
        if version != pin.version:
            return False, (
                f"mcp server '{server}' is pinned at version {pin.version} but the call "
                f"presents version {version} — approve the new version before use"
            )
        presented = ToolManifest(server=server, version=version, tools=tuple(tools)).manifest_hash()
        if presented != pin.manifest_hash:
            return False, (
                f"mcp server '{server}' tool manifest changed since approval "
                f"(pinned {pin.manifest_hash[:12]}…, presented {presented[:12]}…) — "
                "a tool name, description or schema was added or edited; review and re-approve"
            )
        return True, ""
