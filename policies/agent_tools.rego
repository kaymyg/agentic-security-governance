# Agent tool-call policy (Layer 1: Runtime Policy Enforcement Point).
#
# Evaluated by a sidecar (Envoy ext_authz + OPA) for every outbound tool call
# an agent makes. Deny reasons are collected in `deny`; a call is allowed only
# when the tool is on the task's allowlist and no deny rule fires.
package agentguard.tools

# Tools each task type may call. Anything not listed is denied.
task_allowlist := {
        "summarize": {"read_doc", "search_docs"},
        "support_reply": {"read_ticket", "draft_reply", "send_reply"},
        "finance_report": {"read_ledger", "export_report"},
}

# MCP servers each task type may call, pinned by version and by the SHA-256
# hash of the server's tool manifest (names, descriptions, input schemas —
# see docs/mcp-server-allowlist.md for how the hash is computed). A malicious
# or silently updated server can change tool descriptions to inject
# instructions: the pinned hash refuses any manifest that differs from the
# approved one, even when every tool name is unchanged.
#
# `mcp_manifest_sha256` on the call is computed by the connector from the
# server's tools/list response right before the call; the pin here is the
# hash a human reviewed at approval time.
mcp_server_allowlist := {
        "summarize": {
                "docs-server": {
                        "version": "1.2.0",
                        "manifest_sha256": "c80acc220bf5402eeabe272a4b1fca3cb937e46e67c52ab6656a9ef4cced643a",
                },
        },
        "support_reply": {
                "crm-server": {
                        "version": "0.9.4",
                        "manifest_sha256": "1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f809",
                },
        },
        "finance_report": {},
}

approved_mcp_pin := mcp_server_allowlist[input.task.type][input.call.mcp_server]

# Tools with side effects outside the agent's own sandbox.
side_effect_tools := {"send_reply", "export_report", "delete_record", "transfer_funds"}

# Tools whose effects cannot be undone.
irreversible_tools := {"send_reply", "export_report", "delete_record", "transfer_funds"}

write_methods := {"POST", "PUT", "PATCH", "DELETE"}

# Only these instruction sources are trusted. Anything else, including a
# missing or misspelled source, is treated as untrusted (fail closed), since
# tool output and retrieved documents can carry indirect prompt injection.
trusted_sources := {"user", "system"}

instruction_source := object.get(input.call, "instruction_source", "missing")

untrusted_source if not instruction_source in trusted_sources

egress_caps := {
        "low": 1000000,
        "medium": 100000,
        "high": 10000,
}

default allow := false

allow if {
        count(deny) == 0
        tool_permitted
}

tool_permitted if input.call.tool in task_allowlist[input.task.type]

is_side_effect if input.call.tool in side_effect_tools

is_side_effect if upper(input.call.method) in write_methods

has_human_approval if {
        some approver in object.get(input, "approvals", [])
        startswith(approver, "human:")
}

deny contains msg if {
        not task_allowlist[input.task.type]
        msg := sprintf("unknown task type %q", [input.task.type])
}

deny contains msg if {
        task_allowlist[input.task.type]
        not tool_permitted
        msg := sprintf("tool %q is not allowed for task %q", [input.call.tool, input.task.type])
}

deny contains msg if {
        untrusted_source
        is_side_effect
        msg := sprintf(
                "side-effect call %q was requested by untrusted content (%s)",
                [input.call.tool, instruction_source],
        )
}

deny contains msg if {
        input.agent.risk_tier == "high"
        input.call.tool in irreversible_tools
        not has_human_approval
        msg := sprintf("irreversible tool %q requires human approval for high-risk agents", [input.call.tool])
}

deny contains msg if {
        not egress_caps[input.agent.risk_tier]
        msg := sprintf("unknown risk tier %q", [input.agent.risk_tier])
}

deny contains msg if {
        cap := egress_caps[input.agent.risk_tier]
        input.call.egress_bytes > cap
        msg := sprintf(
                "egress %d bytes exceeds %s-tier cap of %d",
                [input.call.egress_bytes, input.agent.risk_tier, cap],
        )
}

# ── MCP server allowlist (issue #10) ────────────────────────────────────────
# These rules only fire when the call names an MCP server (`mcp_server` set);
# a call without MCP provenance is governed by the rules above as before.
# Every check is fail closed: a missing version or hash does not match a pin.

deny contains msg if {
        input.call.mcp_server
        not approved_mcp_pin
        msg := sprintf(
                "mcp server %q is not approved for task %q (allowlist is deny-by-default)",
                [input.call.mcp_server, input.task.type],
        )
}

deny contains msg if {
        pin := approved_mcp_pin
        pin.version != object.get(input.call, "mcp_version", "")
        msg := sprintf(
                "mcp server %q is pinned at version %s but the call presents version %s — approve the new version before use",
                [input.call.mcp_server, pin.version, object.get(input.call, "mcp_version", "")],
        )
}

deny contains msg if {
        pin := approved_mcp_pin
        pin.manifest_sha256 != object.get(input.call, "mcp_manifest_sha256", "")
        msg := sprintf(
                "mcp server %q tool manifest changed since approval (pinned %s, presented %s) — review the new manifest and re-approve",
                [input.call.mcp_server, pin.manifest_sha256, object.get(input.call, "mcp_manifest_sha256", "")],
        )
}

decision := {"allow": allow, "reasons": deny}
