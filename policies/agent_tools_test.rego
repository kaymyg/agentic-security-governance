package agentguard.tools_test

import data.agentguard.tools

base := {
	"agent": {"subject": "spiffe://lab/agent/helper", "risk_tier": "low"},
	"task": {"type": "summarize"},
	"call": {"tool": "read_doc", "method": "GET", "egress_bytes": 500, "instruction_source": "user"},
	"approvals": [],
}

with_call(fields) := object.union(base, {"call": object.union(base.call, fields)})

test_allows_listed_read_tool if {
	tools.allow with input as base
}

test_denies_tool_not_on_allowlist if {
	not tools.allow with input as with_call({"tool": "send_reply"})
	tools.deny["tool \"send_reply\" is not allowed for task \"summarize\""] with input as with_call({"tool": "send_reply"})
}

test_denies_unknown_task_type if {
	inp := object.union(base, {"task": {"type": "mine_crypto"}})
	not tools.allow with input as inp
	tools.deny["unknown task type \"mine_crypto\""] with input as inp
}

test_allows_send_reply_from_user_low_risk if {
	inp := object.union(with_call({"tool": "send_reply", "method": "POST"}), {"task": {"type": "support_reply"}})
	tools.allow with input as inp
}

test_denies_side_effect_from_retrieved_document if {
	inp := object.union(
		with_call({"tool": "send_reply", "method": "POST", "instruction_source": "retrieved_document"}),
		{"task": {"type": "support_reply"}},
	)
	not tools.allow with input as inp
	count(tools.deny) == 1 with input as inp
}

test_denies_side_effect_from_tool_output if {
	inp := object.union(
		with_call({"tool": "export_report", "instruction_source": "tool_output"}),
		{"task": {"type": "finance_report"}},
	)
	not tools.allow with input as inp
}

test_denies_write_method_from_untrusted_source if {
	# read tool, but a POST requested by untrusted content is still a side effect
	inp := with_call({"method": "POST", "instruction_source": "tool_output"})
	not tools.allow with input as inp
}

test_allows_read_from_untrusted_source if {
	tools.allow with input as with_call({"instruction_source": "retrieved_document"})
}

test_high_risk_irreversible_needs_human_approval if {
	inp := {
		"agent": {"subject": "spiffe://lab/agent/fin", "risk_tier": "high"},
		"task": {"type": "finance_report"},
		"call": {"tool": "export_report", "method": "POST", "egress_bytes": 100, "instruction_source": "user"},
		"approvals": [],
	}
	not tools.allow with input as inp
}

test_high_risk_irreversible_allowed_with_human_approval if {
	inp := {
		"agent": {"subject": "spiffe://lab/agent/fin", "risk_tier": "high"},
		"task": {"type": "finance_report"},
		"call": {"tool": "export_report", "method": "POST", "egress_bytes": 100, "instruction_source": "user"},
		"approvals": ["human:alice"],
	}
	tools.allow with input as inp
}

test_machine_approval_does_not_count if {
	inp := {
		"agent": {"subject": "spiffe://lab/agent/fin", "risk_tier": "high"},
		"task": {"type": "finance_report"},
		"call": {"tool": "export_report", "method": "POST", "egress_bytes": 100, "instruction_source": "user"},
		"approvals": ["agent:reviewer-bot"],
	}
	not tools.allow with input as inp
}

test_missing_approvals_field_is_safe if {
	inp := {
		"agent": {"subject": "spiffe://lab/agent/fin", "risk_tier": "high"},
		"task": {"type": "finance_report"},
		"call": {"tool": "export_report", "method": "POST", "egress_bytes": 100, "instruction_source": "user"},
	}
	not tools.allow with input as inp
}

test_egress_cap_per_tier if {
	medium := object.union(base, {"agent": {"subject": "spiffe://lab/agent/helper", "risk_tier": "medium"}})
	tools.allow with input as object.union(medium, {"call": object.union(base.call, {"egress_bytes": 100000})})
	not tools.allow with input as object.union(medium, {"call": object.union(base.call, {"egress_bytes": 100001})})
}

test_high_tier_egress_cap if {
	high := object.union(base, {"agent": {"subject": "spiffe://lab/agent/helper", "risk_tier": "high"}})
	not tools.allow with input as object.union(high, {"call": object.union(base.call, {"egress_bytes": 10001})})
}

test_denies_unknown_risk_tier if {
	inp := object.union(base, {"agent": {"subject": "spiffe://lab/agent/helper", "risk_tier": "godmode"}})
	not tools.allow with input as inp
}

test_decision_shape if {
	d := tools.decision with input as with_call({"tool": "transfer_funds"})
	d.allow == false
	count(d.reasons) > 0
}

test_missing_instruction_source_fails_closed if {
	call := object.remove(object.union(base.call, {"tool": "send_reply", "method": "POST"}), ["instruction_source"])
	inp := object.union(object.remove(base, ["call"]), {"call": call, "task": {"type": "support_reply"}})
	not tools.allow with input as inp
	tools.deny["side-effect call \"send_reply\" was requested by untrusted content (missing)"] with input as inp
}

test_unknown_instruction_source_fails_closed if {
	inp := object.union(with_call({"tool": "send_reply", "method": "POST", "instruction_source": "User"}), {"task": {"type": "support_reply"}})
	not tools.allow with input as inp
}

test_missing_source_still_allows_reads if {
	call := object.remove(base.call, ["instruction_source"])
	inp := object.union(object.remove(base, ["call"]), {"call": call})
	tools.allow with input as inp
}

# ── MCP server allowlist (issue #10) ──────────────────────────────────────

mcp_hash := "c80acc220bf5402eeabe272a4b1fca3cb937e46e67c52ab6656a9ef4cced643a"

mcp_call(fields) := object.union(base, {
	"call": object.union(base.call, {
		"mcp_server": object.get(fields, "server", "docs-server"),
		"mcp_version": object.get(fields, "version", "1.2.0"),
		"mcp_manifest_sha256": object.get(fields, "hash", mcp_hash),
	}),
})

mcp_call_missing_version := object.union(base, {
	"call": object.union(base.call, {"mcp_server": "docs-server", "mcp_manifest_sha256": mcp_hash}),
})

mcp_call_missing_hash := object.union(base, {
	"call": object.union(base.call, {"mcp_server": "docs-server", "mcp_version": "1.2.0"}),
})

test_allows_approved_mcp_server_with_unchanged_manifest if {
	tools.allow with input as mcp_call({})
}

test_allows_non_mcp_call_without_mcp_fields if {
	# A call that does not name a server is governed by the rules above only.
	tools.allow with input as base
}

test_denies_mcp_server_not_approved if {
	inp := mcp_call({"server": "evil-server"})
	not tools.allow with input as inp
	tools.deny["mcp server \"evil-server\" is not approved for task \"summarize\" (allowlist is deny-by-default)"] with input as inp
}

test_denies_mcp_version_drift if {
	inp := mcp_call({"version": "1.3.0"})
	not tools.allow with input as inp
	tools.deny["mcp server \"docs-server\" is pinned at version 1.2.0 but the call presents version 1.3.0 — approve the new version before use"] with input as inp
}

test_denies_mcp_version_missing if {
	# Fail closed: a call that presents no version cannot match a pin.
	not tools.allow with input as mcp_call_missing_version
}

test_denies_manifest_hash_drift if {
	# The "tool description changed after approval" case: same server, same
	# version, one edited description — only the pinned hash catches it.
	tampered := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	inp := mcp_call({"hash": tampered})
	not tools.allow with input as inp
	tools.deny["mcp server \"docs-server\" tool manifest changed since approval (pinned c80acc220bf5402eeabe272a4b1fca3cb937e46e67c52ab6656a9ef4cced643a, presented aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa) — review the new manifest and re-approve"] with input as inp
}

test_denies_manifest_hash_missing if {
	not tools.allow with input as mcp_call_missing_hash
}

test_denies_mcp_server_for_task_without_entries if {
	inp := object.union(mcp_call({}), {"task": {"type": "finance_report"}})
	not tools.allow with input as inp
	tools.deny["mcp server \"docs-server\" is not approved for task \"finance_report\" (allowlist is deny-by-default)"] with input as inp
}

test_denies_unknown_server_for_unknown_task_type if {
	inp := object.union(mcp_call({}), {"task": {"type": "mine_crypto"}})
	not tools.allow with input as inp
	tools.deny["unknown task type \"mine_crypto\""] with input as inp
	tools.deny["mcp server \"docs-server\" is not approved for task \"mine_crypto\" (allowlist is deny-by-default)"] with input as inp
}
