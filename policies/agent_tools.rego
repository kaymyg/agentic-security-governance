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

decision := {"allow": allow, "reasons": deny}
