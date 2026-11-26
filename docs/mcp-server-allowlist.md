# MCP server allowlist — approving and re-approving servers (issue #10)

Every MCP server an agent may talk to is approved **per task type**, pinned by
**version** and by the **SHA-256 hash of its tool manifest** (tool names,
descriptions and input schemas). The hash is what stops the attack the
allowlist alone cannot: a server that keeps its tool names but edits a
description to smuggle instructions into the agent presents the same tools
and a different manifest — the pinned hash refuses it.

There are two implementations of the same control:

| Layer | File | Enforced where |
|---|---|---|
| Python reference check | `agentguard/mcp_allowlist.py` (`McpServerAllowlist`), wired into `agentguard/pep.py` | unit-testable PEP |
| Sidecar policy | `policies/agent_tools.rego` (`mcp_server_allowlist`, `approved_mcp_pin`) | OPA / Envoy ext_authz |

Both are deny-by-default: a server that is not approved for the task type is
refused, and so is an approved server whose version or manifest hash drifted.

## The manifest hash

The hash is computed over a **canonical JSON** form of the tool list — sorted
keys, no whitespace, tools sorted by name — so the same manifest hashes the
same across languages and processes. `ToolManifest.canonical_tools()` in
`agentguard/mcp_allowlist.py` is the reference implementation; in other
languages, replicate it exactly:

```python
import hashlib, json

def manifest_hash(tools: list[dict]) -> str:
    # tools: [{"name": ..., "description": ..., "input_schema": ...}, ...]
    items = [
        {"name": t["name"], "description": t["description"], "input_schema": t.get("input_schema", {})}
        for t in tools
    ]
    items.sort(key=lambda i: i["name"])
    canonical = json.dumps(items, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()
```

Worked example — the two-tool manifest used in the policies:

```json
[
  {"name": "read_doc",   "description": "Read a document by id.",
   "input_schema": {"type": "object", "properties": {"id": {"type": "string"}}, "required": ["id"]}},
  {"name": "search_docs", "description": "Search the document store.",
   "input_schema": {"type": "object", "properties": {"query": {"type": "string"}}, "required": ["query"]}}
]
```

canonical SHA-256: `c80acc220bf5402eeabe272a4b1fca3cb937e46e67c52ab6656a9ef4cced643a`
(this is the pin in `policies/agent_tools.rego` and the hash the rego and
Python tests assert against).

## Approving a new server

1. **Fetch the manifest** — call the server's `tools/list` and record what it
   returns (names, descriptions, input schemas) and its declared version.
2. **Review the manifest as if it were code.** Tool descriptions are
   instructions the model will read: look for imperative language ("always",
   "ignore", "before anything else"), hidden exfiltration in schemas, tools
   that reach outside their stated scope.
3. **Compute the hash** as above.
4. **Register the pin.** Python: `allowlist.approve(task_type, server,
   version, tools)`. Policy: add an entry to `mcp_server_allowlist` in
   `policies/agent_tools.rego` with the version and hash.
5. **Audit.** Record who reviewed what, which manifest hash was approved and
   when — the pin is only as trustworthy as the review behind it.

## Approving a new server version (re-approval)

When a pinned server calls with a different version or the pinned hash no
longer matches, both the Python check and the rego policy refuse the call and
say so:

```
mcp server 'docs-server' is pinned at version 1.2.0 but the call presents
version 1.3.0 — approve the new version before use
```

```
mcp server "docs-server" tool manifest changed since approval (pinned
c80acc22…, presented 4b1e9d0f…) — review the new manifest and re-approve
```

The recovery is deliberate, never automatic:

1. **Diff the manifests** — old manifest (from the approval audit) against the
   one the server presents now. New tools, removed tools, edited descriptions
   and schema changes all change the hash; the diff tells you which.
2. **Re-review** the changed tools exactly as in step 2 above. A server that
   rephrased a description between 1.2.0 and 1.3.0 has not necessarily done
   anything wrong — but the change is what an attacker would ship, so the
   review is not optional.
3. **Re-pin** — `allowlist.approve(...)` with the new version (and its new
   hash), or update the entry in `mcp_server_allowlist`. Do not "fix" drift by
   widening or removing pins.
4. **Verify** — the next call through the allowlist must pass; the refusal
   reason is gone. In the Python tests this flow is
   `test_re_approval_after_review_allows_the_new_manifest`.

If the server is publishing every tool change as a version bump, version and
hash drift together and re-approval stays routine. The dangerous case is the
one the hash exists for: same version, changed manifest — treat it as a
security incident, not an upgrade.

## Input shape (rego)

The call-level fields added by this control:

```json
{
  "call": {
    "tool": "read_doc",
    "method": "GET",
    "mcp_server": "docs-server",
    "mcp_version": "1.2.0",
    "mcp_manifest_sha256": "c80acc220bf5402eeabe272a4b1fca3cb937e46e67c52ab6656a9ef4cced643a"
  }
}
```

The connector computes `mcp_manifest_sha256` from the server's `tools/list`
response immediately before the call, so what is compared is what the server
is presenting *right now* — not what it said at startup. Calls without MCP
provenance are governed by the rest of the policy unchanged.

## Running the checks

```bash
# Python: check + PEP integration, including the description-changed case
python3 -m pytest tests/test_mcp_allowlist.py -q

# Policy: rule syntax and behaviour
opa check policies/agent_tools.rego
opa test policies/ -v
```
