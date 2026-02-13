# Regent

Policy enforcement for Claude Code using [Open Policy Agent](https://www.openpolicyagent.org/).

Regent intercepts every Claude Code tool execution via a `PreToolUse` hook and consults an OPA server for an allow/deny/ask decision before the tool runs. This gives external, declarative control over what Claude Code can do.

```
Claude Code            Python Hook              OPA Server
(PreToolUse)  --->    (opa_hook.py)    --->    (policy.rego)
              <---    decision JSON    <---    POST /v1/data/claudecode/authz
```

## Policy Rules

| Tool | Decision | Condition |
|------|----------|-----------|
| Read, Glob, Grep, WebSearch | **allow** | Always (read-only) |
| Bash | **allow** | Unless command matches dangerous patterns |
| Bash | **deny** | `rm -rf`, `sudo`, `mkfs`, `dd` to device, `curl\|bash`, force push, hard reset, `shutdown`, `reboot`, `chmod 777`, fork bomb, etc. |
| Write, Edit | **allow** | File is within `cwd` and not sensitive |
| Write, Edit | **deny** | File is outside `cwd`, or targets `.env`, `.git/`, `.ssh/`, credentials, `.pem`, `.key`, etc. |
| WebFetch | **allow** | Unless URL is a blocked endpoint |
| WebFetch | **deny** | Cloud metadata (`169.254.169.254`, `metadata.google.internal`), localhost |
| Task (subagents) | **ask** | Always escalated to user prompt |
| Any other tool | **deny** | Default deny |

## Setup

### 1. Start OPA

Using podman:

```bash
podman run -d --name opa -p 8181:8181 openpolicyagent/opa:latest run --server
```

Or install OPA locally and run:

```bash
opa run --server opa/policy.rego
```

### 2. Load the Policy

If running OPA without the policy file mounted, load it via the REST API:

```bash
curl -X PUT http://localhost:8181/v1/policies/claudecode \
  --data-binary @opa/policy.rego \
  -H "Content-Type: text/plain"
```

### 3. Install the Hook

#### Per-project (this repo only)

The `.claude/settings.json` in this repo registers the hook automatically when Claude Code runs in this project directory. No additional steps needed.

#### Global (all projects)

To enforce the policy across all Claude Code sessions, copy the hook and settings to `~/.claude/`:

```bash
mkdir -p ~/.claude/hooks
cp .claude/hooks/opa_hook.py ~/.claude/hooks/opa_hook.py
```

Then add the hook to `~/.claude/settings.json`. If the file doesn't exist, create it:

```bash
cat > ~/.claude/settings.json << 'EOF'
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "",
        "hooks": [
          {
            "type": "command",
            "command": "python3 ~/.claude/hooks/opa_hook.py"
          }
        ]
      }
    ]
  }
}
EOF
```

If you already have a `~/.claude/settings.json`, merge the `hooks` section into it.

#### Configuration

The hook connects to `http://localhost:8181` by default. Override with the `OPA_URL` environment variable:

```bash
OPA_URL=http://opa-server:8181 claude
```

## How It Works

1. Claude Code triggers a `PreToolUse` event before each tool execution
2. The hook script (`.claude/hooks/opa_hook.py`) receives the event as JSON on stdin
3. It posts `{"input": <event>}` to the OPA server
4. OPA evaluates the Rego policy and returns a decision
5. The hook returns the decision to Claude Code as structured JSON

The hook **fails closed**: if OPA is unreachable, returns an error, or produces an invalid response, the tool is denied.

## Testing

Test the policy against a running OPA server:

```bash
# Safe bash command (expect: allow)
curl -s http://localhost:8181/v1/data/claudecode/authz/result \
  -d '{"input":{"tool_name":"Bash","tool_input":{"command":"ls"},"cwd":"/tmp"}}' | python3 -m json.tool

# Dangerous command (expect: deny)
curl -s http://localhost:8181/v1/data/claudecode/authz/result \
  -d '{"input":{"tool_name":"Bash","tool_input":{"command":"sudo rm -rf /"},"cwd":"/tmp"}}' | python3 -m json.tool
```

Test the full hook end-to-end:

```bash
echo '{"tool_name":"Bash","tool_input":{"command":"ls"},"cwd":"/tmp","session_id":"test","permission_mode":"default","hook_event_name":"PreToolUse"}' | \
  python3 .claude/hooks/opa_hook.py
```

## Project Structure

```
.claude/
  hooks/
    opa_hook.py       # PreToolUse hook script
  settings.json       # Claude Code hook registration
opa/
  policy.rego         # OPA authorization policy
```
