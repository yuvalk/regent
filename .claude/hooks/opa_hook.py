#!/usr/bin/env python3
"""Claude Code PreToolUse hook that consults OPA for policy decisions.

Reads hook JSON from stdin, posts it to an OPA server, and returns
a structured decision (allow/deny/ask). Fails closed on any error.
"""

import json
import os
import sys
import urllib.request
import urllib.error

OPA_URL = os.environ.get("OPA_URL", "http://localhost:8181")
OPA_POLICY_PATH = "/v1/data/claudecode/authz/result"
TIMEOUT_SECONDS = 5


def make_response(decision, reason):
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": decision,
            "permissionDecisionReason": reason,
        }
    }


def main():
    try:
        hook_input = json.loads(sys.stdin.read())
    except Exception:
        json.dump(make_response("deny", "failed to read hook input from stdin"), sys.stdout)
        sys.exit(0)

    opa_payload = json.dumps({"input": hook_input}).encode("utf-8")
    url = OPA_URL.rstrip("/") + OPA_POLICY_PATH

    try:
        req = urllib.request.Request(
            url,
            data=opa_payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=TIMEOUT_SECONDS) as resp:
            if resp.status != 200:
                json.dump(
                    make_response("deny", f"OPA returned HTTP {resp.status}"),
                    sys.stdout,
                )
                sys.exit(0)
            body = json.loads(resp.read().decode("utf-8"))
    except urllib.error.URLError as e:
        json.dump(make_response("deny", f"OPA unreachable: {e.reason}"), sys.stdout)
        sys.exit(0)
    except Exception as e:
        json.dump(make_response("deny", f"OPA request failed: {e}"), sys.stdout)
        sys.exit(0)

    # Extract the result from OPA response: {"result": {"decision": "...", "reason": "..."}}
    result = body.get("result")
    if not isinstance(result, dict):
        json.dump(make_response("deny", "OPA response missing 'result' object"), sys.stdout)
        sys.exit(0)

    decision = result.get("decision", "")
    reason = result.get("reason", "no reason provided")

    if decision not in ("allow", "deny", "ask"):
        json.dump(
            make_response("deny", f"invalid decision from OPA: '{decision}'"),
            sys.stdout,
        )
        sys.exit(0)

    json.dump(make_response(decision, reason), sys.stdout)
    sys.exit(0)


if __name__ == "__main__":
    main()
