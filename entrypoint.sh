#!/bin/bash
set -e

# Start OPA server in the background with the policy loaded
opa run --server /opt/regent/policy.rego &
OPA_PID=$!

# Wait for OPA to be ready
for i in $(seq 1 30); do
    if curl -sf http://localhost:8181/health > /dev/null 2>&1; then
        break
    fi
    sleep 0.2
done

if ! curl -sf http://localhost:8181/health > /dev/null 2>&1; then
    echo "Error: OPA server failed to start" >&2
    exit 1
fi

# Run Claude Code, forwarding all arguments
exec claude "$@"
