FROM node:22-slim

# Install Python3 (for hook) and curl (for healthcheck/debugging)
RUN apt-get update && \
    apt-get install -y --no-install-recommends python3 curl git ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Install OPA binary
ARG OPA_VERSION=1.4.2
RUN curl -fsSL "https://github.com/open-policy-agent/opa/releases/download/v${OPA_VERSION}/opa_linux_$(dpkg --print-architecture)_static" \
      -o /usr/local/bin/opa && \
    chmod +x /usr/local/bin/opa

# Install Claude Code
RUN npm install -g @anthropic-ai/claude-code

# Set up home directory for the runtime user
ENV HOME=/home/claude
RUN useradd -m -d $HOME -s /bin/bash claude

# Copy OPA policy
COPY opa/policy.rego /opt/regent/policy.rego

# Install hook and settings globally for Claude Code
RUN mkdir -p $HOME/.claude/hooks
COPY .claude/hooks/opa_hook.py $HOME/.claude/hooks/opa_hook.py
RUN cat > $HOME/.claude/settings.json <<'EOF'
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

# Copy entrypoint
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

# Fix ownership
RUN chown -R claude:claude $HOME

USER claude
WORKDIR $HOME

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
