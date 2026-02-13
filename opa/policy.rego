package claudecode.authz

import rego.v1

# Default result: deny any unrecognized tool
default result := {"decision": "deny", "reason": "tool not recognized or not explicitly allowed by policy"}

# Read-only tools -- always allow
result := {"decision": "allow", "reason": "read-only tool"} if {
	input.tool_name in {"Read", "Glob", "Grep", "WebSearch"}
}

# Bash -- allow unless command matches dangerous patterns
result := {"decision": "allow", "reason": "bash command permitted"} if {
	input.tool_name == "Bash"
	not bash_dangerous
}

result := {"decision": "deny", "reason": sprintf("dangerous bash command blocked: %s", [concat(", ", dangerous_bash_reasons)])} if {
	input.tool_name == "Bash"
	bash_dangerous
}

# Write / Edit -- allow only within cwd and not targeting sensitive files
result := {"decision": "allow", "reason": "file write within project directory"} if {
	input.tool_name in {"Write", "Edit"}
	write_in_cwd
	not write_sensitive
}

result := {"decision": "deny", "reason": "file write outside project directory"} if {
	input.tool_name in {"Write", "Edit"}
	not write_in_cwd
}

result := {"decision": "deny", "reason": sprintf("write to sensitive file blocked: %s", [write_target])} if {
	input.tool_name in {"Write", "Edit"}
	write_in_cwd
	write_sensitive
}

# WebFetch -- deny cloud metadata and localhost endpoints
result := {"decision": "allow", "reason": "web fetch permitted"} if {
	input.tool_name == "WebFetch"
	not webfetch_blocked
}

result := {"decision": "deny", "reason": sprintf("web fetch to blocked endpoint: %s", [input.tool_input.url])} if {
	input.tool_name == "WebFetch"
	webfetch_blocked
}

# Task (subagents) -- escalate to user
result := {"decision": "ask", "reason": "subagent launch requires user approval"} if {
	input.tool_name == "Task"
}

# -------------------------------------------------------------------
# Helper rules
# -------------------------------------------------------------------

# Bash: dangerous command patterns
dangerous_bash_patterns contains {"pattern": `rm\s+(-\w*\s+)*-\w*r\w*f`, "label": "rm -rf"} if true

dangerous_bash_patterns contains {"pattern": `\bsudo\b`, "label": "sudo"} if true

dangerous_bash_patterns contains {"pattern": `\bmkfs\b`, "label": "mkfs"} if true

dangerous_bash_patterns contains {"pattern": `\bdd\b.*\bof=/dev/`, "label": "dd to device"} if true

dangerous_bash_patterns contains {"pattern": `curl\s.*\|\s*bash`, "label": "curl | bash"} if true

dangerous_bash_patterns contains {"pattern": `wget\s.*\|\s*bash`, "label": "wget | bash"} if true

dangerous_bash_patterns contains {"pattern": `curl\s.*\|\s*sh`, "label": "curl | sh"} if true

dangerous_bash_patterns contains {"pattern": `wget\s.*\|\s*sh`, "label": "wget | sh"} if true

dangerous_bash_patterns contains {"pattern": `push\s+.*--force`, "label": "force push"} if true

dangerous_bash_patterns contains {"pattern": `push\s+-f\b`, "label": "force push"} if true

dangerous_bash_patterns contains {"pattern": `reset\s+--hard`, "label": "hard reset"} if true

dangerous_bash_patterns contains {"pattern": `\bshutdown\b`, "label": "shutdown"} if true

dangerous_bash_patterns contains {"pattern": `\breboot\b`, "label": "reboot"} if true

dangerous_bash_patterns contains {"pattern": `\binit\s+0\b`, "label": "init 0 (shutdown)"} if true

dangerous_bash_patterns contains {"pattern": `\bchmod\s+777\b`, "label": "chmod 777"} if true

dangerous_bash_patterns contains {"pattern": `>\s*/dev/sd`, "label": "write to block device"} if true

dangerous_bash_patterns contains {"pattern": `\b:()\s*\{\s*:\|:\s*&\s*\}\s*;`, "label": "fork bomb"} if true

bash_dangerous if {
	count(dangerous_bash_reasons) > 0
}

dangerous_bash_reasons contains label if {
	cmd := object.get(input.tool_input, "command", "")
	some entry in dangerous_bash_patterns
	regex.match(entry.pattern, cmd)
	label := entry.label
}

# Write/Edit: target file path
write_target := object.get(input.tool_input, "file_path", "")

# Write/Edit: check path is under cwd
write_in_cwd if {
	cwd := object.get(input, "cwd", "")
	cwd != ""
	startswith(write_target, cwd)
}

# Write/Edit: sensitive file patterns
sensitive_file_patterns := [
	`.env`,
	`/.git/`,
	`/.ssh/`,
	`credentials`,
	`.pem$`,
	`.key$`,
	`id_rsa`,
	`id_ed25519`,
	`\.secret`,
	`/\.aws/`,
	`/\.kube/config`,
	`shadow$`,
	`passwd$`,
]

write_sensitive if {
	some pattern in sensitive_file_patterns
	regex.match(pattern, write_target)
}

# WebFetch: blocked URL patterns
webfetch_blocked if {
	url := object.get(input.tool_input, "url", "")
	contains(url, "169.254.169.254")
}

webfetch_blocked if {
	url := object.get(input.tool_input, "url", "")
	contains(url, "metadata.google.internal")
}

webfetch_blocked if {
	url := object.get(input.tool_input, "url", "")
	regex.match(`https?://(localhost|127\.0\.0\.1)(:|/)`, url)
}
