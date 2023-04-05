# RCE risks
unsafe_inputs = {
    "user_input_body_title": "\\${{\\s*github.event.(.*).(body|title)\\s*}}",
    "malicious_commit_message": "\\${{\\s*(.*).head_commit.message\\s*}}",
    "malicious_input": "\\${{\\s*(.*)github.event.review(.*)\\s*}}",
    "environ_regex": "\\${{\\s*env.[A-Za-z0-9_-]*\\s*}}",
    "malicious_author": "\\${{\\s*github.event.(.*).author.(name|email)\\s*}}",
}

malicious_commits = {
    "malicious_commit_referenced": "\\${{\\s*github.pull_request.head(.*)\\s*}}",
    "malicious_pull_request_event": "\\${{\\s*(.*)github.event.pull_request.head(.*)\\s*}}",
}

# Secrets
secrets_pattern = ("\\${{\\s*secrets\\.[A-Za-z-_0-9]*\\s*}}",)

# Github Events
dangerous_events = ["pull_request_target", "issues", "issue_comment"]
