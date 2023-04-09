#### RCE risks
unsafe_inputs = {
    "exploitable_input": "\\${{\\s*github.event.(.*).(body|title)\\s*}}",
    #  add  regex for github.event.comment.body and event.comment.user.login
    "malicious_commit_message": "\\${{\\s*(.*).head_commit.message\\s*}}",
    "malicious_input": "\\${{\\s*(.*)github.event.review(.*)\\s*}}",
    "environ_regex": "\\${{\\s*env.[A-Za-z0-9_-]*\\s*}}",
    "malicious_author": "\\${{\\s*github.event.(.*).author.(name|email)\\s*}}",
}


malicious_commits = {
    "malicious_commit_referenced": "\\${{\\s*github.pull_request.head(.*)\\s*}}",
    "malicious_pull_request_event": "\\${{\\s*(.*)github.event.pull_request.head(.*)\\s*}}",
}

#### Secrets
secrets_pattern = "\\${{\\s*secrets\\.[A-Za-z-_0-9]*\\s*}}"

#### Github Events
dangerous_events = ["pull_request_target", "issues", "issue_comment"]


###################
# Report Messages #
###################

issue = {
    "pwn_requests": "The workflow is vulnerable to pwn requests. Vulnerable step: {STEP}.",
    "rce_with_user_input": "[Unsanitized input](https://securitylab.github.com/research/github-actions-untrusted-input/) detected with {REGEX} in {STEP}. Potentially malicious input called through GitHub context: `{ENV_NAME}:{ENV_VALUE}`.",
    "rce_general": "RCE detected with {REGEX}. Usage of `{MATCH}` found in {STEP}.",
    "supply_chain": "User/Org `{PUBLISHER}` not found in Github. Actions by this publisher could be maliciously taken over."
}
remediation = {
    "pwn_requests": "Do NOT checkout the PR branch when using `pull_request_type`. Consider [other options](https://securitylab.github.com/research/github-actions-preventing-pwn-requests/).",
    "rce_with_user_input": "Sanitise `{MATCH}` with an [intermediate environment variable](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#using-an-intermediate-environment-variable) or use an action with arguments.",
    "rce_general": "Sanitise `{MATCH}` with an [intermediate environment variable](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#using-an-intermediate-environment-variable) or use an action with arguments.",
    "supply_chain": "Replace the actions `{ACTIONS}` with the updated username for the publisher, or replace it altoghter with a new one or your own fork."
}
