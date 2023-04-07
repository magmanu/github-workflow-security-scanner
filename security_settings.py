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
    "pwn_requests": "The workflow is vulnerable to pwn requests. Vulnerable step:",
    "rce_with_user_input":  "[Unsanitezed input](https://securitylab.github.com/research/github-actions-untrusted-input/) detected with {REGEX} in {STEP}. The env variable {ENV_NAME} is called through GitHub context and takes input that could be malicious: {ENV_VALUE}",
    "rce_general": "RCE detected with {REGEX} in {STEP}: Usage of {MATCH} found.",
}
remediation = {
    "pwn_requests": "Do not checkout the PR branch when using `pull_request_type`. Consider [other options](https://securitylab.github.com/research/github-actions-preventing-pwn-requests/)",
    "rce_with_user_input": "Please sanitise {MATCH} by using an [intermediate environment variable](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#using-an-intermediate-environment-variable) or an action with arguments",
    "rce_general": "Please sanitise {MATCH} by using an [intermediate environment variable](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#using-an-intermediate-environment-variable) or an action with arguments",
}
