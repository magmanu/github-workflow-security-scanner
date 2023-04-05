def create_msg(step_number, type="", match="", input={}, regex=""):
    if type == "pwn":
        issue = f"The workflow is vulnerable to pwn requests. Vulnerable step: {step_number}"
        remediation = "Do not checkout the PR branch when using `pull_request_type`. Consider [other options](https://securitylab.github.com/research/github-actions-preventing-pwn-requests/)"
    if input == {} and type == "rce":
        issue = f"RCE detected with {regex} in {step_number}"
        remediation = f" Please sanitise {','.join(match)} by using an [intermediate environment variable](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#using-an-intermediate-environment-variable)"
    if type == "rce":
        for env_name in input:
            issue = (
                f"RCE detected with {regex} in {step_number}. ENV variable {env_name} is called through GitHub context and takes user input {input[env_name]}",
            )
            remediation = f" Please sanitise {','.join(match)} by using an [intermediate environment variable](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#using-an-intermediate-environment-variable)"

    return {"issue": issue, "remediation": remediation}
