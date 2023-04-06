import re
import pydash as _

from security_settings import secrets_pattern, dangerous_events
from workflow_copy import WorkflowVulnAudit

vuln_analyzer = WorkflowVulnAudit()

def is_trigger_dangerous(trigger_name: str) -> bool:
    return trigger_name in dangerous_events


def is_workflow_valid(wrkfl):
    return wrkfl.safe_yml_file and not _.get(wrkfl.safe_yml_file, "failed")


def is_environment_dangerous(dangerous_env):
    return dangerous_env and list(dangerous_env.keys())[0] != "environ_regex"


def check_pwn_requests(dangerous_triggers: list, job_elements: dict) -> list:
    issues = []
    action_storage = open("actions.txt", "a+")
    for action in _.get(job_elements, "all_actions"):
        for step_number, step_dict in action.items():
            action_name = _.get(step_dict, "uses")
            action_storage.write(f"{action_name}\n")
            if "actions/checkout" in action_name:
                # check if specific branch is checked out
                if step_dict.get("with", None):
                    if ref_value:= _.get(step_dict, "with.ref"):
                        risky_commits = vuln_analyzer.risky_commit(referenced=ref_value)
                        if risky_commits:
                            if "pull_request_target" in dangerous_triggers:
                                pwn = create_msg(step_number, type="pwn")
                                issues.append(pwn)
    action_storage.close()
    return issues


def check_rce_vuln(job_elements):
    issues_per_workflow = []

    for runner_command in job_elements["runner_commands"]:
        for step_number, step_dict in runner_command.items():
            dangerous_inputs = vuln_analyzer.get_unsafe_inputs(
                command_string=step_dict["run"]
            )

            if dangerous_inputs:
                for regex, matched_strings in dangerous_inputs.items():
                    # check if environment variable contains values provided by the user
                    if regex == "environ_regex":
                        if vulnerable_user_input := get_env_kv_provided_by_user(
                            job_elements, matched_strings
                        ):
                            for user_input in vulnerable_user_input:
                                rce = create_msg(
                                    step_number,
                                    type="rce",
                                    match=matched_strings,
                                    input=user_input,
                                    regex=regex,
                                )
                                issues_per_workflow.append(rce)
                    else:
                        rce = create_msg(
                            step_number, type="rce", match=matched_strings, regex=regex
                        )
                        issues_per_workflow.append(rce)
    return issues_per_workflow


def get_env_kv_provided_by_user(job_elements, matched_strings):
    """
    Retrieve all enviroment variables that contain values provided by the user
    (as opposed to by the environment)
    """

    vulnerable_user_input = []
    for environ_variable in matched_strings:
        environ_variable = (
            environ_variable.strip("${{").strip("}}").split(".")[1].strip()
        )
        environ_var_value = _.get(job_elements, "environs.environ_variable")
        if environ_var_value:
            dangerous_env = vuln_analyzer.get_unsafe_inputs(
                command_string=environ_var_value
            )
            if is_environment_dangerous(dangerous_env):
                vulnerable_user_input.append({environ_variable: environ_var_value})
    return vulnerable_user_input



def get_dangerous_triggers(triggers: list) -> list:
    dangeours_triggers = []
    for trigger in triggers:
        if is_trigger_dangerous(trigger):
            dangeours_triggers.append(trigger)
    return dangeours_triggers


def get_secrets_names(full_yaml: str) -> list:
    """
    Finds all secrets being used in this workflow.
    Useful in case there's an RCE, we can pull these secrets
    :param full_yaml: The full yaml string of the workflow.
    :return: A list of all secrets being used in this workflow."""
    found_matches = []
    secrets = re.compile(secrets_pattern)
    if matches:= secrets.findall(full_yaml):
        for match in matches:
            if match not in found_matches:
                found_matches.append(match)
    return found_matches


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