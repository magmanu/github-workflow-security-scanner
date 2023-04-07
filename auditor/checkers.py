import re
import pydash as _

from auditor.security_settings import (
    secrets_pattern,
    dangerous_events,
    remediation,
    issue,
)
from workflow import WorkflowVulnAudit, WorkflowParser

vuln_analyzer = WorkflowVulnAudit()


def is_trigger_dangerous(trigger_name: str) -> bool:
    return trigger_name in dangerous_events


def is_workflow_valid(wrkfl: WorkflowParser) -> bool:
    return wrkfl.safe_yml_file and not _.get(wrkfl.safe_yml_file, "failed")


def is_environment_dangerous(dangerous_env: dict) -> bool:
    return dangerous_env and list(dangerous_env.keys())[0] != "environ_regex"


def check_pwn_requests(dangerous_triggers: list, job_elements: dict) -> list[dict]:
    """
    What is a pwn request?
    When a Github Workflow
    - Triggers on the pull_request_target event type; and
    - Performs an explicit checkout of the Pull Request branch (i.e. checks out the content being submitted for inclusion in the target repo); and
    - Uses the state of the checked out branch in an unsafe manner (e.g. by building the repo using make or by installing packages using a package manager)
    Such workflow can be abused to steal or use a GITHUB_TOKEN value that belongs to the target repo.
    See an interesting disclosure story here: https://github.com/justinsteven/advisories/blob/main/2021_github_actions_checkspelling_token_leak_via_advice_symlink.md
    """
    issues = []
    action_storage = open("actions.txt", "a+")
    for action in _.get(job_elements, "all_actions"):
        for step_number, step_dict in action.items():
            action_name = _.get(step_dict, "uses")
            action_storage.write(f"{action_name}\n")
            if "actions/checkout" in action_name:
                # check if specific branch is checked out
                if _.get(step_dict, "with"):
                    if ref_value := _.get(step_dict, "with.ref"):
                        risky_commits = vuln_analyzer.risky_commit(referenced=ref_value)
                        if risky_commits:
                            if "pull_request_target" in dangerous_triggers:
                                pwn = create_msg(step_number, type="pwn")
                                issues.append(pwn)
    action_storage.close()
    return issues


def check_rce_vuln(job_elements: dict) -> list[dict[str, str]]:
    issues_per_workflow = []

    for runner_command in job_elements["runner_commands"]:
        for step_number, step_dict in runner_command.items():
            dangerous_inputs = vuln_analyzer.get_unsafe_inputs(
                command_string=step_dict["run"]
            )

            if dangerous_inputs:
                for regex, matched_strings in dangerous_inputs.items():
                    # check if environment variable contains exploitable input
                    if regex == "environ_regex":
                        if exploitable_input := get_env_kv_provided_by_user(
                            job_elements, matched_strings
                        ):
                            for input in exploitable_input:
                                rce = create_msg(
                                    step_number,
                                    type="rce",
                                    match=matched_strings,
                                    input=input,
                                    regex=regex,
                                )
                                issues_per_workflow.append(rce)
                    else:
                        rce = create_msg(
                            step_number, type="rce", match=matched_strings, regex=regex
                        )
                        issues_per_workflow.append(rce)
    return issues_per_workflow


def get_env_kv_provided_by_user(
    job_elements: dict, matched_strings
) -> list[dict[str, str]]:
    """
    Retrieve all enviroment variables that contain exploitable input
    (as opposed to by the environment)
    """

    exploitable_input = []
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
                exploitable_input.append({environ_variable: environ_var_value})
    return exploitable_input


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
    if matches := secrets.findall(full_yaml):
        for match in matches:
            if match not in found_matches:
                found_matches.append(match)
    return found_matches


def create_msg(
    step_number: int, type="", match="", input={}, regex=""
) -> dict[str, str]:
    if type == "pwn":
        problem = f"{_.get(issue, 'pwn_requests')} {step_number}"
        solution = _.get(remediation, "pwn_requests")
    if input == {} and type == "rce":
        problem = (
            f"{_.get(issue, 'rce_general')}".replace("{REGEX}", regex)
            .replace("{STEP}", step_number)
            .replace("{MATCH}", match[0])
        )
        solution = _.get(remediation, "rce_general").replace("{MATCH}", match[0])
    if type == "rce":
        for env_name in input:
            problem = (
                _.get(issue, "rce_with_user_input")
                .replace("{REGEX}", regex)
                .replace("{STEP}", step_number)
                .replace("{ENV_NAME}", input)
                .replace("{ENV_VALUE}", input[env_name])
            )
            solution = _.get(remediation, "rce_with_user_input").replace(
                "{MATCH}", f"{','.join(match)}"
            )

    return {"issue": problem, "remediation": solution}
