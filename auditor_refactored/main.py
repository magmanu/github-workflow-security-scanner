import pydash as _

from auditor_refactored.vulnerability_catcher import list_secrets_used, get_dangerous_triggers
from workflow_copy import WorkflowParser, WorkflowVulnAudit
from auditor_refactored.build_recommendation import create_msg
from lib.logger import AuditLogger

vuln_analyzer = WorkflowVulnAudit()


def workflow_analyzer(content):
    result = {
        "issues": [],
        "secrets": [],
    }

    wrkfl = WorkflowParser(content)

    if is_workflow_valid:
        # help understand impact of RCE
        _.get(result, "secrets").append(
            list_secrets_used(content)
        )  

        all_workflow_triggers = wrkfl.get_event_triggers()
        all_jobs = wrkfl.get_jobs()

        if all_jobs:
            job_elements = get_job_elements_with_id(wrkfl, all_jobs)
            dangerous_triggers = get_dangerous_triggers(
                triggers=all_workflow_triggers
            )

            try:
                rce = get_rce_vuln(job_elements)
                pwn = check_pwn_requests(dangerous_triggers, job_elements)
                _.get(result, "issues").append(rce)
                _.get(result, "issues").append(pwn)
            except Exception as workflow_err:
                AuditLogger.error(
                    f">>> Error parsing workflow. Error is {str(workflow_err)}"
                )
    result["issues"] = _.flatten(_.get(result, "issues"))
    result["secrets"] = _.flatten(_.get(result, "secrets"))
    return result


def is_workflow_valid(wrkfl):
    return wrkfl.safe_yml_file and not _.get(wrkfl.safe_yml_file, "failed")


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


def get_rce_vuln(job_elements):
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
                        if vulnerable_user_input := get_vulnerable_user_input(
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


def get_vulnerable_user_input(job_elements, matched_strings):
    """
    Retrieve all enviroment variables that contain values provided by the user(?)
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


def is_environment_dangerous(dangerous_env):
    return dangerous_env and list(dangerous_env.keys())[0] != "environ_regex"


def get_job_elements_with_id(wrkfl, all_jobs):
    """
    Break down job elements (step, action, env and run command) and give them IDs.
    This helps the user identify where the vulnerability is.
    """
    code_line = 1
    all_actions = []
    runner_commands = []
    environs = {}

    for job_name in all_jobs:
        steps = get_steps(environs, all_jobs, job_name)

        for step_number, step in enumerate(steps):
            actions, runner_command, with_input, step_environ = wrkfl.get_step_elements(step)
            if actions:
                all_actions.append({f"Job{code_line}.Step{step_number+1}": step})
            if runner_command:
                runner_commands.append({f"Job{code_line}.Step{step_number+1}": step})
            if step_environ:
                if isinstance(step_environ, str):
                    step_environ = {f"{step_number}{step}": step_environ}
                environs.update(step_environ)
        code_line += 1
    return {
        "all_actions": all_actions,
        "runner_commands": runner_commands,
        "environs": environs,
    }


def get_steps(environs, all_jobs, job_name):
    job_content = all_jobs[job_name]
    steps = _.get(job_content, "steps")
    if not steps:
        steps = job_content
    try:
        environs.update(_.get(job_content, "env", {}))
    except:
        AuditLogger.error(">> Environ variable is malformed")
    return steps
