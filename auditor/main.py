import pydash as _

from auditor.checkers import (
    get_secrets_names,
    get_dangerous_triggers,
    is_workflow_valid,
    check_rce_vuln,
    check_pwn_requests,
)
from workflow import WorkflowParser, WorkflowVulnAudit
from lib.logger import AuditLogger

vuln_analyzer = WorkflowVulnAudit()


def workflow_analyzer(content: str) -> dict[str, list]:
    result = {
        "issues": [],
        "secrets": [],
    }

    wrkfl = WorkflowParser(content)

    if is_workflow_valid(wrkfl):
        # help understand impact of RCE
        _.get(result, "secrets").append(get_secrets_names(content))

        all_workflow_triggers = wrkfl.get_event_triggers()
        all_jobs = wrkfl.get_jobs()

        if all_jobs:
            job_elements = get_job_elements_with_id(wrkfl, all_jobs)
            dangerous_triggers = get_dangerous_triggers(triggers=all_workflow_triggers)

            try:
                rce = check_rce_vuln(job_elements)
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


def get_job_elements_with_id(
    wrkfl: WorkflowParser, all_jobs: dict
) -> dict[str, list | dict]:
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
            actions, runner_command, with_input, step_environ = wrkfl.get_step_elements(
                step
            )
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


def get_steps(environs: dict, all_jobs: dict, job_name: str) -> list:
    job_content = all_jobs[job_name]
    steps = _.get(job_content, "steps")
    if not steps:
        steps = job_content
    try:
        environs.update(_.get(job_content, "env", {}))
    except:
        AuditLogger.error(">> Environ variable is malformed")
    return steps


def create_msg(
    step_number: int, type: str = "", match: str = "", input: dict = {}, regex: str = ""
) -> dict[str, str]:
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
