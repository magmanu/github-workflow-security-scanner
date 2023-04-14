import pydash as _

from workflow import WorkflowParser, WorkflowVulnAudit
from auditor.action_auditor import action_audit
from lib.logger import AuditLogger
from auditor.checkers import (
    get_dangerous_triggers,
    is_workflow_valid,
    check_rce_vuln,
    check_pwn_requests,
    get_deprecated_commands
)

vuln_analyzer = WorkflowVulnAudit()


def workflow_analyzer(content: str) -> dict[str, list]:
    result = {
        "issues": [],
        "secrets": [],
    }

    wrkfl = WorkflowParser(content)

    if is_workflow_valid(wrkfl):
        result["secrets"].append(wrkfl.secrets)

        all_jobs = wrkfl.get_jobs()

        if all_jobs:
            job_elements = get_job_elements_with_id(wrkfl, all_jobs)
            dangerous_triggers = get_dangerous_triggers(triggers=wrkfl.triggers)

            try:
                deprecated_commands = get_deprecated_commands(wrkfl,job_elements)
                rce = check_rce_vuln(job_elements)
                pwn = check_pwn_requests(dangerous_triggers, job_elements)
                vulnerable_supply_chain = action_audit(job_elements)

                _.get(result, "issues").append(rce)
                _.get(result, "issues").append(pwn)
                _.get(result, "issues").append(vulnerable_supply_chain)
                _.get(result, "issues").append(deprecated_commands)

            except Exception as workflow_err:
                AuditLogger.error(
                    f">>> Error parsing workflow. Error is {str(workflow_err)}"
                )
    result["issues"] = _.flatten_deep(_.get(result, "issues"))
    result["secrets"] = _.flatten_deep(_.get(result, "secrets"))

    return result


def get_job_elements_with_id(
    wrkfl: WorkflowParser, all_jobs: list
) -> dict[str, list | dict]:
    """
    Break down job elements (step, action, env and run command) and give them IDs.
    This helps the user identify where the vulnerability is.
    """
    all_actions = []
    runner_commands = []
    environs = {}

    for job_id, job in enumerate(all_jobs):
        job_id += 1 # human-friendly numbering
        steps = get_steps(environs, job)

        for step_id, step in enumerate(steps):
            step_id += 1 # human-friendly numbering
            actions, runner_command, with_input, step_environ = wrkfl.get_step_elements(
                step
            )
            if actions:
                all_actions.append({f"Job{job_id}.Step{step_id}": step})
            if runner_command:
                runner_commands.append({f"Job{job_id}.Step{step_id}": step})
            if step_environ:
                if isinstance(step_environ, str):
                    step_environ = {f"{step_id}{step}": step_environ}
                environs.update(step_environ)

    return {
        "all_actions": all_actions,
        "runner_commands": runner_commands,
        "environs": environs,
    }


def get_steps(environs: dict, job: dict) -> list:
    steps = _.get(job, "steps")
    if not steps:
        steps = job
    try:
        environs.update(_.get(job, "env", {}))
    except:
        AuditLogger.error(">> Environ variable is malformed")
    return steps
