import pydash as _

from api_comms.github_wrapper import GHWrapper
from workflow import WorkflowParser, WorkflowVulnAudit
from auditor.action_auditor import action_audit
from lib.logger import AuditLogger
from lib.reporter import report, write_to_file
from auditor.checkers import (
    get_dangerous_triggers,
    is_workflow_valid,
    check_rce_vuln,
    check_pwn_requests,
    get_deprecated_commands,
    get_workflow_actions
)


vuln_analyzer = WorkflowVulnAudit()

def start_scan(target_type, target_input, target_branch, IS_DOOM):
    gh = GHWrapper()
    vuln_count = 0

    if target_type == "repo":
        repos = gh.get_single_repo(repo_name=target_input, branch_name=target_branch)
    else:
        count, repos = gh.get_multiple_repos(
            target_name=target_input, branch_name=target_branch, target_type=target_type
        )
        AuditLogger.info(f"Metric: Scanning total {count} repos")

    for repo_name in repos:
        AuditLogger.warning(
            f"\n\n## Audit: [{repo_name}](https://github.com/{repo_name})"
        )
        repo_workflows = repos[repo_name]
        analysis = repo_analysis(repo_workflows, IS_DOOM)

        for workflow in analysis:
            vuln_count += len(analysis[workflow]["issues"])

        report(analysis, vuln_count) if vuln_count > 0 else write_to_file("No issues")
    return vuln_count


def repo_analysis(repo_workflow, IS_DOOM: bool):
    result = {}

    for workflow in repo_workflow:
        workflow_name = workflow["name"]

        vuln_check = workflow_analyzer(workflow, IS_DOOM)
        result[workflow_name] = {
            "secrets": vuln_check["secrets"],
            "issues": vuln_check["issues"],
        }
    return result

def workflow_analyzer(content: str, IS_DOOM:bool) -> dict[str, list]:
    wrkfl = WorkflowParser(content)

    result, job_elements = breakdown_jobs(wrkfl)

    if IS_DOOM:
        actions = get_workflow_actions(job_elements)
        for action in actions:
            action = action.split("@")
            target_type = "repo"
            target_input = action[0]
            target_branch = "HEAD"
            IS_DOOM = False
            start_scan(target_type, target_input, target_branch, IS_DOOM)

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


def breakdown_jobs(wrkfl):
    result = {
        "issues": [],
        "secrets": [],
    }

    if is_workflow_valid(wrkfl):
        result["secrets"].append(wrkfl.secrets)

        all_jobs = wrkfl.get_jobs()

        if all_jobs:
            job_elements = get_job_elements_with_id(wrkfl, all_jobs)
    return (result, job_elements)


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
