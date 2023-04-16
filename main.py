import os
import pydash as _
from api_comms.github_wrapper import GHWrapper
from lib.logger import AuditLogger
from auditor.main import start_scan
from workflow import WorkflowParser
"""
Input:
    repo_dict - dictionary defining repo information
Output:
    scan result (if any) in scan.log file.
Summary:
    For a given workflow dictionary (name, content) this
    function will call content_analyzer to audit the workflow
    for any potential vulnerabilities. 
"""

def main():

    target_type = os.environ.get("TARGET_TYPE", None)  # repo, org, or user
    target_input = os.environ.get("TARGET_INPUT", None)
    target_branch = os.environ.get("BRANCH", None) or "HEAD"
    IS_DOOM = (os.environ.get("IS_DOOM_DAY") == True)

    repos = get_repos_with_workflows(target_type, target_input, target_branch)

    if IS_DOOM:
    #TODO: If IS_DOOM
        # - run scan on action definition (aka action.yml or action.yaml)
        all_actions = []
        wrkfl_list = get_all_workflows_per_repo(repos)
        result = 0
        for wrkfl in wrkfl_list:
            actions = _.sorted_uniq(_.flatten(wrkfl.all_actions))
            for action in actions:
                action = action.split("@")[0]
                if action not in all_actions:
                    all_actions.append(action)
                    target_type = "repo"
                    target_input = action
                    target_branch = "HEAD"
                    IS_ACTION_AUDIT = True
                    IS_DOOM = False
                    action_repo = get_repos_with_workflows(target_type, target_input, target_branch, IS_ACTION_AUDIT)
                    result += start_scan(action_repo, IS_DOOM)
        all_actions = _.sorted_uniq(_.flatten(all_actions))
        print(all_actions)
    else:
        result = start_scan(repos, IS_DOOM)
        print(result)

def get_repos_with_workflows(target_type:str, target_input:str, target_branch:str, IS_ACTION_AUDIT:bool = False) -> dict:
    # TODO: get action definition
    # - if the action uses docker, warn user we're not going there
    gh = GHWrapper()
    if IS_ACTION_AUDIT == True:
        repos = gh.get_action_definition(repo_name=target_input)
    elif target_type == "repo":
        repos = gh.get_single_repo(repo_name=target_input, branch_name=target_branch)
    else:
        count, repos = gh.get_multiple_repos(
            target_name=target_input, branch_name=target_branch, target_type=target_type
        )
        AuditLogger.info(f"Metric: Scanning total {count} repos")

    return repos

def get_all_workflows_per_repo(repo_dict):
    all_workflows = []
    for repo_name in repo_dict:
        AuditLogger.warning(
            f"\n\n## Audit: [{repo_name}](https://github.com/{repo_name})"
        )

        repo_workflows = repo_dict[repo_name]
        for workflow in repo_workflows:
            workflow_name = workflow["name"]
            all_workflows.append(WorkflowParser(workflow))
    return all_workflows

def get_action_definition(target_type, target_input, target_branch) -> dict:
    gh = GHWrapper()
    if target_type == "repo":
        repos = gh.get_single_repo(repo_name=target_input, branch_name=target_branch)
    else:
        count, repos = gh.get_multiple_repos(
            target_name=target_input, branch_name=target_branch, target_type=target_type
        )
        AuditLogger.info(f"Metric: Scanning total {count} repos")
    return repos

main()

