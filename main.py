import os

from api_comms.github_wrapper import GHWrapper
from lib.logger import AuditLogger
from lib.reporter import report, write_to_file
from auditor.main import workflow_analyzer

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


def repo_analysis(repo_workflow):
    result = {}

    for workflow in repo_workflow:
        workflow_name = workflow["name"]
        workflow_content = workflow["content"]

        vuln_check = workflow_analyzer(content=workflow_content)
        result[workflow_name] = {
            "secrets": vuln_check["secrets"],
            "issues": vuln_check["issues"],
        }
    return result


def main():
    gh = GHWrapper()
    vuln_count = 0

    target_type = os.environ.get("TARGET_TYPE", None)  # repo, org, or user
    target_input = os.environ.get(
        "TARGET_INPUT", None
    ) 
    target_branch = os.environ.get("BRANCH", None) or "HEAD"

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
        analysis = repo_analysis(repo_workflows)

        for workflow in analysis:
            vuln_count += len(analysis[workflow]["issues"])

        report(analysis, vuln_count) if vuln_count > 0 else write_to_file("No issues")

    # DO NOT REMOVE PRINT
    # Used to push result to stdout in the github runner and evaluate if CI should break or not
    print(vuln_count)


main()
