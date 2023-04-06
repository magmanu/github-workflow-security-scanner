import os

# Local imports

from action_auditor import action_audit
from github_wrapper import GHWrapper
from lib.logger import AuditLogger
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
        workflow_name = workflow['name']
        workflow_content = workflow['content']

        vuln_check = workflow_analyzer(content=workflow_content)
        result[workflow_name] = {"secrets": vuln_check['secrets'], "issues": vuln_check['issues']}
        
    print(result)
    return result

def main():

    gh = GHWrapper()
    vuln_count = 0
    
    target_type = os.environ.get('TARGET_TYPE',None) #repo, org, or user
    target_input = os.environ.get('REPOSITORY',None) #can be repo url, or a username for org/user
    target_branch = (os.environ.get('BRANCH',None) or "HEAD")

    if target_type == 'repo':
        repos = gh.get_single_repo(repo_name=target_input, branch_name=target_branch)
    else:
        count, repos = gh.get_multiple_repos(target_name=target_input,branch_name=target_branch,target_type=target_type)
        AuditLogger.info(f"Metric: Scanning total {count} repos")
    
    for repo_dict in repos:
        AuditLogger.warning(f"\n\n## Audit for {repo_dict}")
        repo_workflows = repos[repo_dict]
        analysis = repo_analysis(repo_workflows)

        for workflow in analysis:
            vuln_count += len(analysis[workflow]["issues"])

    action_audit()

    AuditLogger.warning(f"## Vulnerabilities found: {vuln_count}")
    print(vuln_count)


main()

