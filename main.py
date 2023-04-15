import os

from api_comms.github_wrapper import GHWrapper
from lib.logger import AuditLogger
from lib.reporter import report, write_to_file
from auditor.main import workflow_analyzer, start_scan

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
    IS_DOOM = os.environ.get("IS_DOOM_DAY", True)

    result = start_scan(target_type, target_input, target_branch, IS_DOOM)

    print(result)

main()

