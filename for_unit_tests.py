h = {
    "scan-workflows": {
        "runs-on": "ubuntu-latest",
        "steps": [
            {
                "uses": "magmanu/github-workflow-security-scanner@feat/run-on-current",
                "with": {
                    "REPO_TOKEN": "${{ secrets.GITHUB_TOKEN }}",
                    "SHOULD_BREAK": True,
                },
                "env": {
                    "REPOSITORY": "${{  github.repository }}",
                    "BRANCH": "${{ github.ref_name}}",
                },
            }
        ],
    }
}
