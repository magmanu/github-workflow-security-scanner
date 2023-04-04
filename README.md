# GWoSS: Github Workflow Security Scanner

<img src="./static/cat_in_space.png" alt="cat in space" width="200"/>

This tool (GWoSS) identifies vulnerabilities in GitHub Workflows, like a workflow SAST if you wanna go fancy. It does so by scanning the workflow files for anti-patterns such as ingesting user inputs in an unsafe manner or using malicious commits in build process.

## Features

- **Security Scanning**: Checks all workflows in a specific branch (e.g., current branch)
- **CI**: Option to break the pipeline if workflow is vulnerable
- **Reporting**: Shows vulnerability report and suggested remediation on pipeline log

## Usage

Example of workflow that uses this action.  
Optional: Set `SHOULD_BREAK` to `true` if you'd like the pipeline to fail if a workflow vulnerability is found. Default is false.

```yml
name: Security Scan for Github Worflows
on: push

jobs:
  scan-workflows:
    runs-on: ubuntu-latest

    steps:
        - uses: magmanu/github-workflow-security-scanner@v0.0.1 
          with:
            REPO_TOKEN: ${{ secrets.GITHUB_TOKEN }}
            SHOULD_BREAK: true
          env:
            REPOSITORY: ${{  github.repository }}
            BRANCH: ${{ github.ref_name}}

```


## What checks are currently in place?

See them [here](scan_config.json)
## To do: Wanna Collaborate?

- [ ] [Feat] Enable org/user scan
- [ ] [Feat] Add `result.md` to PR comment
- [ ] [Feat] Add summary to workflow
- [ ] [Feat] Add supply chain to `result.md` table and vulnerability count
- [ ] [Chore] Improve how `result.md` is created
- [ ] [Chore] Add testing

## Ideas for next steps

* Check for [GitHub Action evaluates curl's output](https://docs.boostsecurity.io/rules/cicd-gha-curl-eval.html)
* Check for [workflow inputs](https://docs.boostsecurity.io/rules/cicd-gha-workflow-dispatch-inputs.html)
* Check for [write-all](https://docs.boostsecurity.io/rules/cicd-gha-write-all-permissions.html)
* Add scan for intentional deprecated commands [ACTIONS_ALLOW_UNSECURE_COMMANDS](https://docs.boostsecurity.io/rules/cicd-gha-unsecure-commands.html) and `save-state` and `set-outout`?

## Notice

This was originally forked from [this repo](https://github.com/TinderSec/gh-workflow-auditor) and converted to a GitHub Action. I explicitly affirm that changes were made to the original code and am in good faith reproducing the copyright. I believe this is enough to fullfill the original copyright requirements.  

