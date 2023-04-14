# GWoSS: Github Workflow Security Scanner

<img src="./static/cat_machine.jpeg" alt="cat in space" width="30%" align="right"/>

![version](https://img.shields.io/github/v/release/magmanu/github-workflow-security-scanner)
![commit](https://img.shields.io/github/last-commit/magmanu/github-workflow-security-scanner)
[![sast](https://img.shields.io/badge/SAST-CodeQL-black.svg)](https://github.com/magmanu/github-workflow-security-scanner/actions/workflows/github-code-scanning/codeql)
[![sca](https://img.shields.io/badge/SCA-dependabot-blue.svg)](https://github.com/magmanu/github-workflow-security-scanner/pulls?q=is%3Apr+author%3Aapp%2Fdependabot+)
[![style](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
<!-- ![workflow](https://img.shields.io/github/actions/workflow/status/magmanu/github_actions_auditor/pytest.yml) -->
<!-- ![coverage](./docs/coverage.svg) -->
<!-- [![maintenance](https://img.shields.io/maintenance/yes/2023)](https://github.com/magmanu/github_actions_auditor/commits/main) -->

**GWoSS** scans your GitHub Workflows for vulnerabilities, like a workflow SAST if you wanna go fancy. It looks for anti-patterns such as ingesting inputs in an unsafe manner or malicious commits in build process.

<br clear="right"/>

## Features

<img src="./static/summary_view.png" alt="cat in space" width="30%" align="left"/>

- **Security Scanning**: Checks all workflows in a specific branch (default: current branch)
- **CI**: Option to break the test if any workflow is vulnerable
- **Reporting**: Shows vulnerability report summary and suggest remediations. When used as a CLI tool, the report is saved to a `result.md` file. If running as a GitHub Action, besides the `result.md` being available as an action output, a summary will show as per the screenshot.
- **Scope**: You can scan a single repo, or all repos for a user/organisation.  

<br clear="left"/>

## Usage

GWoSS can be used both as a GitHub Action or a CLI tool.

### Params

| Param | Condition | Type  | Description |
| ----- | ---------- | ------- | -------- |
| GH_TOKEN | required | `string`  | PAT with `repo` permissions|
| SHOULD_BREAK | optional | `boolean` | Determine if CI should break if vulnerability is found. Defaults to `false`. Applicable only when executed as Github Action. |
| TYPE | optional | `string` |What resource to analyse. Valid values" `repo`, `org` or `user`. Defaults to `repo` |
| TARGET | required |`string` | If type `repo`, the name of the repo to scan. Must be in the format `<owner>/<repo-name>`. Else, pass the user or org name instead. |
BRANCH | optional | `string` | Branch in which to run the scan. Defaults to the main branch |  

### GitHub Action

Examples
### Case 1: Workflow in a general dev repository, check development branches
This example is suitable if you want to check branches before they are merged to main. `push` is used because malicious actions can cause damage even before they are merged to `main`.

```yml
name: Security Scan for Github Worflows

on: push

jobs:
  scan-workflows:
    runs-on: ubuntu-latest

    steps:
        - uses: magmanu/github-workflow-security-scanner@v0.1.0
          with:
            GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
            SHOULD_BREAK: true
          env:
            TARGET: ${{  github.repository }}
            BRANCH: ${{ github.ref_name}}

```

### Case 2: [ORG] Workflow in a security audit repo, checking main branch
This example is suitable if you need reporting or an extra check on top of the previous, to check if your main branches are safe. 

```yml
name: Security Scan for Github Worflows

on: push

jobs:
  scan-workflows:
    runs-on: ubuntu-latest

    steps:
        - uses: magmanu/github-workflow-security-scanner@v0.1.0
          with:
            GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          env:
            TARGET: 'my_org_name'
            TYPE: 'org'

```
### Case 3: [USER] Workflow in a security audit repo, checking main branch
Same as above, but for `user`.

```yml
name: Security Scan for Github Worflows

on: push

jobs:
  scan-workflows:
    runs-on: ubuntu-latest

    steps:
        - uses: magmanu/github-workflow-security-scanner@v0.1.0
          with:
            GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          env:
            TARGET: 'my_github_username'
            TYPE: 'user'

```


### CLI Tool

To run GWoSS locally, clone this repo, cd into it and create a `.env` file with the relevant parameters.
Then, run `pip install -r requirements.txt && python main.py`.  
GWoSS was developed in python 3.11.1 and tested in python 3.10.  

## Security

### Token

GWoSS queries Github's GraphQL and requires only read access. As for the time being fine grained tokens do not work with GraphQL, please generate a [classic PAT token](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/creating-a-personal-access-token) with `repo` permissions. If you're using GWoSS to scan an organization repo, you might need to [get the PAT SSO'ed first](https://docs.github.com/en/enterprise-cloud@latest/authentication/authenticating-with-saml-single-sign-on/authorizing-a-personal-access-token-for-use-with-saml-single-sign-on).  

### GWoSS Usage

This is in the license, but just to reinforce: You may use this software only to scan and assess your own software and systems and may not use it for any malicious or illegal purpose. You may disclose any potential vulnerabilities you detect with this software only to the developer of the software in which you detect the potential vulnerability.

## What checks are currently in place?

- [gwoss-001] Injection
- [gwoss-002] Potentially malicious commits
- [gwoss-003] pwn requests
- [gwoss-004] namespace supply chain vulnerability (user/org namespace is vacant but the action still in use via redirect)

## To do: Wanna Collaborate?

- [ ] [Feat] Add `result.md` to PR comment
- [ ] [Feat] Add severity to findings [Unsure]
- [ ] [Feat] Perhaps migrate my action auditor here too [Unsure]
- [ ] [Chore] Add tests
- [ ] [Chore] Run black and unit testing to CI

## Possible next steps

* [gwoss-005] Check if actions use full sha or tag rather than branch name
* Check for [GitHub Action evaluates curl's output](https://docs.boostsecurity.io/rules/cicd-gha-curl-eval.html)
* Check for [workflow inputs](https://docs.boostsecurity.io/rules/cicd-gha-workflow-dispatch-inputs.html)
* Check for [write-all](https://docs.boostsecurity.io/rules/cicd-gha-write-all-permissions.html)
* Add scan for intentional deprecated commands [ACTIONS_ALLOW_UNSECURE_COMMANDS](https://docs.boostsecurity.io/rules/cicd-gha-unsecure-commands.html) and `save-state` and `set-outout`?

## Notice

This was originally forked from [this repo](https://github.com/TinderSec/gh-workflow-auditor) and converted to a GitHub Action. I explicitly affirm that changes were made to the original code and am in good faith reproducing the copyright. I believe this is enough to fullfill the original copyright requirements.  
