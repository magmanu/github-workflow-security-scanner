from vulnerability_catcher import list_secrets_used
from workflow_copy import WorkflowParser, WorkflowVulnAudit

vuln_analyzer = WorkflowVulnAudit()

def analyze_step(step:dict) -> tuple:
    actions = step.get('uses',None)
    run_command = step.get('run',None)
    with_input = step.get('with',None)
    step_environ = step.get('env', None)
    return actions, run_command, with_input, step_environ


def content_analyzer(content):
    isVulnerable = []
    issues_per_workflow = []

    risky_triggers = []
    all_actions = []
    commands = []
    environs = {}
    checked_action = []
    wrkfl = WorkflowParser(content)

    # Sanity check to make sure proper YAML was given.
    if wrkfl.safe_yml_file and not wrkfl.safe_yml_file.get('failed',None): 
        all_secrets = list_secrets_used(content) # help understand impact of RCE
        all_workflow_triggers = wrkfl.get_event_triggers() 
        all_jobs = wrkfl.get_jobs() 

        code_line = 1 # Counter used to identify which line of code is vulnerable.

        # Retrieve and store all needed information for a workflow run for analysis.
        if all_jobs:
            for job in all_jobs:
                steps = all_jobs[job].get('steps',None)
                if not steps: 
                    steps = [all_jobs[job]]
                try:
                    environs.update(all_jobs[job].get('env',{}))
                except:
                    AuditLogger.error(">> Environ variable is malformed")
                for step_number,step in enumerate(steps):
                    actions, run_command, step_environ = wrkfl.analyze_step(step)
                    if actions:
                        all_actions.append({f"Job{code_line}.Step{step_number+1}":step})
                    if step_environ:
                        if isinstance(step_environ, str):
                            step_environ = {f"{step_number}{step}":step_environ}
                        environs.update(step_environ)
                    if run_command:
                        commands.append({f"Job{code_line}.Step{step_number+1}":step})
                code_line +=1 
            
            # Start analyzing the retrieved information.
            try: 
                # Analyzes event triggers to see if they are user controlled.
                risky_triggers = risky_trigger_analysis(identified_triggers=all_workflow_triggers)
                
                # Analyzes commands called by Steps.
                for command in commands:
                    for step_number, step_dict in command.items():
                        risky_command = vuln_analyzer.risky_command(command_string=step_dict['run'])
                        if risky_command:
                            for regex, matched_strings in risky_command.items():
                                if regex == 'environ_regex': # not all environments are bad. Check if this environment is user controlled.
                                    # get the key out of the matched strings. We use this to check if the environ variable stores any user controlled input.
                                    for environ_variable in matched_strings:
                                        environ_variable = environ_variable.strip('${{').strip('}}').split('.')[1].strip()
                                        # get environ value
                                        environ_var_value = environs.get(environ_variable,None)
                                        if environ_var_value:
                                            risky_env = vuln_analyzer.risky_command(command_string=environ_var_value)
                                            if risky_env and list(risky_env.keys())[0] != 'environ_regex':
                                                isVulnerable.append(True)
                                                issue = {"issue":  f" RCE detected with {regex} in {step_number}. ENV variable {environ_variable} is called through GitHub context and takes user input {environ_var_value}", "remediation": f" Please sanitise {','.join(matched_strings)} by using an [intermediate environment variable](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#using-an-intermediate-environment-variable)"}
                                                
                                                issues_per_workflow.append(issue)
                                                
                                else:
                                    isVulnerable.append(True)
                                    issue = {"issue": f"RCE detected with {regex} in {step_number}", "remediation": f" Please sanitise {','.join(matched_strings)} by using an [intermediate environment variable](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#using-an-intermediate-environment-variable)"}
                                    issues_per_workflow.append(issue)
                
                # Some actions combined with triggers can be bad. Check for those cases.
                action_storage = open('actions.txt','a+')
                for action in all_actions:
                    for step_number, step_dict in action.items():
                        action_name = step_dict.get('uses',None)
                        action_storage.write(f"{action_name}\n")
                        if 'actions/checkout' in action_name:
                            # check if specific branch is checked out
                            if step_dict.get('with',None):
                                if step_dict['with'].get('ref',None):
                                    ref_value = step_dict['with'].get('ref')
                                    risky_commits = vuln_analyzer.risky_commit(referenced=ref_value)
                                    if risky_commits:
                                        if 'pull_request_target' in risky_triggers:
                                            isVulnerable.append(True)
                                            issue = {"issue": f"Malicious pull request might be used in actions/checkout. Vulnerable step: {step_number}", "remediation": f"Please check remediation [here](https://securitylab.github.com/research/github-actions-preventing-pwn-requests/)"}
                                            issues_per_workflow.append(issue)
                action_storage.close()
            except Exception as workflow_err:
                AuditLogger.error(f">>> Error parsing workflow. Error is {str(workflow_err)}")
    return {"isVulnerable": isVulnerable, "issues": issues_per_workflow, "secrets": all_secrets}


