import subprocess
import pydash as _

commands = [
    'echo "| Workflow | Issues | Secrets | Recommendation |" >> $GITHUB_STEP_SUMMARY'
    'echo "| --- | --- | --- | --- |" >> $GITHUB_STEP_SUMMARY'
]


def build_tail_commands(result: dict) -> list[dict]:
    commands = []
    for wrkfl_name in result:
        secrets = (",".join(_.get(result[wrkfl_name], "secrets")))

        issues_list = _.get(result[wrkfl_name],"issues")
        if issues_list:
            for issue in issues_list:
                desc = _.get(issue, "issue")
                remediation = _.get(issue, "remediation")
                string = f'echo "| {wrkfl_name} | {secrets or "None"} | {desc} | {remediation} |" >> $GITHUB_STEP_SUMMARY'
                commands.append(string)
        else:
            string = f'echo "| {wrkfl_name} | {secrets or "None"} | None | None |" >> $GITHUB_STEP_SUMMARY'
            commands.append(string)
    return commands


def build_commands(tail):
    commands = [
        'echo "============>Generating summary"',
        'echo "| Workflow | Issues | Secrets | Recommendation |" >> $GITHUB_STEP_SUMMARY',
        'echo "| --- | --- | --- | --- |" >> $GITHUB_STEP_SUMMARY'
    ]

    for command in tail:
        commands.append(command)
    print(commands)
    return commands

def report(result:dict):
    print("===========> REPORT")
    tail = build_tail_commands(result)
    commands = build_commands(tail)
    for command in commands:
        process = subprocess.Popen(command.split(), stdout=subprocess.PIPE)
        output, error = process.communicate()




