import subprocess
import pydash as _

def add_command(string):
    return f'echo "{string}" >> GITHUB_STEP_SUMMARY'


def build_tail_commands(result: dict) -> list[dict]:
    strings = []
    for wrkfl_name in result:
        secrets = (",".join(_.get(result[wrkfl_name], "secrets", None)))

        issues_list = _.get(result[wrkfl_name],"issues")
        if issues_list:
            for issue in issues_list:
                desc = _.get(issue, "issue")
                remediation = _.get(issue, "remediation")
                string = f"| {wrkfl_name} | {secrets} | {desc} | {remediation} |"
                strings.append(string)
        else:
            string = f"| {wrkfl_name} | {secrets} | None | None |"
            strings.append(string)
    return strings


def build_commands(tail):
    commands = []
    header = [
        "| Workflow | Secrets | Issues | Recommendation |",
        "| --- | --- | --- | --- |"
    ]


    write_to_file(header)

    for string in tail:
        write_to_file(string)
        command = add_command(string)
        commands.append(f"{command}")
    return commands

def report(result:dict):

    tail = build_tail_commands(result)

    commands = build_commands(tail)
    for command in commands:
        process = subprocess.Popen(command.split(), stdout=subprocess.PIPE)
        output, error = process.communicate()

def write_to_file(inputs: str | list):
    f = open("result.md", "a")

    if isinstance(inputs, list):
        for element in inputs:
            f.write(element)
            f.write(f"\n")

    else:
        f.write(inputs)
        f.write(f"\n")
    f.close()