import pydash as _


def build_table_body(result: dict) -> list[dict]:
    strings = []
    for wrkfl_name in result:
        secrets = ",".join(_.get(result[wrkfl_name], "secrets", None))

        issues_list = _.get(result[wrkfl_name], "issues")
        if issues_list:
            for issue in issues_list:
                if issue_desc := _.get(issue, "issue"):
                    remediation = _.get(issue, "remediation")
                    string = (
                        f"| {wrkfl_name} | {secrets} | {issue_desc} | {remediation} |"
                    )
                    strings.append(string)
        else:
            string = f"| {wrkfl_name} | {secrets} | None | None |"
            strings.append(string)
    return strings


def report(result: dict, vuln_count: int):
    summary_subheader = f"### Vulnerabilities found: {vuln_count}"

    if vuln_count == 0:
        return

    header = [
        "| Workflow | Secrets | Issues | Recommendation |",
        "| --- | --- | --- | --- |",
    ]
    table = build_table_body(result)

    write_to_file(summary_subheader)
    write_to_file(header)
    write_to_file(table)


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
