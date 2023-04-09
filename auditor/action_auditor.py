import re
import pydash as _

from api_comms.github_wrapper import GHWrapper
from lib.logger import AuditLogger
from dotenv import load_dotenv
from auditor.checkers import get_workflow_actions, create_msg

load_dotenv()
gh = GHWrapper()


def get_actions_publishers(actions: dict) -> dict[str, list]:
    """Returns dictionary {publisher: [actions}"""
    usernames = {}
    for action_name in actions:
        username = action_name.split("/")[0]
        username_regex = re.compile("[A-Za-z0-9-]*")
        if username_regex.fullmatch(username):
            if username not in usernames.keys():
                usernames.update({username: [action_name]})
            else:
                usernames[username].append(action_name)
    return usernames


def get_vulnerable_publishers(usernames: dict) -> list:

    username_not_found = []
    for username in usernames:
        is_valid_user = gh.stale_checker(username=username)
        if not is_valid_user:
            username_not_found.append(username)
    return username_not_found


def action_audit(job_elements: dict) -> list:
    actions = get_workflow_actions(job_elements)
    result = []

    if len(actions) ==  0:
        return


    actions_by_usernames = get_actions_publishers(actions)
    vulnerable_publishers = get_vulnerable_publishers(actions_by_usernames)

    for publisher in vulnerable_publishers:
        for action in actions_by_usernames[publisher]:
            step = actions[action]["step"]
            vulnerable_actions = (",".join(actions_by_usernames[publisher]))
            supply_chain = create_msg(step_number=step,publisher=publisher,vuln_actions=vulnerable_actions,vuln_type="supply_chain")
            result.append(supply_chain)
    return result