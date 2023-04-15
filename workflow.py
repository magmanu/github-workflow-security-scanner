import json
import re
import yaml

from auditor.security_settings import secrets_pattern
from lib.logger import AuditLogger

class WorkflowParser:
    def __init__(self, res: str):
        try:
            self.name = res.get("name")
            self.safe_yml_file = yaml.safe_load(
                res.get("content")
            )  # We don't want a vulnerability ;)

        except:
            self.safe_yml_file = {"failed": True}
        
        self.triggers = self.get_event_triggers()
        self.jobs = self.get_jobs()
        self.secrets = self.get_secrets()
        self.jobs = self.get_jobs()
        self.steps = self.get_steps_for_job()
        self.all_actions = self.get_step_element("actions")
        self.all_run_commands = self.get_step_element("run_commands")
        self.all_actions_args = self.get_step_element("actions_args")
        self.all_steps_vars = self.get_step_element("steps_vars")

    def get_event_triggers(self) -> list:
        if self.safe_yml_file.get(True, None):
            if isinstance(self.safe_yml_file[True], list):
                return self.safe_yml_file[True]
            elif isinstance(self.safe_yml_file[True], dict):
                return list(self.safe_yml_file[True].keys())
            else:
                return [self.safe_yml_file[True]]

    def get_jobs(self) -> list:
        "Returns a list so we can use the index as a job id"
        jobs = self.safe_yml_file.get("jobs", None)
        all_jobs = []
        for job in jobs:
            all_jobs.append(jobs[job])
        return all_jobs

    def get_steps_for_job(self) -> list:
        for job in self.jobs:
            return job.get("steps", None)

    def get_step_element(self, element_name: str) -> list:
        """Retrieves all <element> for the workflow, not only for a step.
        Acceptable element_name: "actions", "run_commands", "actions_args", "steps_vars"
        """
        all_instances = []
        if element_name not in ["actions", "run_commands", "actions_args", "steps_vars"]:
            AuditLogger.warning("Please provide an allowlisted element.")

        mapping = {
            "actions": "uses",
            "run_commands": "run", 
            "actions_args": "with",
            "steps_vars": "env"
        }
        for step in self.steps:
            if element:= step.get(mapping[element_name], None):
                all_instances.append(element)
        return all_instances

    def get_step_elements(self, step: dict) -> tuple:
        actions = step.get("uses", None)
        run_command = step.get("run", None)
        with_input = step.get("with", None)
        step_environ = step.get(
            "env", None
        )
        return actions, run_command, with_input, step_environ

    def get_secrets(self) -> list:
        """
        Finds all secrets being used in this workflow.
        Not the actual secret, just the namespace.
        Useful in case there's an RCE, we can pull these secrets.
        """
        found_matches = []
        secrets = re.compile(secrets_pattern)
        if matches := secrets.findall(json.dumps(self.safe_yml_file)):
            for match in matches:
                if match not in found_matches:
                    found_matches.append(match)
        return found_matches


# Analyze various aspects of workflows to identify if it is risky.
class WorkflowVulnAudit:
    def __init__(self):
        # get scan config regex ready
        self.unsafe_input = {}
        self.malicious_commits = {}
        with open("scan_config.json", "r") as scan_file:
            scan_config = json.loads(scan_file.read())
            self.triggers = scan_config["triggers"]
            self.secrets = re.compile(scan_config["secrets"])
        for risky_input in scan_config["rce_risks"]["unsafe_inputs"]:
            self.unsafe_input[risky_input] = re.compile(
                scan_config["rce_risks"]["unsafe_inputs"][risky_input]
            )
        for commit_to_watch in scan_config["rce_risks"]["malicious_commits"]:
            self.malicious_commits[commit_to_watch] = re.compile(
                scan_config["rce_risks"]["malicious_commits"][commit_to_watch]
            )
        self.vulnerable = {"vulnerable": True}

    def get_unsafe_inputs(self, command_string) -> list:
        found_matches = {}
        for regex in self.unsafe_input:
            if matches := self.unsafe_input[regex].finditer(command_string):
                matched_commands = [command.group() for command in matches]
                if matched_commands:
                    found_matches[regex] = matched_commands
        return found_matches

    def risky_trigger(self, trigger_name: str) -> bool:
        """Refactored to is_trigger_dangerous"""
        return bool(trigger_name in self.triggers)

    def risky_commit(self, referenced):
        found_matches = {}
        for regex in self.malicious_commits:
            if matches := self.malicious_commits[regex].finditer(referenced):
                matched_commits = [commit.group() for commit in matches]
                if matched_commits:
                    found_matches[regex] = matched_commits
        return found_matches
