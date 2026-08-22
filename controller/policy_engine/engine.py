from dataclasses import asdict
from pathlib import Path
from typing import Any

import yaml

from controller.models.access_request import AccessRequest


class PolicyEngine:
    """
    Evaluates an AccessRequest against the configured Zero Trust policy.

    Policy behavior:
    1. Find a rule matching source workload.
    2. Match destination workload.
    3. Match protocol.
    4. Match destination port.
    5. Return the rule action.
    6. If no rule matches, apply default_action.
    """

    def __init__(self, policy_path: str | Path):
        self.policy_path = Path(policy_path)
        self.policy = self._load_policy()

    def _load_policy(self) -> dict[str, Any]:
        with self.policy_path.open("r", encoding="utf-8") as file:
            policy = yaml.safe_load(file)

        if not isinstance(policy, dict):
            raise ValueError("Policy file must contain a YAML mapping")

        if "default_action" not in policy:
            raise ValueError("Policy must define default_action")

        if "rules" not in policy:
            raise ValueError("Policy must define rules")

        return policy

    def evaluate(self, request: AccessRequest) -> str:
        for rule in self.policy["rules"]:
            source_matches = (
                rule["source"]["workload"]
                == request.source_workload
            )

            destination_matches = (
                rule["destination"]["workload"]
                == request.destination_workload
            )

            protocol_matches = (
                rule["protocol"].lower()
                == request.protocol.lower()
            )

            port_matches = (
                int(rule["port"])
                == request.destination_port
            )

            if (
                source_matches
                and destination_matches
                and protocol_matches
                and port_matches
            ):
                return str(rule["action"]).upper()

        return str(self.policy["default_action"]).upper()
