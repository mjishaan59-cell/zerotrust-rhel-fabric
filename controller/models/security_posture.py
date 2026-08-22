from dataclasses import dataclass
from typing import List


@dataclass
class SecurityPosture:
    selinux_mode: str
    firewall_state: str
    open_ports: List[int]
    running_services: List[str]
    unexpected_ports: List[int]
    compliance_score: float
