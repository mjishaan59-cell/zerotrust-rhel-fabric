from dataclasses import dataclass
from typing import List


@dataclass
class Workload:
    workload_id: str
    hostname: str
    role: str
    ip_address: str
    trust_level: str
    tags: List[str]
