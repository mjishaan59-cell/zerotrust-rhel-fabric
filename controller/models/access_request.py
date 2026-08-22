from dataclasses import dataclass


@dataclass
class AccessRequest:
    request_id: str
    source_workload: str
    destination_workload: str
    protocol: str
    destination_port: int
    identity: str
