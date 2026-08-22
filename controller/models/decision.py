from dataclasses import dataclass


@dataclass
class Decision:
    request_id: str
    action: str
    risk_score: float
    reason: str
