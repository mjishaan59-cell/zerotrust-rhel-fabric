from dataclasses import dataclass


@dataclass
class RiskResult:
    score: float
    level: str
    reasons: list[str]
