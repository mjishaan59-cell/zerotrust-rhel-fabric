from controller.models.access_request import AccessRequest
from controller.models.decision import Decision
from controller.models.security_posture import SecurityPosture
from controller.policy_engine.engine import PolicyEngine
from controller.risk_engine.engine import RiskEngine


class DecisionEngine:
    """
    Combines policy evaluation and security posture risk
    into a final Zero Trust decision.
    """

    def __init__(self, policy_path: str):
        self.policy_engine = PolicyEngine(policy_path)
        self.risk_engine = RiskEngine()

    def evaluate(
        self,
        request: AccessRequest,
        posture: SecurityPosture,
    ) -> Decision:
        policy_result = self.policy_engine.evaluate(request)

        if policy_result != "ALLOW":
            return Decision(
                request_id=request.request_id,
                action="DENY",
                risk_score=0.0,
                reason="No matching allow policy",
            )

        risk_result = self.risk_engine.evaluate(posture)

        if risk_result.level == "LOW":
            action = "ALLOW"
        elif risk_result.level == "MEDIUM":
            action = "ALERT"
        else:
            action = "DENY"

        return Decision(
            request_id=request.request_id,
            action=action,
            risk_score=risk_result.score,
            reason="; ".join(risk_result.reasons),
        )
