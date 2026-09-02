from controller.models.security_posture import SecurityPosture
from controller.models.risk_result import RiskResult


class RiskEngine:
    """
    Calculates a deterministic security posture score.

    Maximum score: 100
    """

    SELINUX_POINTS = 25
    FIREWALL_POINTS = 20
    UNEXPECTED_PORTS_POINTS = 20
    UNEXPECTED_SERVICES_POINTS = 15
    COMPLIANCE_POINTS = 20

    def evaluate(self, posture: SecurityPosture) -> RiskResult:
        score = 0.0
        reasons: list[str] = []

        # SELinux posture
        if posture.selinux_mode.lower() == "enforcing":
            score += self.SELINUX_POINTS
            reasons.append("SELinux is enforcing")
        else:
            reasons.append(
                f"SELinux mode is {posture.selinux_mode}"
            )

        # Firewall posture
        if posture.firewall_state.lower() == "running":
            score += self.FIREWALL_POINTS
            reasons.append("firewall is running")
        else:
            reasons.append(
                f"firewall state is {posture.firewall_state}"
            )

        # Unexpected network exposure
        if not posture.unexpected_ports:
            score += self.UNEXPECTED_PORTS_POINTS
            reasons.append("no unexpected ports detected")
        else:
            reasons.append(
                f"unexpected ports detected: "
                f"{posture.unexpected_ports}"
            )

        # Unexpected services
        if not posture.unexpected_services:
            score += self.UNEXPECTED_SERVICES_POINTS
            reasons.append("no unexpected services detected")
        else:
            reasons.append(
                f"unexpected services detected: "
                f"{posture.unexpected_services}"
            )

        # Baseline compliance
        compliance = max(0.0, min(100.0, posture.compliance_score))
        compliance_points = (
            compliance / 100
        ) * self.COMPLIANCE_POINTS

        score += compliance_points

        reasons.append(
            f"baseline compliance is {compliance:.1f}%"
        )

        score = round(score, 2)

        if score >= 90:
            level = "LOW"
        elif score >= 70:
            level = "MEDIUM"
        elif score >= 40:
            level = "HIGH"
        else:
            level = "CRITICAL"

        return RiskResult(
            score=score,
            level=level,
            reasons=reasons,
        )
