from controller.models.security_posture import SecurityPosture
from controller.risk_engine.engine import RiskEngine


def test_healthy_host_gets_low_risk():
    engine = RiskEngine()

    posture = SecurityPosture(
        selinux_mode="Enforcing",
        firewall_state="running",
        open_ports=[22, 80],
        running_services=["sshd", "httpd"],
        unexpected_ports=[],
        compliance_score=100.0,
    )

    result = engine.evaluate(posture)

    assert result.score == 100.0
    assert result.level == "LOW"


def test_unhealthy_host_has_reduced_score():
    engine = RiskEngine()

    posture = SecurityPosture(
        selinux_mode="Permissive",
        firewall_state="stopped",
        open_ports=[22, 80, 4444],
        running_services=["sshd", "httpd"],
        unexpected_ports=[4444],
        compliance_score=50.0,
    )

    result = engine.evaluate(posture)

    assert result.score < 70
    assert result.level in {"HIGH", "CRITICAL"}


def test_compliance_is_clamped():
    engine = RiskEngine()

    posture = SecurityPosture(
        selinux_mode="Enforcing",
        firewall_state="running",
        open_ports=[22],
        running_services=["sshd"],
        unexpected_ports=[],
        compliance_score=120.0,
    )

    result = engine.evaluate(posture)

    assert result.score == 100.0
