from pathlib import Path

from controller.decision_engine import DecisionEngine
from controller.models.access_request import AccessRequest
from controller.models.security_posture import SecurityPosture


PROJECT_ROOT = Path(__file__).resolve().parents[1]
POLICY_FILE = PROJECT_ROOT / "policies" / "access-policy.yaml"


def healthy_posture():
    return SecurityPosture(
        selinux_mode="Enforcing",
        firewall_state="running",
        open_ports=[22, 80],
        running_services=["sshd.service", "httpd.service"],
        unexpected_ports=[],
        unexpected_services=[],
        compliance_score=100.0,
    )


def unhealthy_posture():
    return SecurityPosture(
        selinux_mode="Permissive",
        firewall_state="stopped",
        open_ports=[22, 80, 4444],
        running_services=["sshd.service", "httpd.service"],
        unexpected_ports=[4444],
        unexpected_services=["suspicious.service"],
        compliance_score=50.0,
    )


def test_allowed_policy_and_healthy_posture():
    engine = DecisionEngine(str(POLICY_FILE))

    request = AccessRequest(
        request_id="REQ-101",
        source_workload="WEB01",
        destination_workload="APP01",
        protocol="tcp",
        destination_port=8080,
        identity="web-service",
    )

    result = engine.evaluate(request, healthy_posture())

    assert result.action == "ALLOW"
    assert result.risk_score == 100.0


def test_allowed_policy_and_unhealthy_posture():
    engine = DecisionEngine(str(POLICY_FILE))

    request = AccessRequest(
        request_id="REQ-102",
        source_workload="WEB01",
        destination_workload="APP01",
        protocol="tcp",
        destination_port=8080,
        identity="web-service",
    )

    result = engine.evaluate(request, unhealthy_posture())

    assert result.action == "DENY"


def test_denied_policy_stays_denied():
    engine = DecisionEngine(str(POLICY_FILE))

    request = AccessRequest(
        request_id="REQ-103",
        source_workload="WEB01",
        destination_workload="DB01",
        protocol="tcp",
        destination_port=5432,
        identity="web-service",
    )

    result = engine.evaluate(request, healthy_posture())

    assert result.action == "DENY"
