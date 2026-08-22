from controller.models.workload import Workload
from controller.models.access_request import AccessRequest
from controller.models.security_posture import SecurityPosture
from controller.models.decision import Decision


def test_workload_model():
    workload = Workload(
        workload_id="WEB01",
        hostname="ztrf-web01",
        role="web",
        ip_address="192.168.152.20",
        trust_level="managed",
        tags=["frontend", "rhel10"],
    )

    assert workload.workload_id == "WEB01"
    assert workload.role == "web"


def test_access_request_model():
    request = AccessRequest(
        request_id="REQ-001",
        source_workload="WEB01",
        destination_workload="APP01",
        protocol="tcp",
        destination_port=8080,
        identity="web-service",
    )

    assert request.destination_workload == "APP01"
    assert request.destination_port == 8080


def test_security_posture_model():
    posture = SecurityPosture(
        selinux_mode="Enforcing",
        firewall_state="running",
        open_ports=[22, 80],
        running_services=["sshd", "httpd"],
        unexpected_ports=[],
        compliance_score=100.0,
    )

    assert posture.selinux_mode == "Enforcing"
    assert posture.unexpected_ports == []


def test_decision_model():
    decision = Decision(
        request_id="REQ-001",
        action="ALLOW",
        risk_score=10.0,
        reason="Matching policy",
    )

    assert decision.action == "ALLOW"
