from pathlib import Path

from controller.models.access_request import AccessRequest
from controller.policy_engine.engine import PolicyEngine


PROJECT_ROOT = Path(__file__).resolve().parents[1]
POLICY_FILE = PROJECT_ROOT / "policies" / "access-policy.yaml"


def test_web_to_app_is_allowed():
    engine = PolicyEngine(POLICY_FILE)

    request = AccessRequest(
        request_id="REQ-001",
        source_workload="WEB01",
        destination_workload="APP01",
        protocol="tcp",
        destination_port=8080,
        identity="web-service",
    )

    assert engine.evaluate(request) == "ALLOW"


def test_app_to_db_is_allowed():
    engine = PolicyEngine(POLICY_FILE)

    request = AccessRequest(
        request_id="REQ-002",
        source_workload="APP01",
        destination_workload="DB01",
        protocol="tcp",
        destination_port=5432,
        identity="app-service",
    )

    assert engine.evaluate(request) == "ALLOW"


def test_web_to_db_is_denied():
    engine = PolicyEngine(POLICY_FILE)

    request = AccessRequest(
        request_id="REQ-003",
        source_workload="WEB01",
        destination_workload="DB01",
        protocol="tcp",
        destination_port=5432,
        identity="web-service",
    )

    assert engine.evaluate(request) == "DENY"


def test_wrong_port_is_denied():
    engine = PolicyEngine(POLICY_FILE)

    request = AccessRequest(
        request_id="REQ-004",
        source_workload="WEB01",
        destination_workload="APP01",
        protocol="tcp",
        destination_port=9999,
        identity="web-service",
    )

    assert engine.evaluate(request) == "DENY"
