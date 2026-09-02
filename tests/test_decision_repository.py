from controller.database.repository import (
    get_recent_access_decisions,
    save_access_decision,
)
from controller.models.access_request import AccessRequest
from controller.models.decision import Decision


def test_save_and_read_access_decision():
    request = AccessRequest(
        request_id="REQ-DB-001",
        source_workload="WEB01",
        destination_workload="APP01",
        protocol="tcp",
        destination_port=8080,
        identity="web-service",
    )

    decision = Decision(
        request_id="REQ-DB-001",
        action="ALLOW",
        risk_score=100.0,
        reason="Healthy workload and matching policy",
    )

    decision_id = save_access_decision(decision, request)

    assert decision_id > 0

    decisions = get_recent_access_decisions(limit=10)

    assert any(
        item["id"] == decision_id
        and item["request_id"] == "REQ-DB-001"
        and item["action"] == "ALLOW"
        for item in decisions
    )
