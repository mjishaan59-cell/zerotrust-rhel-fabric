from fastapi.testclient import TestClient

from controller.api.main import app


client = TestClient(app)


def healthy_posture():
    return {
        "selinux_mode": "Enforcing",
        "firewall_state": "running",
        "open_ports": [22, 80],
        "running_services": ["sshd.service", "httpd.service"],
        "unexpected_ports": [],
        "unexpected_services": [],
        "compliance_score": 100.0,
    }


def unhealthy_posture():
    return {
        "selinux_mode": "Permissive",
        "firewall_state": "stopped",
        "open_ports": [22, 80, 4444],
        "running_services": ["sshd.service", "httpd.service"],
        "unexpected_ports": [4444],
        "unexpected_services": ["suspicious.service"],
        "compliance_score": 50.0,
    }


def test_health_endpoint():
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "healthy"}


def test_posture_endpoint_accepts_healthy_host():
    response = client.post(
        "/api/v1/posture",
        json={
            "workload_id": "WEB01",
            "hostname": "ztrf-web01.ztrf.lab",
            "ip_addresses": ["192.168.152.20/24"],
            **healthy_posture(),
        },
    )

    assert response.status_code == 200

    body = response.json()

    assert body["status"] == "accepted"
    assert body["workload_id"] == "WEB01"
    assert body["risk_score"] == 100.0
    assert body["risk_level"] == "LOW"


def test_posture_endpoint_rejects_invalid_compliance():
    response = client.post(
        "/api/v1/posture",
        json={
            "workload_id": "WEB01",
            "hostname": "ztrf-web01.ztrf.lab",
            "ip_addresses": ["192.168.152.20/24"],
            "selinux_mode": "Enforcing",
            "firewall_state": "running",
            "open_ports": [22, 80],
            "running_services": ["sshd.service", "httpd.service"],
            "unexpected_ports": [],
            "unexpected_services": [],
            "compliance_score": 150.0,
        },
    )

    assert response.status_code == 422


def test_access_decision_allows_healthy_workload():
    response = client.post(
        "/api/v1/access/decision",
        json={
            "request": {
                "request_id": "REQ-201",
                "source_workload": "WEB01",
                "destination_workload": "APP01",
                "protocol": "tcp",
                "destination_port": 8080,
                "identity": "web-service",
            },
            "posture": healthy_posture(),
        },
    )

    assert response.status_code == 200

    body = response.json()

    assert body["request_id"] == "REQ-201"
    assert body["action"] == "ALLOW"
    assert body["risk_score"] == 100.0


def test_access_decision_denies_without_policy_match():
    response = client.post(
        "/api/v1/access/decision",
        json={
            "request": {
                "request_id": "REQ-202",
                "source_workload": "WEB01",
                "destination_workload": "DB01",
                "protocol": "tcp",
                "destination_port": 5432,
                "identity": "web-service",
            },
            "posture": healthy_posture(),
        },
    )

    assert response.status_code == 200

    body = response.json()

    assert body["request_id"] == "REQ-202"
    assert body["action"] == "DENY"
    assert body["risk_score"] == 0.0
    assert body["reason"] == "No matching allow policy"


def test_access_decision_denies_unhealthy_workload():
    response = client.post(
        "/api/v1/access/decision",
        json={
            "request": {
                "request_id": "REQ-203",
                "source_workload": "WEB01",
                "destination_workload": "APP01",
                "protocol": "tcp",
                "destination_port": 8080,
                "identity": "web-service",
            },
            "posture": unhealthy_posture(),
        },
    )

    assert response.status_code == 200

    body = response.json()

    assert body["request_id"] == "REQ-203"
    assert body["action"] == "DENY"
    assert body["risk_score"] < 40.0
    assert "SELinux mode is Permissive" in body["reason"]
