from fastapi.testclient import TestClient

from controller.api.main import app


client = TestClient(app)


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
            "selinux_mode": "Enforcing",
            "firewall_state": "running",
            "open_ports": [22, 80],
            "running_services": ["sshd.service", "httpd.service"],
            "unexpected_ports": [],
            "unexpected_services": [],
            "compliance_score": 100.0,
        },
    )

    assert response.status_code == 200

    data = response.json()

    assert data["status"] == "accepted"
    assert data["workload_id"] == "WEB01"
    assert data["risk_score"] == 100.0
    assert data["risk_level"] == "LOW"


def test_posture_endpoint_rejects_invalid_compliance():
    response = client.post(
        "/api/v1/posture",
        json={
            "workload_id": "WEB01",
            "hostname": "ztrf-web01.ztrf.lab",
            "ip_addresses": [],
            "selinux_mode": "Enforcing",
            "firewall_state": "running",
            "open_ports": [22, 80],
            "running_services": [],
            "unexpected_ports": [],
            "unexpected_services": [],
            "compliance_score": 150.0,
        },
    )

    assert response.status_code == 422
