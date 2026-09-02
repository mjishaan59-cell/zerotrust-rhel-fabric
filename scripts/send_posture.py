import json
import sys
import urllib.request
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from agent.posture import collect_posture


def main():
    metadata, posture = collect_posture(
        expected_ports={22, 80},
        expected_services={"sshd.service", "httpd.service"},
    )

    payload = {
        "workload_id": "ZTRF-CONTROLLER",
        "hostname": metadata["hostname"],
        "ip_addresses": metadata["ip_addresses"],
        "selinux_mode": posture.selinux_mode,
        "firewall_state": posture.firewall_state,
        "open_ports": posture.open_ports,
        "running_services": posture.running_services,
        "unexpected_ports": posture.unexpected_ports,
        "unexpected_services": posture.unexpected_services,
        "compliance_score": posture.compliance_score,
    }

    data = json.dumps(payload).encode("utf-8")

    request = urllib.request.Request(
        "http://127.0.0.1:8000/api/v1/posture",
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    with urllib.request.urlopen(request, timeout=5) as response:
        print(response.status)
        print(response.read().decode("utf-8"))


if __name__ == "__main__":
    main()
