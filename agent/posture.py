from agent.collectors.firewall import collect_firewall_state
from agent.collectors.host import (
    collect_hostname,
    collect_ip_addresses,
)
from agent.collectors.network import collect_listening_tcp_ports
from agent.collectors.selinux import collect_selinux_mode
from agent.collectors.services import collect_running_services
from controller.models.security_posture import SecurityPosture


def collect_posture(
    expected_ports: set[int] | None = None,
    expected_services: set[str] | None = None,
) -> tuple[dict, SecurityPosture]:
    expected_ports = expected_ports or set()
    expected_services = expected_services or set()

    hostname = collect_hostname()
    ip_addresses = collect_ip_addresses()
    selinux_mode = collect_selinux_mode()
    firewall_state = collect_firewall_state()
    open_ports = collect_listening_tcp_ports()
    running_services = collect_running_services()

    unexpected_ports = sorted(
        set(open_ports) - expected_ports
    )

    unexpected_services = sorted(
        set(running_services) - expected_services
    )

    posture = SecurityPosture(
        selinux_mode=selinux_mode,
        firewall_state=firewall_state,
        open_ports=open_ports,
        running_services=running_services,
        unexpected_ports=unexpected_ports,
        unexpected_services=unexpected_services,
        compliance_score=100.0,
    )

    metadata = {
        "hostname": hostname,
        "ip_addresses": ip_addresses,
    }

    return metadata, posture
