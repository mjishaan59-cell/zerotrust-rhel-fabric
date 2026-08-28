from agent.posture import collect_posture


def test_live_rhel_posture_collection():
    metadata, posture = collect_posture(
        expected_ports={22, 80},
        expected_services={"sshd.service", "httpd.service"},
    )

    assert metadata["hostname"]
    assert metadata["ip_addresses"]

    assert posture.selinux_mode in {
        "Enforcing",
        "Permissive",
        "Disabled",
    }

    assert posture.firewall_state in {
        "running",
        "not running",
    }

    assert all(
        isinstance(port, int)
        for port in posture.open_ports
    )
