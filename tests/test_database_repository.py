from controller.database.repository import (
    get_recent_posture_reports,
    save_posture_report,
)


def test_save_and_read_posture_report():
    report_id = save_posture_report(
        workload_id="TEST01",
        hostname="test01.ztrf.lab",
        ip_addresses=["192.168.100.50"],
        selinux_mode="Enforcing",
        firewall_state="running",
        open_ports=[22, 8080],
        running_services=["sshd.service", "httpd.service"],
        unexpected_ports=[],
        unexpected_services=[],
        compliance_score=100.0,
        risk_score=100.0,
        risk_level="LOW",
    )

    assert report_id > 0

    reports = get_recent_posture_reports(limit=10)

    assert any(
        report["id"] == report_id
        and report["workload_id"] == "TEST01"
        for report in reports
    )
