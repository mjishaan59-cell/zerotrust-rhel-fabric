from typing import Any

from controller.database.connection import get_database_connection


def save_posture_report(
    *,
    workload_id: str,
    hostname: str,
    ip_addresses: list[str],
    selinux_mode: str,
    firewall_state: str,
    open_ports: list[int],
    running_services: list[str],
    unexpected_ports: list[int],
    unexpected_services: list[str],
    compliance_score: float,
    risk_score: float | None = None,
    risk_level: str | None = None,
) -> int:
    query = """
        INSERT INTO security_posture_reports (
            workload_id,
            hostname,
            ip_addresses,
            selinux_mode,
            firewall_state,
            open_ports,
            running_services,
            unexpected_ports,
            unexpected_services,
            compliance_score,
            risk_score,
            risk_level
        )
        VALUES (
            %(workload_id)s,
            %(hostname)s,
            %(ip_addresses)s,
            %(selinux_mode)s,
            %(firewall_state)s,
            %(open_ports)s,
            %(running_services)s,
            %(unexpected_ports)s,
            %(unexpected_services)s,
            %(compliance_score)s,
            %(risk_score)s,
            %(risk_level)s
        )
        RETURNING id;
    """

    parameters = {
        "workload_id": workload_id,
        "hostname": hostname,
        "ip_addresses": ip_addresses,
        "selinux_mode": selinux_mode,
        "firewall_state": firewall_state,
        "open_ports": open_ports,
        "running_services": running_services,
        "unexpected_ports": unexpected_ports,
        "unexpected_services": unexpected_services,
        "compliance_score": compliance_score,
        "risk_score": risk_score,
        "risk_level": risk_level,
    }

    with get_database_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute(query, parameters)
            row = cursor.fetchone()
            return int(row["id"])


def get_recent_posture_reports(limit: int = 20) -> list[dict[str, Any]]:
    query = """
        SELECT
            id,
            workload_id,
            hostname,
            selinux_mode,
            firewall_state,
            compliance_score,
            risk_score,
            risk_level,
            collected_at
        FROM security_posture_reports
        ORDER BY collected_at DESC
        LIMIT %(limit)s;
    """

    with get_database_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute(query, {"limit": limit})
            return list(cursor.fetchall())
