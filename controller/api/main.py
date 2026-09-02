from fastapi import FastAPI

from controller.api.schemas import PostureReport
from controller.database.repository import save_posture_report
from controller.models.security_posture import SecurityPosture
from controller.risk_engine.engine import RiskEngine

app = FastAPI(
    title="ZeroTrust RHEL Fabric",
    version="0.1.0",
    description="Security-posture-aware Zero Trust controller for RHEL workloads",
)

risk_engine = RiskEngine()


@app.get("/health")
def health():
    return {"status": "healthy"}


@app.post("/api/v1/posture")
def submit_posture(report: PostureReport):
    posture = SecurityPosture(
        selinux_mode=report.selinux_mode,
        firewall_state=report.firewall_state,
        open_ports=report.open_ports,
        running_services=report.running_services,
        unexpected_ports=report.unexpected_ports,
        unexpected_services=report.unexpected_services,
        compliance_score=report.compliance_score,
    )

    risk_result = risk_engine.evaluate(posture)

    report_id = save_posture_report(
        workload_id=report.workload_id,
        hostname=report.hostname,
        ip_addresses=report.ip_addresses,
        selinux_mode=report.selinux_mode,
        firewall_state=report.firewall_state,
        open_ports=report.open_ports,
        running_services=report.running_services,
        unexpected_ports=report.unexpected_ports,
        unexpected_services=report.unexpected_services,
        compliance_score=report.compliance_score,
        risk_score=risk_result.score,
        risk_level=risk_result.level,
    )

    return {
        "status": "accepted",
        "report_id": report_id,
        "workload_id": report.workload_id,
        "risk_score": risk_result.score,
        "risk_level": risk_result.level,
    }
