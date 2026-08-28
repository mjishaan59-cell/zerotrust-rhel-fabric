from fastapi import FastAPI

from controller.api.schemas import PostureReport, PostureResponse
from controller.models.security_posture import SecurityPosture
from controller.risk_engine.engine import RiskEngine


app = FastAPI(
    title="ZeroTrust RHEL Fabric",
    version="0.1.0",
    description="Security-posture-aware Zero Trust controller for RHEL 10 workloads",
)

risk_engine = RiskEngine()


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "healthy"}


@app.post(
    "/api/v1/posture",
    response_model=PostureResponse,
)
def submit_posture(report: PostureReport) -> PostureResponse:
    posture = SecurityPosture(
        selinux_mode=report.selinux_mode,
        firewall_state=report.firewall_state,
        open_ports=report.open_ports,
        running_services=report.running_services,
        unexpected_ports=report.unexpected_ports,
        unexpected_services=report.unexpected_services,
        compliance_score=report.compliance_score,
    )

    result = risk_engine.evaluate(posture)

    return PostureResponse(
        status="accepted",
        workload_id=report.workload_id,
        risk_score=result.score,
        risk_level=result.level,
    )
