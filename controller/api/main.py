from pathlib import Path

from fastapi import FastAPI

from controller.api.schemas import (
    AccessDecisionRequest,
    DecisionResponse,
    PostureReport,
    PostureResponse,
)
from controller.database.repository import (
    save_access_decision,
    save_posture_report,
)
from controller.decision_engine import DecisionEngine
from controller.models.access_request import AccessRequest
from controller.models.security_posture import SecurityPosture
from controller.risk_engine.engine import RiskEngine


PROJECT_ROOT = Path(__file__).resolve().parents[2]
POLICY_FILE = PROJECT_ROOT / "policies" / "access-policy.yaml"


app = FastAPI(
    title="ZeroTrust RHEL Fabric",
    version="0.1.0",
    description="Security-posture-aware Zero Trust controller for RHEL workloads",
)


risk_engine = RiskEngine()
decision_engine = DecisionEngine(str(POLICY_FILE))


@app.get("/health")
def health():
    return {"status": "healthy"}


@app.post("/api/v1/posture", response_model=PostureResponse)
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

    save_posture_report(
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

    return PostureResponse(
        status="accepted",
        workload_id=report.workload_id,
        risk_score=risk_result.score,
        risk_level=risk_result.level,
    )


@app.post(
    "/api/v1/access/decision",
    response_model=DecisionResponse,
)
def evaluate_access(payload: AccessDecisionRequest):
    access_request = AccessRequest(
        request_id=payload.request.request_id,
        source_workload=payload.request.source_workload,
        destination_workload=payload.request.destination_workload,
        protocol=payload.request.protocol,
        destination_port=payload.request.destination_port,
        identity=payload.request.identity,
    )

    security_posture = SecurityPosture(
        selinux_mode=payload.posture.selinux_mode,
        firewall_state=payload.posture.firewall_state,
        open_ports=payload.posture.open_ports,
        running_services=payload.posture.running_services,
        unexpected_ports=payload.posture.unexpected_ports,
        unexpected_services=payload.posture.unexpected_services,
        compliance_score=payload.posture.compliance_score,
    )

    decision = decision_engine.evaluate(
        access_request,
        security_posture,
    )

    save_access_decision(
        decision,
        access_request,
    )

    return DecisionResponse(
        request_id=decision.request_id,
        action=decision.action,
        risk_score=decision.risk_score,
        reason=decision.reason,
    )
