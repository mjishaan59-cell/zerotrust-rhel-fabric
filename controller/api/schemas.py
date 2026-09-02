from pydantic import BaseModel, Field


class PostureReport(BaseModel):
    workload_id: str = Field(min_length=1)
    hostname: str = Field(min_length=1)
    ip_addresses: list[str] = Field(default_factory=list)

    selinux_mode: str
    firewall_state: str

    open_ports: list[int] = Field(default_factory=list)
    running_services: list[str] = Field(default_factory=list)

    unexpected_ports: list[int] = Field(default_factory=list)
    unexpected_services: list[str] = Field(default_factory=list)

    compliance_score: float = Field(ge=0.0, le=100.0)


class PostureResponse(BaseModel):
    status: str
    workload_id: str
    risk_score: float
    risk_level: str


class AccessRequestSchema(BaseModel):
    request_id: str = Field(min_length=1)
    source_workload: str = Field(min_length=1)
    destination_workload: str = Field(min_length=1)
    protocol: str = Field(min_length=1)
    destination_port: int = Field(ge=1, le=65535)
    identity: str = Field(min_length=1)


class SecurityPostureSchema(BaseModel):
    selinux_mode: str
    firewall_state: str
    open_ports: list[int] = Field(default_factory=list)
    running_services: list[str] = Field(default_factory=list)
    unexpected_ports: list[int] = Field(default_factory=list)
    unexpected_services: list[str] = Field(default_factory=list)
    compliance_score: float = Field(ge=0.0, le=100.0)


class AccessDecisionRequest(BaseModel):
    request: AccessRequestSchema
    posture: SecurityPostureSchema


class DecisionResponse(BaseModel):
    request_id: str
    action: str
    risk_score: float
    reason: str
