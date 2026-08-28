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
