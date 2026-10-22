from datetime import datetime

from pydantic import BaseModel

from app.models.finding import Finding


class AuditMetrics(BaseModel):
    security_issues: int
    applicable_findings: int
    evaluated_findings: int
    compliance_rate: float | None
    unknown_findings: int
    error_findings: int


class AuditResponse(BaseModel):
    audit_id: str
    subscription_id: str
    audited_at: datetime
    total_resources: int
    total_findings: int
    summary: dict[str, int]
    failed_findings_by_severity: dict[str, int]
    metrics: AuditMetrics
    findings: list[Finding]