
from collections import Counter
from datetime import datetime, timezone
from typing import Any

from app.engine.engine import RuleEngine
from app.engine.rules.azure_baseline import DEFAULT_RULES
from app.models.finding import FindingStatus, Severity
from app.models.resource import AzureResource


class AuditService:
    """Run security rules and summarize their findings."""

    def __init__(self) -> None:
        self.engine = RuleEngine(DEFAULT_RULES)

    def run_audit(
        self,
        subscription_id: str,
        resources: list[AzureResource],
    ) -> dict[str, Any]:
        audited_at = datetime.now(timezone.utc)

        findings = self.engine.evaluate(resources)

        status_counts = Counter(
            finding.status.value for finding in findings
        )

        severity_counts = Counter(
            finding.severity.value
            for finding in findings
            if finding.status == FindingStatus.FAIL
        )

        passed = status_counts.get(FindingStatus.PASS.value, 0)
        failed = status_counts.get(FindingStatus.FAIL.value, 0)
        not_applicable = status_counts.get(
            FindingStatus.NOT_APPLICABLE.value, 0
        )
        unknown = status_counts.get(FindingStatus.UNKNOWN.value, 0)
        errors = status_counts.get(FindingStatus.ERROR.value, 0)

        applicable_findings = len(findings) - not_applicable

        evaluated_findings = passed + failed

        compliance_rate = (
            round((passed / evaluated_findings) * 100, 2)
            if evaluated_findings > 0
            else None
        )

        return {
            "audit_id": (
                f"audit-{audited_at.strftime('%Y%m%dT%H%M%S%fZ')}"
            ),
            "subscription_id": subscription_id,
            "audited_at": audited_at.isoformat(),
            "total_resources": len(resources),
            "total_findings": len(findings),
            "summary": {
                status.value: status_counts.get(status.value, 0)
                for status in FindingStatus
            },
            "failed_findings_by_severity": {
                severity.value: severity_counts.get(severity.value, 0)
                for severity in Severity
            },
            "metrics": {
                "security_issues": failed,
                "applicable_findings": applicable_findings,
                "evaluated_findings": evaluated_findings,
                "compliance_rate": compliance_rate,
                "unknown_findings": unknown,
                "error_findings": errors,
            },
            "findings": [
                finding.model_dump(mode="json")
                for finding in findings
            ],
        }


audit_service = AuditService()
