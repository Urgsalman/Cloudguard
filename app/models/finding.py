
from enum import Enum

from pydantic import BaseModel, Field


class FindingStatus(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    ERROR = "ERROR"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    UNKNOWN = "UNKNOWN"


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

class Finding(BaseModel):
    rule_id: str
    title: str
    description: str
    status: FindingStatus
    severity: Severity
    resource_id: str
    resource_name: str
    resource_type: str
    rationale: str
    remediation: str | None = None
    evidence: dict[str, object] = Field(default_factory=dict)

    @property
    def is_security_issue(self) -> bool:
        """Return whether the finding represents a detected failure."""
        return self.status == FindingStatus.FAIL