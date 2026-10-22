from collections.abc import Iterable
from typing import Protocol

from app.models.finding import Finding
from app.models.resource import AzureResource


class Rule(Protocol):
    """Contract for a security rule with declared target resource types."""

    resource_types: frozenset[str]
    rule_id: str

    def __call__(self, resource: AzureResource) -> Finding: ...


class RuleEngine:
    """Execute registered security rules against Azure resources."""

    def __init__(self, rules: Iterable[Rule] = ()) -> None:
        self._rules = list(rules)

    def register(self, rule: Rule) -> None:
        """Register a security rule."""
        self._rules.append(rule)

    def evaluate(
        self,
        resources: Iterable[AzureResource],
    ) -> list[Finding]:
        """Evaluate every registered rule against every resource."""
        findings: list[Finding] = []

        for resource in resources:
            for rule in self._rules:
                try:
                    finding = rule(resource)
                except Exception as exc:  # noqa: BLE001
                    rule_id = getattr(
                        rule,
                        "rule_id",
                        getattr(rule, "__name__", "unknown_rule"),
                    )
                    findings.append(
                        Finding(
                            rule_id=rule_id,
                            title="Rule execution error",
                            description=(
                                "A security rule could not be evaluated."
                            ),
                            status="ERROR",
                            severity="INFO",
                            resource_id=resource.id,
                            resource_name=resource.name,
                            resource_type=resource.resource_type,
                            rationale=(
                                f"Rule execution raised {type(exc).__name__}."
                            ),
                        )
                    )
                    continue

                findings.append(finding)

        return findings
