from collections.abc import Mapping

from app.models.finding import Finding, FindingStatus, Severity
from app.models.resource import AzureResource

STORAGE_RESOURCE_TYPES = frozenset({"microsoft.storage/storageaccounts"})
NSG_RESOURCE_TYPES = frozenset({"microsoft.network/networksecuritygroups"})


def _finding(
    resource: AzureResource,
    *,
    rule_id: str,
    title: str,
    description: str,
    status: FindingStatus,
    severity: Severity,
    rationale: str,
    remediation: str,
    evidence: dict[str, object] | None = None,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        title=title,
        description=description,
        status=status,
        severity=severity,
        resource_id=resource.id,
        resource_name=resource.name,
        resource_type=resource.resource_type,
        rationale=rationale,
        remediation=remediation,
        evidence=evidence or {},
    )


def _as_mapping(value: object) -> Mapping[str, object] | None:
    if isinstance(value, Mapping):
        return value
    return None


def storage_public_access_rule(resource: AzureResource) -> Finding:
    """Evaluate the storage account allowBlobPublicAccess property."""
    if resource.resource_type.lower() not in STORAGE_RESOURCE_TYPES:
        return _finding(
            resource,
            rule_id="AZ-STORAGE-001",
            title="Storage account public blob access",
            description="Check whether anonymous public blob access is permitted.",
            status=FindingStatus.NOT_APPLICABLE,
            severity=Severity.HIGH,
            rationale="The resource is not an Azure Storage account.",
            remediation="No action required for this resource type.",
        )

    value = resource.properties.get("allowBlobPublicAccess")
    if value is False:
        status = FindingStatus.PASS
        rationale = "allowBlobPublicAccess is explicitly false."
    elif value is True:
        status = FindingStatus.FAIL
        rationale = "allowBlobPublicAccess is explicitly true."
    else:
        status = FindingStatus.UNKNOWN
        rationale = (
            "The allowBlobPublicAccess property is missing or not a "
            "boolean in the retrieved resource data."
        )

    return _finding(
        resource,
        rule_id="AZ-STORAGE-001",
        title="Storage account public blob access",
        description="Check whether anonymous public access to blobs is permitted.",
        status=status,
        severity=Severity.HIGH,
        rationale=rationale,
        remediation=(
            "Disable public blob access unless it is explicitly required "
            "and approved."
        ),
        evidence={"allowBlobPublicAccess": value},
    )


def nsg_inbound_access_rule(resource: AzureResource) -> Finding:
    """Detect broad inbound Allow rules in a Network Security Group."""
    if resource.resource_type.lower() not in NSG_RESOURCE_TYPES:
        return _finding(
            resource,
            rule_id="AZ-NETWORK-001",
            title="Network Security Group inbound exposure",
            description="Check for broad inbound Allow rules.",
            status=FindingStatus.NOT_APPLICABLE,
            severity=Severity.HIGH,
            rationale="The resource is not a Network Security Group.",
            remediation="No action required for this resource type.",
        )

    raw_rules = resource.properties.get("securityRules")
    if not isinstance(raw_rules, list):
        return _finding(
            resource,
            rule_id="AZ-NETWORK-001",
            title="Network Security Group inbound exposure",
            description="Check for broad inbound Allow rules.",
            status=FindingStatus.UNKNOWN,
            severity=Severity.HIGH,
            rationale=(
                "The securityRules property is missing or has an "
                "unexpected format."
            ),
            remediation="Retrieve the NSG security rules and review inbound access.",
        )

    broad_rules: list[dict[str, object]] = []
    evaluated_rules = 0
    malformed_rules: list[str] = []
    broad_sources = {"*", "internet", "0.0.0.0/0", "::/0"}

    for index, raw_rule in enumerate(raw_rules):
        rule = _as_mapping(raw_rule)
        if rule is None:
            malformed_rules.append(f"rule[{index}]: invalid object")
            continue

        direction = str(rule.get("direction", "")).lower()
        access = str(rule.get("access", "")).lower()
        if direction != "inbound" or access != "allow":
            continue

        source_single = rule.get("sourceAddressPrefix")
        source_multiple = rule.get("sourceAddressPrefixes", [])
        port_single = rule.get("destinationPortRange")
        port_multiple = rule.get("destinationPortRanges", [])

        invalid = False
        if source_single is not None and not isinstance(source_single, str):
            invalid = True
        if port_single is not None and not isinstance(port_single, str):
            invalid = True
        if not isinstance(source_multiple, list) or not all(
            isinstance(value, str) for value in source_multiple
        ):
            invalid = True
        if not isinstance(port_multiple, list) or not all(
            isinstance(value, str) for value in port_multiple
        ):
            invalid = True

        if invalid:
            malformed_rules.append(
                f"rule[{index}]: invalid source or destination port format"
            )
            continue

        source_values = (
            [source_single] if isinstance(source_single, str) else []
        ) + source_multiple
        port_values = (
            [port_single] if isinstance(port_single, str) else []
        ) + port_multiple

        if not source_values or not port_values:
            malformed_rules.append(
                f"rule[{index}]: missing source or destination port"
            )
            continue

        evaluated_rules += 1
        source_is_broad = any(
            source.strip().lower() in broad_sources for source in source_values
        )
        port_is_broad = any(port.strip() == "*" for port in port_values)

        if source_is_broad and port_is_broad:
            broad_rules.append(dict(rule))

    if broad_rules:
        status = FindingStatus.FAIL
        rationale = (
            "At least one inbound Allow rule has a broad source and "
            "a wildcard destination port range."
        )
    elif malformed_rules:
        status = FindingStatus.UNKNOWN
        rationale = (
            "One or more inbound Allow rules could not be evaluated "
            "reliably because their source or destination port data "
            "was missing or malformed."
        )
    else:
        status = FindingStatus.PASS
        rationale = (
            "No inbound Allow rule matching this specific broad-source "
            "and wildcard-port condition was found among the supplied "
            "custom security rules."
        )

    return _finding(
        resource,
        rule_id="AZ-NETWORK-001",
        title="Network Security Group inbound exposure",
        description=(
            "Detect inbound Allow rules combining a broad source with "
            "a wildcard destination port range."
        ),
        status=status,
        severity=Severity.HIGH,
        rationale=rationale,
        remediation=(
            "Restrict source address ranges and destination ports to "
            "the minimum required. Review all NSG rules before changing them."
        ),
        evidence={
            "evaluatedInboundAllowRules": evaluated_rules,
            "matchingRules": broad_rules,
            "malformedRules": malformed_rules,
        },
    )


def storage_minimum_tls_rule(resource: AzureResource) -> Finding:
    """Check that an Azure Storage account requires TLS 1.2 or later."""
    if resource.resource_type.lower() not in STORAGE_RESOURCE_TYPES:
        return _finding(
            resource,
            rule_id="AZ-STORAGE-002",
            title="Storage account minimum TLS version",
            description="Check the minimum TLS version required by the account.",
            status=FindingStatus.NOT_APPLICABLE,
            severity=Severity.HIGH,
            rationale="The resource is not an Azure Storage account.",
            remediation="No action required for this resource type.",
        )

    value = resource.properties.get("minimumTlsVersion")
    if not isinstance(value, str):
        status = FindingStatus.UNKNOWN
        rationale = "The minimumTlsVersion property is missing or invalid."
    elif value.strip().upper() == "TLS1_2":
        status = FindingStatus.PASS
        rationale = "The storage account requires TLS 1.2."
    elif value.strip().upper() in {"TLS1_0", "TLS1_1"}:
        status = FindingStatus.FAIL
        rationale = f"The storage account requires the outdated version {value}."
    else:
        status = FindingStatus.UNKNOWN
        rationale = f"The TLS value {value!r} is not recognized by this rule."

    return _finding(
        resource,
        rule_id="AZ-STORAGE-002",
        title="Storage account minimum TLS version",
        description="Check the minimum TLS version required by the account.",
        status=status,
        severity=Severity.HIGH,
        rationale=rationale,
        remediation="Configure the account to require TLS 1.2 or later.",
        evidence={"minimumTlsVersion": value},
    )


def storage_blob_encryption_rule(resource: AzureResource) -> Finding:
    """Check whether Blob service encryption is explicitly enabled."""
    if resource.resource_type.lower() not in STORAGE_RESOURCE_TYPES:
        return _finding(
            resource,
            rule_id="AZ-STORAGE-003",
            title="Storage Blob encryption at rest",
            description="Check whether encryption is enabled for the Blob service.",
            status=FindingStatus.NOT_APPLICABLE,
            severity=Severity.HIGH,
            rationale="The resource is not an Azure Storage account.",
            remediation="No action required for this resource type.",
        )

    encryption = _as_mapping(resource.properties.get("encryption"))
    services = (
        _as_mapping(encryption.get("services"))
        if encryption is not None
        else None
    )
    blob = _as_mapping(services.get("blob")) if services is not None else None
    enabled = blob.get("enabled") if blob is not None else None

    if enabled is True:
        status = FindingStatus.PASS
        rationale = "Blob service encryption is explicitly enabled."
    elif enabled is False:
        status = FindingStatus.FAIL
        rationale = "Blob service encryption is explicitly disabled."
    else:
        status = FindingStatus.UNKNOWN
        rationale = (
            "The Blob encryption property is missing or has an "
            "unexpected format."
        )

    return _finding(
        resource,
        rule_id="AZ-STORAGE-003",
        title="Storage Blob encryption at rest",
        description=(
            "Check whether encryption is explicitly enabled for "
            "the Azure Storage Blob service."
        ),
        status=status,
        severity=Severity.HIGH,
        rationale=rationale,
        remediation=(
            "Verify the storage account encryption configuration and "
            "ensure Blob service encryption is enabled."
        ),
        evidence={"blobEncryptionEnabled": enabled},
    )


def storage_public_network_access_rule(resource: AzureResource) -> Finding:
    """Check whether public network access is explicitly disabled."""
    if resource.resource_type.lower() not in STORAGE_RESOURCE_TYPES:
        return _finding(
            resource,
            rule_id="AZ-STORAGE-004",
            title="Storage account public network access",
            description=(
                "Check whether public network access is explicitly disabled."
            ),
            status=FindingStatus.NOT_APPLICABLE,
            severity=Severity.HIGH,
            rationale="The resource is not an Azure Storage account.",
            remediation="No action required for this resource type.",
        )

    value = resource.properties.get("publicNetworkAccess")
    normalized_value = value.strip().lower() if isinstance(value, str) else None

    network_acls = _as_mapping(resource.properties.get("networkAcls"))
    default_action = (
        network_acls.get("defaultAction")
        if network_acls is not None
        else None
    )
    normalized_default_action = (
        default_action.strip().lower()
        if isinstance(default_action, str)
        else None
    )

    if normalized_value == "disabled":
        status = FindingStatus.PASS
        rationale = "Public network access is explicitly disabled."
    elif normalized_value == "enabled":
        status = FindingStatus.FAIL
        rationale = "Public network access is explicitly enabled."
    else:
        status = FindingStatus.UNKNOWN
        rationale = (
            "The publicNetworkAccess property is missing or has an "
            "unrecognized value. The network ACL default action is "
            f"{normalized_default_action!r}, but it cannot independently "
            "confirm whether public network access is enabled or disabled."
        )

    return _finding(
        resource,
        rule_id="AZ-STORAGE-004",
        title="Storage account public network access",
        description=(
            "Check whether public network access is explicitly disabled "
            "for the storage account."
        ),
        status=status,
        severity=Severity.HIGH,
        rationale=rationale,
        remediation=(
            "Review the required connectivity and network ACLs. Disable "
            "public network access if private connectivity is appropriate "
            "for the workload."
        ),
        evidence={
            "publicNetworkAccess": value,
            "networkAclsDefaultAction": default_action,
        },
    )


# Déclaration des types de ressources ciblés par chaque règle.
storage_public_access_rule.resource_types = STORAGE_RESOURCE_TYPES
storage_public_access_rule.rule_id = "AZ-STORAGE-001"

storage_minimum_tls_rule.resource_types = STORAGE_RESOURCE_TYPES
storage_minimum_tls_rule.rule_id = "AZ-STORAGE-002"

storage_blob_encryption_rule.resource_types = STORAGE_RESOURCE_TYPES
storage_blob_encryption_rule.rule_id = "AZ-STORAGE-003"

storage_public_network_access_rule.resource_types = STORAGE_RESOURCE_TYPES
storage_public_network_access_rule.rule_id = "AZ-STORAGE-004"

nsg_inbound_access_rule.resource_types = NSG_RESOURCE_TYPES
nsg_inbound_access_rule.rule_id = "AZ-NETWORK-001"


from app.engine.rules.azure_extended import EXTENDED_RULES

DEFAULT_RULES = [
    storage_public_access_rule,
    storage_minimum_tls_rule,
    storage_blob_encryption_rule,
    storage_public_network_access_rule,
    nsg_inbound_access_rule,
    *EXTENDED_RULES,
]
