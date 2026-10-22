from collections.abc import Mapping

from app.models.finding import Finding, FindingStatus, Severity
from app.models.resource import AzureResource

KEY_VAULT_TYPES = frozenset({"microsoft.keyvault/vaults"})
VM_TYPES = frozenset({"microsoft.compute/virtualmachines"})
NSG_TYPES = frozenset({"microsoft.network/networksecuritygroups"})


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


def _mapping(value: object) -> Mapping[str, object] | None:
    return value if isinstance(value, Mapping) else None


def _not_applicable(
    resource: AzureResource,
    *,
    rule_id: str,
    title: str,
    description: str,
    severity: Severity,
) -> Finding:
    return _finding(
        resource,
        rule_id=rule_id,
        title=title,
        description=description,
        status=FindingStatus.NOT_APPLICABLE,
        severity=severity,
        rationale="The resource is not targeted by this security control.",
        remediation="No action required for this resource type.",
    )


def key_vault_public_network_rule(resource: AzureResource) -> Finding:
    """Check whether public network access to Key Vault is disabled."""
    if resource.resource_type.lower() not in KEY_VAULT_TYPES:
        return _not_applicable(
            resource,
            rule_id="AZ-KEYVAULT-001",
            title="Key Vault public network access",
            description="Check public network access to Azure Key Vault.",
            severity=Severity.HIGH,
        )

    value = resource.properties.get("publicNetworkAccess")
    normalized = value.strip().lower() if isinstance(value, str) else None

    if normalized == "disabled":
        status = FindingStatus.PASS
        rationale = "Public network access is explicitly disabled."
    elif normalized == "enabled":
        status = FindingStatus.FAIL
        rationale = "Public network access is explicitly enabled."
    else:
        status = FindingStatus.UNKNOWN
        rationale = (
            "publicNetworkAccess is missing or has an unrecognized value."
        )

    return _finding(
        resource,
        rule_id="AZ-KEYVAULT-001",
        title="Key Vault public network access",
        description="Check whether public network access is disabled.",
        status=status,
        severity=Severity.HIGH,
        rationale=rationale,
        remediation=(
            "Disable public network access when compatible with the workload "
            "and use an approved private connectivity design."
        ),
        evidence={"publicNetworkAccess": value},
    )


def key_vault_purge_protection_rule(resource: AzureResource) -> Finding:
    """Check whether Key Vault purge protection is enabled."""
    if resource.resource_type.lower() not in KEY_VAULT_TYPES:
        return _not_applicable(
            resource,
            rule_id="AZ-KEYVAULT-002",
            title="Key Vault purge protection",
            description="Check protection against permanent deletion.",
            severity=Severity.HIGH,
        )

    value = resource.properties.get("enablePurgeProtection")

    if value is True:
        status = FindingStatus.PASS
        rationale = "Purge protection is explicitly enabled."
    elif value is False:
        status = FindingStatus.FAIL
        rationale = "Purge protection is explicitly disabled."
    else:
        status = FindingStatus.UNKNOWN
        rationale = (
            "enablePurgeProtection is missing or is not a boolean."
        )

    return _finding(
        resource,
        rule_id="AZ-KEYVAULT-002",
        title="Key Vault purge protection",
        description="Check whether purge protection is enabled.",
        status=status,
        severity=Severity.HIGH,
        rationale=rationale,
        remediation=(
            "Enable purge protection to reduce the risk of permanent "
            "deletion of vaults and protected objects."
        ),
        evidence={"enablePurgeProtection": value},
    )


def vm_encryption_at_host_rule(resource: AzureResource) -> Finding:
    """Check whether host-based encryption is explicitly enabled on a VM."""
    if resource.resource_type.lower() not in VM_TYPES:
        return _not_applicable(
            resource,
            rule_id="AZ-VM-001",
            title="Virtual machine encryption at host",
            description="Check host-based encryption for an Azure VM.",
            severity=Severity.HIGH,
        )

    security_profile = _mapping(
        resource.properties.get("securityProfile")
    )
    value = (
        security_profile.get("encryptionAtHost")
        if security_profile is not None
        else None
    )

    if value is True:
        status = FindingStatus.PASS
        rationale = "Encryption at host is explicitly enabled."
    elif value is False:
        status = FindingStatus.FAIL
        rationale = "Encryption at host is explicitly disabled."
    else:
        status = FindingStatus.UNKNOWN
        rationale = (
            "securityProfile.encryptionAtHost is missing or not a boolean. "
            "This result does not establish whether managed disks are "
            "encrypted at rest."
        )

    return _finding(
        resource,
        rule_id="AZ-VM-001",
        title="Virtual machine encryption at host",
        description="Check whether host-based encryption is enabled.",
        status=status,
        severity=Severity.HIGH,
        rationale=rationale,
        remediation=(
            "Assess VM and disk compatibility, then enable encryption at "
            "host where required by the security baseline."
        ),
        evidence={"encryptionAtHost": value},
    )


def _ports_expose_ssh_or_rdp(port_values: list[str]) -> tuple[set[str], bool]:
    """Return exposed admin ports and whether any port value was malformed."""
    remote_ports = {"22", "3389"}
    exposed: set[str] = set()
    malformed = False

    for raw_value in port_values:
        value = raw_value.strip()
        if value == "*":
            exposed.update(remote_ports)
            continue

        if value in remote_ports:
            exposed.add(value)
            continue

        # Azure NSG port ranges use the form "start-end".
        if "-" in value:
            parts = value.split("-", maxsplit=1)
            if len(parts) != 2 or not all(part.isdigit() for part in parts):
                malformed = True
                continue

            start_port, end_port = map(int, parts)
            if not (0 <= start_port <= end_port <= 65535):
                malformed = True
                continue

            for remote_port in remote_ports:
                if start_port <= int(remote_port) <= end_port:
                    exposed.add(remote_port)
            continue

        # Other numeric single ports are valid but do not expose SSH/RDP.
        if value.isdigit() and 0 <= int(value) <= 65535:
            continue

        # Unknown formats must not silently produce a PASS.
        malformed = True

    return exposed, malformed


def nsg_ssh_rdp_exposure_rule(resource: AzureResource) -> Finding:
    """Detect inbound Allow rules exposing SSH or RDP to broad sources."""
    if resource.resource_type.lower() not in NSG_TYPES:
        return _not_applicable(
            resource,
            rule_id="AZ-NETWORK-002",
            title="NSG SSH/RDP exposure",
            description="Check broad inbound SSH and RDP access.",
            severity=Severity.HIGH,
        )

    raw_rules = resource.properties.get("securityRules")
    if not isinstance(raw_rules, list):
        return _finding(
            resource,
            rule_id="AZ-NETWORK-002",
            title="NSG SSH/RDP exposure",
            description="Check broad inbound SSH and RDP access.",
            status=FindingStatus.UNKNOWN,
            severity=Severity.HIGH,
            rationale="The securityRules property is missing or invalid.",
            remediation="Retrieve the NSG rules and review inbound access.",
        )

    broad_sources = {"*", "internet", "0.0.0.0/0", "::/0"}
    matches: list[dict[str, object]] = []
    malformed = False

    for raw_rule in raw_rules:
        rule = _mapping(raw_rule)
        if rule is None:
            malformed = True
            continue

        if str(rule.get("direction", "")).strip().lower() != "inbound":
            continue
        if str(rule.get("access", "")).strip().lower() != "allow":
            continue

        sources: list[str] = []
        source = rule.get("sourceAddressPrefix")
        multiple_sources = rule.get("sourceAddressPrefixes", [])

        if isinstance(source, str):
            sources.append(source)
        elif source is not None:
            malformed = True

        if isinstance(multiple_sources, list) and all(
            isinstance(item, str) for item in multiple_sources
        ):
            sources.extend(multiple_sources)
        elif multiple_sources:
            malformed = True

        ports: list[str] = []
        port = rule.get("destinationPortRange")
        multiple_ports = rule.get("destinationPortRanges", [])

        if isinstance(port, str):
            ports.append(port)
        elif port is not None:
            malformed = True

        if isinstance(multiple_ports, list) and all(
            isinstance(item, str) for item in multiple_ports
        ):
            ports.extend(multiple_ports)
        elif multiple_ports:
            malformed = True

        if not sources or not ports:
            malformed = True
            continue

        source_is_broad = any(
            item.strip().lower() in broad_sources for item in sources
        )
        exposed_ports, invalid_ports = _ports_expose_ssh_or_rdp(ports)
        malformed = malformed or invalid_ports

        if source_is_broad and exposed_ports:
            matches.append(
                {
                    "name": rule.get("name"),
                    "sources": sources,
                    "ports": sorted(exposed_ports, key=int),
                }
            )

    if matches:
        status = FindingStatus.FAIL
        rationale = (
            "At least one inbound Allow rule exposes SSH or RDP to a "
            "broad source."
        )
    elif malformed:
        status = FindingStatus.UNKNOWN
        rationale = (
            "Some inbound rules could not be fully evaluated. "
            "The absence of a detected match is not conclusive."
        )
    else:
        status = FindingStatus.PASS
        rationale = (
            "No broad-source inbound Allow rule exposing ports 22 or 3389 "
            "was found in the supplied custom security rules."
        )

    return _finding(
        resource,
        rule_id="AZ-NETWORK-002",
        title="NSG SSH/RDP exposure",
        description="Detect broad inbound SSH or RDP access.",
        status=status,
        severity=Severity.HIGH,
        rationale=rationale,
        remediation=(
            "Restrict SSH and RDP to approved source ranges. Prefer "
            "controlled administration paths such as Azure Bastion "
            "where appropriate."
        ),
        evidence={"matchingRules": matches},
    )


key_vault_public_network_rule.resource_types = KEY_VAULT_TYPES
key_vault_public_network_rule.rule_id = "AZ-KEYVAULT-001"

key_vault_purge_protection_rule.resource_types = KEY_VAULT_TYPES
key_vault_purge_protection_rule.rule_id = "AZ-KEYVAULT-002"

vm_encryption_at_host_rule.resource_types = VM_TYPES
vm_encryption_at_host_rule.rule_id = "AZ-VM-001"

nsg_ssh_rdp_exposure_rule.resource_types = NSG_TYPES
nsg_ssh_rdp_exposure_rule.rule_id = "AZ-NETWORK-002"

EXTENDED_RULES = [
    key_vault_public_network_rule,
    key_vault_purge_protection_rule,
    vm_encryption_at_host_rule,
    nsg_ssh_rdp_exposure_rule,
]
