
from app.engine.engine import RuleEngine
from app.engine.rules.azure_baseline import (
    DEFAULT_RULES,
    NSG_RESOURCE_TYPES,
    STORAGE_RESOURCE_TYPES,
    nsg_inbound_access_rule,
    storage_blob_encryption_rule,
    storage_minimum_tls_rule,
    storage_public_access_rule,
    storage_public_network_access_rule,
)
from app.models.finding import Finding, FindingStatus
from app.models.resource import AzureResource


def make_resource(
    resource_type: str,
    name: str = "demo",
    properties: dict[str, object] | None = None,
) -> AzureResource:
    return AzureResource(
        id=(
            "/subscriptions/test/resourceGroups/demo/providers/"
            f"{resource_type}/{name}"
        ),
        name=name,
        type=resource_type,
        location="westeurope",
        resource_group="demo",
        subscription_id="test",
        properties=properties or {},
    )


def test_storage_rule_returns_unknown_without_properties() -> None:
    resource = make_resource("Microsoft.Storage/storageAccounts")
    finding = storage_public_access_rule(resource)
    assert finding.status == FindingStatus.UNKNOWN


def test_storage_rule_is_not_applicable_to_virtual_machine() -> None:
    resource = make_resource("Microsoft.Compute/virtualMachines")
    finding = storage_public_access_rule(resource)
    assert finding.status == FindingStatus.NOT_APPLICABLE


def test_engine_evaluates_all_registered_rules() -> None:
    resource = make_resource("Microsoft.Storage/storageAccounts")
    engine = RuleEngine(
        rules=[storage_public_access_rule, nsg_inbound_access_rule]
    )
    findings = engine.evaluate([resource])

    assert len(findings) == 2
    assert findings[0].status == FindingStatus.UNKNOWN
    assert findings[1].status == FindingStatus.NOT_APPLICABLE


def test_storage_rule_passes_when_public_access_is_disabled() -> None:
    resource = make_resource(
        "Microsoft.Storage/storageAccounts",
        properties={"allowBlobPublicAccess": False},
    )
    finding = storage_public_access_rule(resource)
    assert finding.status == FindingStatus.PASS


def test_storage_rule_fails_when_public_access_is_enabled() -> None:
    resource = make_resource(
        "Microsoft.Storage/storageAccounts",
        properties={"allowBlobPublicAccess": True},
    )
    finding = storage_public_access_rule(resource)

    assert finding.status == FindingStatus.FAIL
    assert finding.evidence["allowBlobPublicAccess"] is True


def test_nsg_rule_fails_for_broad_source_and_wildcard_port() -> None:
    resource = make_resource(
        "Microsoft.Network/networkSecurityGroups",
        properties={
            "securityRules": [
                {
                    "name": "allow-all-inbound",
                    "direction": "Inbound",
                    "access": "Allow",
                    "sourceAddressPrefix": "*",
                    "destinationPortRange": "*",
                }
            ]
        },
    )
    finding = nsg_inbound_access_rule(resource)

    assert finding.status == FindingStatus.FAIL
    assert len(finding.evidence["matchingRules"]) == 1


def test_nsg_rule_passes_when_no_matching_rule_exists() -> None:
    resource = make_resource(
        "Microsoft.Network/networkSecurityGroups",
        properties={
            "securityRules": [
                {
                    "name": "allow-https",
                    "direction": "Inbound",
                    "access": "Allow",
                    "sourceAddressPrefix": "10.0.0.0/24",
                    "destinationPortRange": "443",
                }
            ]
        },
    )
    finding = nsg_inbound_access_rule(resource)
    assert finding.status == FindingStatus.PASS


def test_storage_tls_rule_passes_for_tls_12() -> None:
    resource = make_resource(
        "Microsoft.Storage/storageAccounts",
        properties={"minimumTlsVersion": "TLS1_2"},
    )
    finding = storage_minimum_tls_rule(resource)
    assert finding.status == FindingStatus.PASS


def test_storage_tls_rule_fails_for_tls_10() -> None:
    resource = make_resource(
        "Microsoft.Storage/storageAccounts",
        properties={"minimumTlsVersion": "TLS1_0"},
    )
    finding = storage_minimum_tls_rule(resource)
    assert finding.status == FindingStatus.FAIL


def test_storage_tls_rule_returns_unknown_when_missing() -> None:
    resource = make_resource("Microsoft.Storage/storageAccounts")
    finding = storage_minimum_tls_rule(resource)
    assert finding.status == FindingStatus.UNKNOWN


def test_engine_preserves_not_applicable_findings() -> None:
    """Keep explicit NOT_APPLICABLE results for non-target resources."""
    storage = make_resource(
        "Microsoft.Storage/storageAccounts",
        properties={"allowBlobPublicAccess": False},
    )
    vm = make_resource("Microsoft.Compute/virtualMachines")
    engine = RuleEngine(rules=[storage_public_access_rule])
    findings = engine.evaluate([storage, vm])

    assert len(findings) == 2
    assert findings[0].status == FindingStatus.PASS
    assert findings[1].status == FindingStatus.NOT_APPLICABLE


def test_rules_declare_their_target_resource_types() -> None:
    assert storage_public_access_rule.resource_types == STORAGE_RESOURCE_TYPES
    assert storage_minimum_tls_rule.resource_types == STORAGE_RESOURCE_TYPES
    assert storage_blob_encryption_rule.resource_types == STORAGE_RESOURCE_TYPES
    assert (
        storage_public_network_access_rule.resource_types
        == STORAGE_RESOURCE_TYPES
    )
    assert nsg_inbound_access_rule.resource_types == NSG_RESOURCE_TYPES
    assert len(DEFAULT_RULES) == 9


def test_nsg_rule_returns_unknown_for_malformed_source_prefixes() -> None:
    resource = make_resource(
        "Microsoft.Network/networkSecurityGroups",
        properties={
            "securityRules": [
                {
                    "name": "malformed-source",
                    "direction": "Inbound",
                    "access": "Allow",
                    "sourceAddressPrefix": None,
                    "sourceAddressPrefixes": "Internet",
                    "destinationPortRange": "*",
                }
            ]
        },
    )
    finding = nsg_inbound_access_rule(resource)
    assert finding.status == FindingStatus.UNKNOWN


def test_nsg_rule_returns_unknown_for_malformed_destination_ports() -> None:
    resource = make_resource(
        "Microsoft.Network/networkSecurityGroups",
        properties={
            "securityRules": [
                {
                    "name": "malformed-port",
                    "direction": "Inbound",
                    "access": "Allow",
                    "sourceAddressPrefix": "*",
                    "destinationPortRange": None,
                    "destinationPortRanges": "*",
                }
            ]
        },
    )
    finding = nsg_inbound_access_rule(resource)
    assert finding.status == FindingStatus.UNKNOWN


def test_nsg_rule_keeps_fail_when_another_rule_is_malformed() -> None:
    resource = make_resource(
        "Microsoft.Network/networkSecurityGroups",
        properties={
            "securityRules": [
                {
                    "direction": "Inbound",
                    "access": "Allow",
                    "sourceAddressPrefix": "*",
                    "destinationPortRange": "*",
                },
                {
                    "direction": "Inbound",
                    "access": "Allow",
                    "sourceAddressPrefix": None,
                    "sourceAddressPrefixes": "Internet",
                    "destinationPortRange": "*",
                },
            ]
        },
    )
    finding = nsg_inbound_access_rule(resource)

    assert finding.status == FindingStatus.FAIL
    assert finding.evidence["matchingRules"]
    assert finding.evidence["malformedRules"]


def test_blob_encryption_passes_when_explicitly_enabled() -> None:
    resource = make_resource(
        "Microsoft.Storage/storageAccounts",
        properties={"encryption": {"services": {"blob": {"enabled": True}}}},
    )
    finding = storage_blob_encryption_rule(resource)

    assert finding.status == FindingStatus.PASS
    assert finding.evidence["blobEncryptionEnabled"] is True


def test_blob_encryption_fails_when_explicitly_disabled() -> None:
    resource = make_resource(
        "Microsoft.Storage/storageAccounts",
        properties={"encryption": {"services": {"blob": {"enabled": False}}}},
    )
    finding = storage_blob_encryption_rule(resource)

    assert finding.status == FindingStatus.FAIL
    assert finding.evidence["blobEncryptionEnabled"] is False


def test_blob_encryption_returns_unknown_when_missing() -> None:
    resource = make_resource("Microsoft.Storage/storageAccounts")
    finding = storage_blob_encryption_rule(resource)
    assert finding.status == FindingStatus.UNKNOWN


def test_blob_encryption_is_not_applicable_to_virtual_machine() -> None:
    resource = make_resource("Microsoft.Compute/virtualMachines")
    finding = storage_blob_encryption_rule(resource)
    assert finding.status == FindingStatus.NOT_APPLICABLE


def test_storage_public_network_access_fails_when_enabled() -> None:
    resource = make_resource(
        "Microsoft.Storage/storageAccounts",
        properties={"publicNetworkAccess": "Enabled"},
    )
    finding = storage_public_network_access_rule(resource)

    assert finding.rule_id == "AZ-STORAGE-004"
    assert finding.status == FindingStatus.FAIL
    assert finding.evidence["publicNetworkAccess"] == "Enabled"


def test_storage_public_network_access_passes_when_disabled() -> None:
    resource = make_resource(
        "Microsoft.Storage/storageAccounts",
        properties={"publicNetworkAccess": "Disabled"},
    )
    finding = storage_public_network_access_rule(resource)
    assert finding.status == FindingStatus.PASS


def test_storage_public_network_access_returns_unknown_when_missing() -> None:
    resource = make_resource("Microsoft.Storage/storageAccounts")
    finding = storage_public_network_access_rule(resource)
    assert finding.status == FindingStatus.UNKNOWN


def test_storage_public_network_access_returns_unknown_for_unexpected_value() -> None:
    resource = make_resource(
        "Microsoft.Storage/storageAccounts",
        properties={"publicNetworkAccess": "Sometimes"},
    )
    finding = storage_public_network_access_rule(resource)
    assert finding.status == FindingStatus.UNKNOWN


def test_storage_public_network_access_is_not_applicable_to_vm() -> None:
    resource = make_resource(
        "Microsoft.Compute/virtualMachines",
        properties={"publicNetworkAccess": "Enabled"},
    )
    finding = storage_public_network_access_rule(resource)
    assert finding.status == FindingStatus.NOT_APPLICABLE


def test_engine_continues_after_rule_raises_exception() -> None:
    resource = make_resource(
        "Microsoft.Storage/storageAccounts",
        properties={"allowBlobPublicAccess": False},
    )

    def broken_rule(resource: AzureResource) -> Finding:
        raise RuntimeError("Simulated rule failure")

    broken_rule.resource_types = STORAGE_RESOURCE_TYPES

    engine = RuleEngine(
        rules=[broken_rule, storage_public_access_rule],
    )

    findings = engine.evaluate([resource])

    assert len(findings) == 2

    # La règle en erreur produit un constat ERROR.
    assert findings[0].status == FindingStatus.ERROR
    assert findings[0].title == "Rule execution error"
    assert "RuntimeError" in findings[0].rationale

    # Le moteur poursuit l'exécution de la règle suivante.
    assert findings[1].rule_id == "AZ-STORAGE-001"
    assert findings[1].status == FindingStatus.PASS


from app.engine.rules.azure_extended import (
    EXTENDED_RULES,
    key_vault_public_network_rule,
    key_vault_purge_protection_rule,
    nsg_ssh_rdp_exposure_rule,
    vm_encryption_at_host_rule,
)


def test_extended_rules_are_registered() -> None:
    assert len(EXTENDED_RULES) == 4
    assert len(DEFAULT_RULES) == 9


def test_key_vault_public_network_disabled_passes() -> None:
    resource = make_resource(
        "Microsoft.KeyVault/vaults",
        properties={"publicNetworkAccess": "Disabled"},
    )
    assert (
        key_vault_public_network_rule(resource).status
        == FindingStatus.PASS
    )


def test_key_vault_public_network_enabled_fails() -> None:
    resource = make_resource(
        "Microsoft.KeyVault/vaults",
        properties={"publicNetworkAccess": "Enabled"},
    )
    assert (
        key_vault_public_network_rule(resource).status
        == FindingStatus.FAIL
    )


def test_key_vault_public_network_missing_is_unknown() -> None:
    resource = make_resource("Microsoft.KeyVault/vaults")
    assert (
        key_vault_public_network_rule(resource).status
        == FindingStatus.UNKNOWN
    )


def test_key_vault_purge_protection_enabled_passes() -> None:
    resource = make_resource(
        "Microsoft.KeyVault/vaults",
        properties={"enablePurgeProtection": True},
    )
    assert (
        key_vault_purge_protection_rule(resource).status
        == FindingStatus.PASS
    )


def test_key_vault_purge_protection_disabled_fails() -> None:
    resource = make_resource(
        "Microsoft.KeyVault/vaults",
        properties={"enablePurgeProtection": False},
    )
    assert (
        key_vault_purge_protection_rule(resource).status
        == FindingStatus.FAIL
    )


def test_key_vault_purge_protection_missing_is_unknown() -> None:
    resource = make_resource("Microsoft.KeyVault/vaults")
    assert (
        key_vault_purge_protection_rule(resource).status
        == FindingStatus.UNKNOWN
    )


def test_vm_encryption_at_host_enabled_passes() -> None:
    resource = make_resource(
        "Microsoft.Compute/virtualMachines",
        properties={"securityProfile": {"encryptionAtHost": True}},
    )
    assert vm_encryption_at_host_rule(resource).status == FindingStatus.PASS


def test_vm_encryption_at_host_disabled_fails() -> None:
    resource = make_resource(
        "Microsoft.Compute/virtualMachines",
        properties={"securityProfile": {"encryptionAtHost": False}},
    )
    assert vm_encryption_at_host_rule(resource).status == FindingStatus.FAIL


def test_vm_encryption_at_host_missing_is_unknown() -> None:
    resource = make_resource("Microsoft.Compute/virtualMachines")
    assert (
        vm_encryption_at_host_rule(resource).status
        == FindingStatus.UNKNOWN
    )


def test_nsg_ssh_open_to_internet_fails() -> None:
    resource = make_resource(
        "Microsoft.Network/networkSecurityGroups",
        properties={
            "securityRules": [
                {
                    "name": "allow-ssh",
                    "direction": "Inbound",
                    "access": "Allow",
                    "sourceAddressPrefix": "*",
                    "destinationPortRange": "22",
                }
            ]
        },
    )
    assert nsg_ssh_rdp_exposure_rule(resource).status == FindingStatus.FAIL


def test_nsg_rdp_open_to_internet_fails() -> None:
    resource = make_resource(
        "Microsoft.Network/networkSecurityGroups",
        properties={
            "securityRules": [
                {
                    "name": "allow-rdp",
                    "direction": "Inbound",
                    "access": "Allow",
                    "sourceAddressPrefix": "0.0.0.0/0",
                    "destinationPortRange": "3389",
                }
            ]
        },
    )
    assert nsg_ssh_rdp_exposure_rule(resource).status == FindingStatus.FAIL


def test_nsg_restricted_ssh_passes() -> None:
    resource = make_resource(
        "Microsoft.Network/networkSecurityGroups",
        properties={
            "securityRules": [
                {
                    "name": "allow-ssh-admin",
                    "direction": "Inbound",
                    "access": "Allow",
                    "sourceAddressPrefix": "10.0.0.0/24",
                    "destinationPortRange": "22",
                }
            ]
        },
    )
    assert nsg_ssh_rdp_exposure_rule(resource).status == FindingStatus.PASS


def test_extended_rule_is_not_applicable_to_storage() -> None:
    resource = make_resource("Microsoft.Storage/storageAccounts")
    assert (
        key_vault_public_network_rule(resource).status
        == FindingStatus.NOT_APPLICABLE
    )



def test_nsg_wildcard_port_exposes_ssh_rdp_to_internet() -> None:
    resource = make_resource(
        "Microsoft.Network/networkSecurityGroups",
        properties={
            "securityRules": [
                {
                    "name": "allow-all-ports",
                    "direction": "Inbound",
                    "access": "Allow",
                    "sourceAddressPrefix": "*",
                    "destinationPortRange": "*",
                }
            ]
        },
    )

    finding = nsg_ssh_rdp_exposure_rule(resource)

    assert finding.status == FindingStatus.FAIL
    assert finding.rule_id == "AZ-NETWORK-002"
    assert finding.evidence["matchingRules"]


def test_nsg_port_range_exposing_ssh_fails() -> None:
    resource = make_resource(
        "Microsoft.Network/networkSecurityGroups",
        properties={
            "securityRules": [
                {
                    "name": "allow-ssh-range",
                    "direction": "Inbound",
                    "access": "Allow",
                    "sourceAddressPrefix": "Internet",
                    "destinationPortRange": "20-25",
                }
            ]
        },
    )

    finding = nsg_ssh_rdp_exposure_rule(resource)

    assert finding.status == FindingStatus.FAIL


def test_nsg_port_range_exposing_rdp_fails() -> None:
    resource = make_resource(
        "Microsoft.Network/networkSecurityGroups",
        properties={
            "securityRules": [
                {
                    "name": "allow-rdp-range",
                    "direction": "Inbound",
                    "access": "Allow",
                    "sourceAddressPrefix": "0.0.0.0/0",
                    "destinationPortRange": "3388-3390",
                }
            ]
        },
    )

    finding = nsg_ssh_rdp_exposure_rule(resource)

    assert finding.status == FindingStatus.FAIL


def test_nsg_wildcard_port_from_restricted_source_does_not_fail() -> None:
    resource = make_resource(
        "Microsoft.Network/networkSecurityGroups",
        properties={
            "securityRules": [
                {
                    "name": "allow-all-ports-internal",
                    "direction": "Inbound",
                    "access": "Allow",
                    "sourceAddressPrefix": "10.0.0.0/24",
                    "destinationPortRange": "*",
                }
            ]
        },
    )

    finding = nsg_ssh_rdp_exposure_rule(resource)

    assert finding.status == FindingStatus.PASS
