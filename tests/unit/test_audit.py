
from fastapi.testclient import TestClient

from app.api.routes import audit
from app.core.config import settings
from app.main import app
from app.models.resource import AzureInventoryResponse, AzureResource

client = TestClient(app)

TEST_API_TOKEN = "test-api-token"
AUTH_HEADERS = {"Authorization": f"Bearer {TEST_API_TOKEN}"}


def test_audit_returns_findings_without_calling_azure(
    monkeypatch,
) -> None:
    monkeypatch.setattr(settings, "api_token", TEST_API_TOKEN)

    fake_resource = AzureResource(
        id=(
            "/subscriptions/test/resourceGroups/demo/providers/"
            "Microsoft.Storage/storageAccounts/demo"
        ),
        name="demo",
        type="Microsoft.Storage/storageAccounts",
        location="westeurope",
        resource_group="demo",
        subscription_id="test",
        properties={
            "allowBlobPublicAccess": True,
            "minimumTlsVersion": "TLS1_0",
        },
    )

    def fake_read_inventory(
        subscription_id: str | None = None,
    ) -> AzureInventoryResponse:
        return AzureInventoryResponse(
            subscription_id=subscription_id or "test",
            total_resources=1,
            resources=[fake_resource],
        )

    monkeypatch.setattr(
        audit,
        "read_inventory",
        fake_read_inventory,
    )

    response = client.post(
        "/audit",
        params={"subscription_id": "test"},
        headers=AUTH_HEADERS,
    )

    assert response.status_code == 200

    data = response.json()

    assert data["subscription_id"] == "test"
    assert data["total_resources"] == 1
    assert data["total_findings"] == 9

    assert data["summary"]["FAIL"] == 2
    assert data["summary"]["PASS"] == 0
    assert data["summary"]["NOT_APPLICABLE"] == 5
    assert data["summary"]["UNKNOWN"] == 2
    assert data["summary"]["ERROR"] == 0

    finding_ids = [
        finding["rule_id"] for finding in data["findings"]
    ]

    assert finding_ids == [
        "AZ-STORAGE-001",
        "AZ-STORAGE-002",
        "AZ-STORAGE-003",
        "AZ-STORAGE-004",
        "AZ-NETWORK-001",
        "AZ-KEYVAULT-001",
        "AZ-KEYVAULT-002",
        "AZ-VM-001",
        "AZ-NETWORK-002",
    ]

    assert data["metrics"]["security_issues"] == 2
    assert data["metrics"]["applicable_findings"] == 4
    assert data["metrics"]["evaluated_findings"] == 2
    assert data["metrics"]["compliance_rate"] == 0.0
    assert data["metrics"]["unknown_findings"] == 2
    assert data["metrics"]["error_findings"] == 0


def test_audit_compliance_rate_excludes_unknown_and_not_applicable(
    monkeypatch,
) -> None:
    monkeypatch.setattr(settings, "api_token", TEST_API_TOKEN)

    fake_resource = AzureResource(
        id=(
            "/subscriptions/test/resourceGroups/demo/providers/"
            "Microsoft.Storage/storageAccounts/demo"
        ),
        name="demo",
        type="Microsoft.Storage/storageAccounts",
        location="westeurope",
        resource_group="demo",
        subscription_id="test",
        properties={
            "allowBlobPublicAccess": False,
            "minimumTlsVersion": "TLS1_2",
            "encryption": {"services": {"blob": {"enabled": True}}},
            "publicNetworkAccess": "Disabled",
        },
    )

    def fake_read_inventory(
        subscription_id: str | None = None,
    ) -> AzureInventoryResponse:
        return AzureInventoryResponse(
            subscription_id=subscription_id or "test",
            total_resources=1,
            resources=[fake_resource],
        )

    monkeypatch.setattr(
        audit,
        "read_inventory",
        fake_read_inventory,
    )

    response = client.post(
        "/audit",
        params={"subscription_id": "test"},
        headers=AUTH_HEADERS,
    )

    assert response.status_code == 200

    data = response.json()
    metrics = data["metrics"]

    evaluated = data["summary"]["PASS"] + data["summary"]["FAIL"]

    assert metrics["evaluated_findings"] == evaluated

    if evaluated > 0:
        expected_rate = round(
            data["summary"]["PASS"] / evaluated * 100,
            2,
        )
        assert metrics["compliance_rate"] == expected_rate


def test_audit_compliance_rate_is_none_when_nothing_is_evaluated(
    monkeypatch,
) -> None:
    monkeypatch.setattr(settings, "api_token", TEST_API_TOKEN)

    fake_resource = AzureResource(
        id=(
            "/subscriptions/test/resourceGroups/demo/providers/"
            "Microsoft.Compute/virtualMachines/demo"
        ),
        name="demo",
        type="Microsoft.Compute/virtualMachines",
        location="westeurope",
        resource_group="demo",
        subscription_id="test",
        properties={},
    )

    def fake_read_inventory(
        subscription_id: str | None = None,
    ) -> AzureInventoryResponse:
        return AzureInventoryResponse(
            subscription_id=subscription_id or "test",
            total_resources=1,
            resources=[fake_resource],
        )

    monkeypatch.setattr(
        audit,
        "read_inventory",
        fake_read_inventory,
    )

    response = client.post(
        "/audit",
        params={"subscription_id": "test"},
        headers=AUTH_HEADERS,
    )

    assert response.status_code == 200

    data = response.json()

    assert data["metrics"]["evaluated_findings"] == 0
    assert data["metrics"]["compliance_rate"] is None
