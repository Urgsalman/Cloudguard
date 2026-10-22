
from fastapi.testclient import TestClient

from app.api.routes import inventory
from app.core.config import settings
from app.main import app

client = TestClient(app)

TEST_API_TOKEN = "test-api-token"
AUTH_HEADERS = {"Authorization": f"Bearer {TEST_API_TOKEN}"}


def test_inventory_requires_subscription_id_when_not_configured(
    monkeypatch,
) -> None:
    monkeypatch.setattr(settings, "api_token", TEST_API_TOKEN)
    monkeypatch.setattr(
        inventory.settings,
        "azure_subscription_id",
        None,
    )

    response = client.get(
        "/azure/inventory",
        headers=AUTH_HEADERS,
    )

    assert response.status_code == 400
    assert "No subscription ID provided" in response.json()["detail"]


def test_inventory_returns_mocked_resources(monkeypatch) -> None:
    monkeypatch.setattr(settings, "api_token", TEST_API_TOKEN)

    def fake_inventory(subscription_id: str) -> list[dict]:
        return [
            {
                "id": (
                    "/subscriptions/test-sub/resourceGroups/demo-rg/"
                    "providers/Microsoft.Storage/storageAccounts/demo"
                ),
                "name": "demo",
                "type": "Microsoft.Storage/storageAccounts",
                "location": "westeurope",
                "resourceGroup": "demo-rg",
                "subscriptionId": subscription_id,
            }
        ]

    monkeypatch.setattr(
        inventory,
        "get_azure_inventory",
        fake_inventory,
    )

    response = client.get(
        "/azure/inventory",
        params={"subscription_id": "test-sub"},
        headers=AUTH_HEADERS,
    )

    assert response.status_code == 200

    data = response.json()
    assert data["subscription_id"] == "test-sub"
    assert data["total_resources"] == 1
    assert data["resources"][0]["name"] == "demo"
    assert data["resources"][0]["resource_group"] == "demo-rg"
