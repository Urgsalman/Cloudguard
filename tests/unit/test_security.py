
from fastapi.testclient import TestClient

from app.core.config import settings
from app.main import app

client = TestClient(app)

TEST_API_TOKEN = "test-api-token"
AUTH_HEADERS = {"Authorization": f"Bearer {TEST_API_TOKEN}"}


def test_protected_route_rejects_missing_token(monkeypatch) -> None:
    monkeypatch.setattr(settings, "api_token", TEST_API_TOKEN)

    response = client.get("/azure/inventory")

    assert response.status_code == 401


def test_protected_route_rejects_invalid_token(monkeypatch) -> None:
    monkeypatch.setattr(settings, "api_token", TEST_API_TOKEN)

    response = client.get(
        "/azure/inventory",
        headers={"Authorization": "Bearer invalid-token"},
    )

    assert response.status_code == 401


def test_protected_route_accepts_valid_token(monkeypatch) -> None:
    monkeypatch.setattr(settings, "api_token", TEST_API_TOKEN)
    monkeypatch.setattr(settings, "azure_subscription_id", None)

    response = client.get(
        "/azure/inventory",
        headers=AUTH_HEADERS,
    )

    # L'authentification passe ; l'absence de subscription ID
    # provoque ensuite l'erreur métier attendue.
    assert response.status_code == 400
    assert "No subscription ID provided" in response.json()["detail"]


def test_protected_route_fails_when_token_is_not_configured(
    monkeypatch,
) -> None:
    monkeypatch.setattr(settings, "api_token", None)

    response = client.get(
        "/azure/inventory",
        headers=AUTH_HEADERS,
    )

    assert response.status_code == 503


def test_health_route_remains_public() -> None:
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json()["status"] == "ok"
