
from azure.core.exceptions import AzureError
from fastapi import APIRouter, Depends, HTTPException, Query

from app.azure.client import get_azure_inventory
from app.core.config import settings
from app.core.security import require_api_token
from app.models.resource import (
    AzureInventoryResponse,
    AzureResource,
)

router = APIRouter(
    prefix="/azure",
    tags=["Azure"],
    dependencies=[Depends(require_api_token)],
)


@router.get(
    "/inventory",
    response_model=AzureInventoryResponse,
    summary="List Azure resources",
)
def read_inventory(
    subscription_id: str | None = Query(
        default=None,
        description="Azure subscription ID. Defaults to AZURE_SUBSCRIPTION_ID.",
    ),
) -> AzureInventoryResponse:
    selected_subscription = (
        subscription_id or settings.azure_subscription_id
    )

    if not selected_subscription:
        raise HTTPException(
            status_code=400,
            detail=(
                "No subscription ID provided. Pass subscription_id "
                "or configure AZURE_SUBSCRIPTION_ID in .env."
            ),
        )

    try:
        raw_resources = get_azure_inventory(selected_subscription)

        resources: list[AzureResource] = []

        for item in raw_resources:
            if not isinstance(item, dict):
                raise HTTPException(
                    status_code=502,
                    detail="Azure returned a resource in an unexpected format.",
                )

            resource_id = item.get("id")
            resource_name = item.get("name")
            resource_type = item.get("type")

            if not all(
                isinstance(value, str) and value
                for value in (resource_id, resource_name, resource_type)
            ):
                raise HTTPException(
                    status_code=502,
                    detail=(
                        "Azure returned a resource without valid "
                        "id, name, or type."
                    ),
                )

            properties = item.get("properties")

            if properties is None:
                properties = {}
            elif not isinstance(properties, dict):
                raise HTTPException(
                    status_code=502,
                    detail=(
                        "Azure returned resource properties "
                        "in an unexpected format."
                    ),
                )

            resources.append(
                AzureResource(
                    id=resource_id,
                    name=resource_name,
                    type=resource_type,
                    location=item.get("location"),
                    resource_group=item.get("resourceGroup"),
                    subscription_id=item.get("subscriptionId"),
                    properties=properties,
                )
            )

        return AzureInventoryResponse(
            subscription_id=selected_subscription,
            total_resources=len(resources),
            resources=resources,
        )

    except AzureError as exc:
        raise HTTPException(
            status_code=502,
            detail=(
                "Azure Resource Graph request failed. Verify your login, "
                "subscription ID, permissions, and network connectivity."
            ),
        ) from exc

    except (KeyError, TypeError) as exc:
        raise HTTPException(
            status_code=502,
            detail="Azure returned resource data in an unexpected format.",
        ) from exc
