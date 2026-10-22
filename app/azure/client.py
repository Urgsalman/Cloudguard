
from typing import Any

from azure.identity import DefaultAzureCredential
from azure.mgmt.resourcegraph import ResourceGraphClient
from azure.mgmt.resourcegraph.models import (
    QueryRequest,
    QueryRequestOptions,
    ResultFormat,
)

MAX_RESOURCES = 1000

INVENTORY_QUERY = """
Resources
| project
    id,
    name,
    type,
    location,
    resourceGroup,
    subscriptionId,
    properties
| order by id asc
"""


def get_azure_inventory(subscription_id: str) -> list[dict[str, Any]]:
    """Retrieve up to MAX_RESOURCES from a subscription using Resource Graph."""
    credential = DefaultAzureCredential()

    try:
        client = ResourceGraphClient(credential)

        request = QueryRequest(
            subscriptions=[subscription_id],
            query=INVENTORY_QUERY,
            options=QueryRequestOptions(
                top=MAX_RESOURCES,
                result_format=ResultFormat.object_array,
            ),
        )

        response = client.resources(request)
        data = response.data or []

        if not isinstance(data, list):
            raise TypeError(
                "Unexpected response format received from Azure Resource Graph."
            )

        if data and isinstance(data[0], list):
            columns = [
                column.name
                for column in (response.columns or [])
            ]

            if not columns:
                raise TypeError(
                    "Azure Resource Graph returned rows without column metadata."
                )

            data = [
                dict(zip(columns, row, strict=False))
                for row in data
                if isinstance(row, list)
            ]

        resources: list[dict[str, Any]] = []

        for item in data:
            if not isinstance(item, dict):
                continue

            properties = item.get("properties")

            if properties is None:
                properties = {}
            elif not isinstance(properties, dict):
                # Preserve the resource record without inventing properties.
                properties = {}

            normalized_item = dict(item)
            normalized_item["properties"] = properties
            resources.append(normalized_item)

        return resources

    finally:
        credential.close()
