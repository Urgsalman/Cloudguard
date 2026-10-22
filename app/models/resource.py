
from typing import Any

from pydantic import BaseModel, Field


class AzureResource(BaseModel):
    id: str
    name: str
    resource_type: str = Field(alias="type")
    location: str | None = None
    resource_group: str | None = None
    subscription_id: str | None = None
    properties: dict[str, Any] = Field(default_factory=dict)

    model_config = {"populate_by_name": True}


class AzureInventoryResponse(BaseModel):
    subscription_id: str
    total_resources: int
    resources: list[AzureResource]
