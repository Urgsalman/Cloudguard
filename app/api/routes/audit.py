
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query

from app.api.routes.inventory import read_inventory
from app.core.config import settings
from app.core.security import require_api_token
from app.models.audit import AuditResponse
from app.repositories.audit_repository import (
    get_audit,
    list_audits,
    save_audit,
)
from app.services.audit_service import audit_service

router = APIRouter(
    prefix="/audit",
    tags=["Audit"],
    dependencies=[Depends(require_api_token)],
)


@router.post(
    "",
    response_model=AuditResponse,
    summary="Run a read-only security audit",
)
def run_security_audit(
    subscription_id: str | None = Query(
        default=None,
        description=(
            "Azure subscription ID. Defaults to AZURE_SUBSCRIPTION_ID."
        ),
    ),
) -> AuditResponse:
    selected_subscription = (
        subscription_id or settings.azure_subscription_id
    )

    inventory_response = read_inventory(
        subscription_id=selected_subscription,
    )

    report = audit_service.run_audit(
        subscription_id=inventory_response.subscription_id,
        resources=inventory_response.resources,
    )

    try:
        save_audit(report)
    except (OSError, ValueError) as exc:
        raise HTTPException(
            status_code=500,
            detail="The audit ran, but its history could not be saved.",
        ) from exc

    return AuditResponse(**report)


@router.get(
    "s",
    summary="List previous security audits",
)
def read_audit_history() -> list[dict[str, Any]]:
    try:
        audits = list_audits()
    except (OSError, ValueError) as exc:
        raise HTTPException(
            status_code=500,
            detail="Could not read audit history.",
        ) from exc

    return [
        {
            "audit_id": audit["audit_id"],
            "subscription_id": audit["subscription_id"],
            "audited_at": audit["audited_at"],
            "total_resources": audit["total_resources"],
            "total_findings": audit["total_findings"],
            "summary": audit["summary"],
            "metrics": audit["metrics"],
        }
        for audit in audits
    ]


@router.get(
    "s/{audit_id}",
    response_model=AuditResponse,
    summary="Get a previous security audit",
)
def read_audit_by_id(audit_id: str) -> AuditResponse:
    try:
        audit = get_audit(audit_id)
    except (OSError, ValueError) as exc:
        raise HTTPException(
            status_code=500,
            detail="Could not read audit history.",
        ) from exc

    if audit is None:
        raise HTTPException(
            status_code=404,
            detail="Audit not found.",
        )

    return AuditResponse(**audit)
