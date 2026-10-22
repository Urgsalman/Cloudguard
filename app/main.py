
from fastapi import FastAPI

from app.api.routes.audit import router as audit_router
from app.api.routes.inventory import router as inventory_router
from app.core.config import settings

app = FastAPI(
    title=settings.app_name,
    description="Azure Cloud Security & Compliance Platform",
    version="0.3.0",
)

app.include_router(inventory_router)
app.include_router(audit_router)


@app.get("/health", tags=["Health"])
def health_check() -> dict[str, str]:
    return {
        "status": "ok",
        "application": settings.app_name,
        "environment": settings.app_env,
    }
