from fastapi import FastAPI

from app.api.routes_bas import router as bas_router
from app.core.config import settings


app = FastAPI(
    title=f"{settings.app_name} BAS mTLS",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)
app.include_router(bas_router)
