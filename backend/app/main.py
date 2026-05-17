import logging

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)

from app.api.routes_auth import router as auth_router
from app.api.routes_management import router as management_router
from app.api.routes_scans import router as scans_router
from app.api.routes_ws import router as ws_router
from app.core.config import settings
from app.core.security import get_password_hash
from app.db.session import Base, engine
from app.models.models import User


app = FastAPI(title=settings.app_name)


def _cors_origins() -> list[str]:
    origins: list[str] = []
    for raw in [settings.frontend_origin, settings.frontend_origins]:
        if not raw:
            continue
        origins.extend([item.strip() for item in str(raw).split(",") if item.strip()])
    return list(dict.fromkeys(origins))

app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins(),
    allow_origin_regex=settings.frontend_origin_regex,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.exception_handler(Exception)
async def _unhandled_exception_handler(request: Request, exc: Exception):
    """Garante que erros 500 carreguem cabeçalhos CORS.

    O CORSMiddleware fica fora do ServerErrorMiddleware do Starlette, então uma
    exceção não tratada retorna sem ``Access-Control-Allow-Origin`` — e o
    navegador mascara o 500 real como "erro de CORS". Aqui adicionamos os
    cabeçalhos manualmente para que o frontend veja o erro verdadeiro.
    """
    logger.exception("Unhandled error on %s %s", request.method, request.url.path)
    headers: dict[str, str] = {}
    origin = request.headers.get("origin")
    if origin and origin in _cors_origins():
        headers["Access-Control-Allow-Origin"] = origin
        headers["Access-Control-Allow-Credentials"] = "true"
        headers["Vary"] = "Origin"
    return JSONResponse(
        status_code=500,
        content={"detail": "Erro interno do servidor"},
        headers=headers,
    )


@app.on_event("startup")
def on_startup():
    Base.metadata.create_all(bind=engine)
    seed_admin_user()


def seed_admin_user():
    db: Session = Session(bind=engine)
    try:
        existing = db.query(User).filter(User.email == settings.admin_email).first()
        if existing:
            if not existing.is_admin:
                existing.is_admin = True
                db.commit()
            return

        admin = User(
            email=settings.admin_email,
            password_hash=get_password_hash(settings.admin_password),
            is_active=True,
            is_admin=True,
        )
        db.add(admin)
        db.commit()
    finally:
        db.close()


@app.get("/health")
def health():
    return {"status": "ok"}


app.include_router(auth_router)
app.include_router(scans_router)
app.include_router(management_router)
app.include_router(ws_router)
