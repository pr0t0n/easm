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
from app.api.routes_agent_flow import router as agent_flow_router
from app.core.config import settings
from app.core.security import get_password_hash
from app.db.session import Base, engine
from app.models.models import User


app = FastAPI(title=settings.app_name)


def _build_cors_config() -> tuple[list[str] | str, str | None]:
    """
    Constrói configuração de CORS.
    
    Se um regex custom for configurado, usa apenas regex.
    Caso contrário, usa lista de origins + regex para IPs locais.
    """
    # Se há regex customizado, usa só regex
    if settings.frontend_origin_regex:
        return ["*"], settings.frontend_origin_regex
    
    # Caso contrário, combina origens explícitas com regex para IPs locais
    origins: list[str] = []
    for raw in [settings.frontend_origin, settings.frontend_origins]:
        if not raw:
            continue
        origins.extend([item.strip() for item in str(raw).split(",") if item.strip()])
    
    # Remove duplicatas e adiciona wildcard
    origins = list(dict.fromkeys(origins))
    origins.append("*")  # Protegido pelo regex abaixo
    
    # Regex para IPs locais: localhost, 127.0.0.1, 192.168.x.x, 10.x.x.x, 172.16-31.x.x
    regex = (
        r"^https?://(localhost|127\.0\.0\.1|"
        r"192\.168\.\d{1,3}\.\d{1,3}|"
        r"10\.\d{1,3}\.\d{1,3}\.\d{1,3}|"
        r"172\.(1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3})"
        r"(:\d+)?$"
    )
    
    return origins, regex

_cors_origins_list, _cors_regex = _build_cors_config()

app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins_list,
    allow_origin_regex=_cors_regex,
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
    if origin and origin in _cors_origins_list:
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
    seed_skill_library_data()


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


def seed_skill_library_data():
    from app.services.skill_library_service import seed_skill_library
    db: Session = Session(bind=engine)
    try:
        seed_skill_library(db)
    finally:
        db.close()


@app.get("/health")
def health():
    return {"status": "ok"}


app.include_router(auth_router)
app.include_router(scans_router)
app.include_router(management_router)
app.include_router(ws_router)
app.include_router(agent_flow_router)
