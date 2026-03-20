from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session

from app.api.routes_auth import router as auth_router
from app.api.routes_management import router as management_router
from app.api.routes_scans import router as scans_router
from app.api.routes_ws import router as ws_router
from app.core.config import settings
from app.core.security import get_password_hash
from app.db.session import Base, engine
from app.models.models import User


app = FastAPI(title=settings.app_name)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[settings.frontend_origin],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
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
