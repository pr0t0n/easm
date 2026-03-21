from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.core.security import create_access_token, create_refresh_token, decode_refresh_token
from app.db.session import get_db
from app.models.models import User
from app.schemas.auth import MeResponse, TokenResponse, UserCreate, UserLogin
from app.services.auth_service import login_user, register_user


router = APIRouter(prefix="/api/auth", tags=["auth"])


@router.post("/register", response_model=TokenResponse)
def register(payload: UserCreate, db: Session = Depends(get_db)):
    token = register_user(db, payload.email, payload.password)
    return TokenResponse(access_token=token)


@router.post("/login")
def login(payload: UserLogin, db: Session = Depends(get_db)):
    access_token = login_user(db, payload.email, payload.password)
    # Decodifica o subject para gerar o refresh token com o mesmo subject
    from app.core.security import decode_access_token
    subject = decode_access_token(access_token)
    refresh_token = create_refresh_token(subject) if subject else None
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "expires_in": 1440 * 60,  # segundos
    }


@router.post("/refresh")
def refresh(payload: dict, db: Session = Depends(get_db)):
    """
    Recebe { "refresh_token": "..." } e retorna um novo access_token.
    Usado pelo frontend para renovar silenciosamente a sessao durante
    monitoramento de scans longos, sem forcar re-login do usuario.
    """
    raw = (payload.get("refresh_token") or "").strip()
    if not raw:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="refresh_token obrigatorio")

    subject = decode_refresh_token(raw)
    if not subject:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token invalido ou expirado")

    user = db.query(User).filter(User.email == subject, User.is_active == True).first()  # noqa: E712
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Usuario nao encontrado ou inativo")

    new_access = create_access_token(user.email)
    new_refresh = create_refresh_token(user.email)
    return {
        "access_token": new_access,
        "refresh_token": new_refresh,
        "token_type": "bearer",
        "expires_in": 1440 * 60,
    }


@router.get("/me", response_model=MeResponse)
def me(current_user: User = Depends(get_current_user)):
    return MeResponse(
        id=current_user.id,
        email=current_user.email,
        is_admin=current_user.is_admin,
        group_ids=[g.id for g in current_user.groups],
    )
