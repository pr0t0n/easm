from datetime import datetime, timedelta, timezone

from jose import JWTError, jwt
from passlib.context import CryptContext

from app.core.config import settings


ALGORITHM = "HS256"
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


def create_access_token(subject: str) -> str:
    expire = datetime.now(timezone.utc) + timedelta(minutes=settings.access_token_expire_minutes)
    payload = {"sub": subject, "exp": expire, "type": "access"}
    return jwt.encode(payload, settings.secret_key, algorithm=ALGORITHM)


def create_refresh_token(subject: str) -> str:
    expire = datetime.now(timezone.utc) + timedelta(days=settings.refresh_token_expire_days)
    payload = {"sub": subject, "exp": expire, "type": "refresh"}
    return jwt.encode(payload, settings.secret_key, algorithm=ALGORITHM)


def decode_access_token(token: str) -> str | None:
    try:
        payload = jwt.decode(token, settings.secret_key, algorithms=[ALGORITHM])
        # Aceita tokens sem campo "type" para compatibilidade retroativa
        if payload.get("type", "access") != "access":
            return None
        return payload.get("sub")
    except JWTError:
        return None


def decode_refresh_token(token: str) -> str | None:
    try:
        payload = jwt.decode(token, settings.secret_key, algorithms=[ALGORITHM])
        if payload.get("type") != "refresh":
            return None
        return payload.get("sub")
    except JWTError:
        return None


def create_bas_agent_token(agent_id: int) -> str:
    """BAS agent credential, type="bas_agent" — segregated from human
    access_token/refresh_token by type, never accepted by decode_access_token."""
    expire = datetime.now(timezone.utc) + timedelta(days=settings.bas_agent_token_expire_days)
    payload = {"sub": f"bas_agent:{agent_id}", "exp": expire, "type": "bas_agent"}
    return jwt.encode(payload, settings.secret_key, algorithm=ALGORITHM)


def decode_bas_agent_token(token: str) -> int | None:
    """Returns the BasAgent id, or None if the token is invalid/expired/wrong type."""
    try:
        payload = jwt.decode(token, settings.secret_key, algorithms=[ALGORITHM])
        if payload.get("type") != "bas_agent":
            return None
        subject = str(payload.get("sub") or "")
        if not subject.startswith("bas_agent:"):
            return None
        return int(subject.split(":", 1)[1])
    except (JWTError, ValueError):
        return None
