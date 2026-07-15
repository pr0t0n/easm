from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy import false
from sqlalchemy.orm import Session

from app.core.security import decode_access_token
from app.db.session import get_db
from app.models.models import AccessGroup, User


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")


def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> User:
    subject = decode_access_token(token)
    if not subject:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token invalido")

    user = db.query(User).filter(User.id == int(subject)).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Usuario nao encontrado")
    return user


def require_admin(current_user: User = Depends(get_current_user)) -> User:
    if not current_user.is_admin:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Acesso apenas para administrador")
    return current_user


def user_company_group_ids(user: User) -> list[int]:
    return [int(g.id) for g in (user.groups or []) if g.id is not None]


def apply_company_scope(query, current_user: User, model):
    """Restrict tenant data to the user's company groups.

    owner_id remains an audit field. Non-admin visibility is based only on
    access_group_id because each group represents a company/tenant.
    """
    if current_user.is_admin:
        return query
    group_ids = user_company_group_ids(current_user)
    if not group_ids:
        return query.filter(false())
    return query.filter(model.access_group_id.in_(group_ids))


def ensure_company_member(current_user: User) -> list[int]:
    group_ids = user_company_group_ids(current_user)
    if not current_user.is_admin and not group_ids:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Usuario sem empresa/grupo associado",
        )
    return group_ids


def can_access_company_resource(current_user: User, access_group_id: int | None) -> bool:
    if current_user.is_admin:
        return True
    if access_group_id is None:
        return False
    return int(access_group_id) in set(user_company_group_ids(current_user))


def resolve_company_group_id(
    db: Session,
    current_user: User,
    access_group_id: int | None,
    access_group_name: str | None = None,
    *,
    required: bool = True,
) -> int | None:
    group_name = str(access_group_name or "").strip()
    if group_name:
        existing = db.query(AccessGroup).filter(AccessGroup.name == group_name).first()
        if existing is None:
            if not current_user.is_admin:
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Grupo de empresa nao permitido")
            existing = AccessGroup(owner_id=current_user.id, name=group_name, description="")
            db.add(existing)
            db.flush()
        access_group_id = existing.id

    user_group_ids = user_company_group_ids(current_user)
    if access_group_id in ["", 0]:  # defensive for dict payloads
        access_group_id = None

    if access_group_id is None:
        if not required:
            return None
        if not current_user.is_admin and len(user_group_ids) == 1:
            return user_group_ids[0]
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Empresa/grupo obrigatorio")

    access_group_id = int(access_group_id)
    group = db.query(AccessGroup).filter(AccessGroup.id == access_group_id).first()
    if not group:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Empresa/grupo nao encontrado")

    if not current_user.is_admin and access_group_id not in user_group_ids:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Empresa/grupo nao permitido")
    return access_group_id
