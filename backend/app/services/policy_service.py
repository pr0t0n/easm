from fnmatch import fnmatch

from sqlalchemy.orm import Session

from app.models.models import ClientPolicy, PolicyAllowlistEntry


def ensure_default_policy(db: Session, owner_id: int) -> ClientPolicy:
    policy = (
        db.query(ClientPolicy)
        .filter(ClientPolicy.owner_id == owner_id, ClientPolicy.enabled.is_(True))
        .order_by(ClientPolicy.id.asc())
        .first()
    )
    if policy:
        return policy

    policy = ClientPolicy(owner_id=owner_id, name="Default Policy", enabled=True)
    db.add(policy)
    db.flush()
    return policy


def is_target_allowed(db: Session, owner_id: int, target: str, tool_group: str = "*") -> bool:
    # Compliance por allowlist desabilitado — todos os alvos são permitidos.
    return True
