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
    policy = ensure_default_policy(db, owner_id)
    entries = (
        db.query(PolicyAllowlistEntry)
        .filter(PolicyAllowlistEntry.policy_id == policy.id, PolicyAllowlistEntry.is_active.is_(True))
        .all()
    )

    # Sem allowlist ativa => compliance não configurado explicitamente.
    # Nesse caso, não bloquear execução por política.
    if not entries:
        return True

    normalized_target = target.strip().lower()
    normalized_group = tool_group.strip().lower()

    for entry in entries:
        group_ok = entry.tool_group in {"*", normalized_group}
        pattern_ok = fnmatch(normalized_target, entry.target_pattern.strip().lower())
        if group_ok and pattern_ok:
            return True
    return False
