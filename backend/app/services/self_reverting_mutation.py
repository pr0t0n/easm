"""self_reverting_mutation.py — the ONE narrow, code-defined mutation
sequence the platform is allowed to perform outside the read-only baseline
executor: self-grant an observed role/permission to the caller's own
identity, confirm it took effect, and immediately revert it.

This exists because business_logic_test.py's run_as_tool hard-blocks every
method outside {GET, HEAD, OPTIONS} by design (the "no plan, no request"
guard), and skill_execution_engine.py's fixed _ACTION_TEMPLATES are all
non-mutating -- correctly so, since neither module's job is to decide
whether a specific write is safe. Proving privilege escalation (CVSS 9.0/8.8
class findings: self-grant an elevated role via a legitimate assignment
endpoint) genuinely requires a real write, so this module carries that one
capability in isolation, under stricter rules than anything else in the
codebase sends:

  - NEVER invents a request body. The role/permission value comes from an
    already-fetched roles-listing response (real data the target itself
    returned); the body SHAPE comes from a small, code-defined list of
    common REST conventions (see _BODY_SHAPES) tried in order -- not from
    the LLM, not hand-picked per target.
  - NEVER grants to anyone but the caller's own identity (self_user_id,
    read from the caller's own JWT -- see business_logic_test._jwt_self_id).
  - NEVER attempts a grant unless a plausible revert endpoint was
    independently discovered FIRST. No revert path found -> no grant
    attempted, full stop.
  - ALWAYS attempts the revert in a `finally` block, and screams (ScanLog
    level ERROR, unmissable) if the revert doesn't come back clean, so a
    human knows real cleanup may be needed. This module narrows the risk to
    near-zero; it does not, and cannot, claim zero.
"""
from __future__ import annotations

import logging
from typing import Any
from urllib.parse import urlparse

import requests

from app.services.auth_session_manager import privilege_rank

logger = logging.getLogger(__name__)

_HTTP_TIMEOUT = 10
_REVERT_PATH_MARKERS = ("remove", "revoke", "unassign", "detach")

# Small, code-defined REST body-shape conventions -- tried in order, first
# 2xx wins. Never LLM-authored, never target-specific: these are the common
# ways APIs accept "assign this role" across frameworks, not this one app's
# schema guessed by hand.
_BODY_SHAPES: list[tuple[str, Any]] = [
    ("roles_array_of_object", lambda role: {"roles": [role]}),
    ("role_object", lambda role: {"role": role}),
    ("role_name", lambda role: {"role": role.get("name") or role.get("id")}),
    ("roleId", lambda role: {"roleId": role.get("id")}),
    ("role_id", lambda role: {"role_id": role.get("id")}),
    ("permission_name", lambda role: {"permission": role.get("name") or role.get("id")}),
]


def _extract_role_objects(payload: Any) -> list[dict[str, Any]]:
    """Pull {"id":..., "name":...}-shaped role objects out of a roles-listing
    response, wherever the actual list lives (top-level, or wrapped in a
    common "data"/"roles"/"items" envelope)."""
    if isinstance(payload, list):
        candidates = payload
    elif isinstance(payload, dict):
        candidates = None
        for key in ("data", "roles", "items", "results"):
            value = payload.get(key)
            if isinstance(value, list):
                candidates = value
                break
        if candidates is None:
            return []
    else:
        return []
    out = []
    for item in candidates:
        if isinstance(item, dict) and (item.get("id") or item.get("name")):
            out.append({"id": item.get("id"), "name": item.get("name")})
    return out


def _rank_role(role: dict[str, Any]) -> int:
    return privilege_rank(f"{role.get('name') or ''} {role.get('id') or ''}")


def find_revert_endpoint(grant_url: str, endpoints: list[dict[str, str]]) -> dict[str, str] | None:
    """A revert candidate is: DELETE on the same path, or any method on a
    sibling path that names removal (".../roles" -> ".../roles/remove",
    ".../permissions/users/:id" -> ".../permissions/users/:id/remove"). No
    match -> no revert path -> the caller must not attempt the grant."""
    grant_path = urlparse(grant_url).path.rstrip("/")
    for ep in endpoints:
        path = urlparse(str(ep.get("url") or "")).path.rstrip("/")
        method = str(ep.get("method") or "GET").upper()
        if not path:
            continue
        if path == grant_path:
            if method == "DELETE":
                return ep
            continue
        if path.startswith(grant_path) and any(marker in path.lower() for marker in _REVERT_PATH_MARKERS):
            return ep
    return None


def _path_binds_self(url: str, self_user_id: Any) -> bool:
    path = urlparse(str(url or "")).path.lower()
    identity = str(self_user_id or "").strip().lower()
    segments = {part for part in path.split("/") if part}
    return bool(identity and identity in segments or segments & {"me", "self", "current-user"})


def find_roles_listing_endpoint(
    endpoints: list[dict[str, str]], self_user_id: Any | None = None,
) -> dict[str, str] | None:
    """A GET endpoint whose path names roles/permissions -- the source of
    truth for what to self-grant, never an LLM-invented value."""
    for ep in endpoints:
        method = str(ep.get("method") or "GET").upper()
        path = urlparse(str(ep.get("url") or "")).path.lower()
        if method == "GET" and ("role" in path or "permission" in path) and (
            self_user_id is None or _path_binds_self(str(ep.get("url") or ""), self_user_id)
        ):
            return ep
    return None


def execute_self_grant_then_revert(
    *,
    grant_endpoint: str,
    grant_method: str,
    roles_endpoint: str,
    revert_endpoint: dict[str, str],
    headers: dict[str, str],
    cookies: dict[str, str],
    self_user_id: Any,
    scan_id: int,
    log_error: Any,
) -> dict[str, Any]:
    """Runs the full sequence. `log_error(message)` is injected by the caller
    (rather than opening a DB session here) so this module has zero DB
    coupling and stays trivially unit-testable with plain mocks.

    Returns a result dict; never raises -- any exception during the grant
    attempt is treated as "not granted" (fail closed), and the revert is
    still attempted for whatever state was reached.
    """
    result: dict[str, Any] = {
        "granted": False, "escalation_confirmed": False, "reverted": None,
        "attempts": [], "target_role": None, "reason": "", "cleanup_status": "not_required",
    }
    if not self_user_id:
        result["reason"] = "self_identity_unavailable"
        return result
    if not _path_binds_self(grant_endpoint, self_user_id) or not _path_binds_self(roles_endpoint, self_user_id):
        result["reason"] = "endpoints_not_bound_to_caller_identity"
        return result
    try:
        roles_resp = requests.get(roles_endpoint, headers=headers, cookies=cookies, timeout=_HTTP_TIMEOUT, verify=False)
        roles = _extract_role_objects(roles_resp.json() if roles_resp.ok else None)
    except Exception as exc:
        result["reason"] = f"roles_listing_fetch_failed:{exc}"
        return result
    if not roles:
        result["reason"] = "roles_listing_not_parseable"
        return result

    baseline_roles = sorted(str(r.get("name") or r.get("id")) for r in roles)
    result["baseline_roles"] = baseline_roles
    ranked = sorted(roles, key=_rank_role, reverse=True)
    target_role = ranked[0]
    if _rank_role(target_role) < 2:
        # Nothing in the observed list looks more privileged than "peer" --
        # attempting a "self-escalation" to a role that isn't actually
        # elevated proves nothing and isn't worth the write.
        result["reason"] = "no_elevated_role_observed"
        return result
    result["target_role"] = target_role

    granted = False
    mutation_attempted = False
    successful_shape = ""
    try:
        for shape_name, shape_fn in _BODY_SHAPES:
            body = shape_fn(target_role)
            mutation_attempted = True
            try:
                resp = requests.request(
                    grant_method, grant_endpoint, json=body,
                    headers=headers, cookies=cookies, timeout=_HTTP_TIMEOUT, verify=False,
                )
            except Exception as exc:
                result["attempts"].append({"shape": shape_name, "error": str(exc)})
                continue
            result["attempts"].append({"shape": shape_name, "status": resp.status_code})
            if resp.status_code in (200, 201, 204):
                granted = True
                successful_shape = shape_name
                break
        result["granted"] = granted
        if mutation_attempted:
            result["cleanup_status"] = "required"
            try:
                whoami = requests.get(roles_endpoint, headers=headers, cookies=cookies, timeout=_HTTP_TIMEOUT, verify=False)
                after_roles = {r.get("name") or r.get("id") for r in _extract_role_objects(whoami.json() if whoami.ok else None)}
                result["escalation_confirmed"] = (target_role.get("name") or target_role.get("id")) in after_roles
            except Exception:
                # Grant call itself succeeded (2xx) even if the read-back
                # couldn't confirm it -- report the ambiguity rather than
                # silently downgrading to "not escalated".
                result["escalation_confirmed"] = None
    finally:
        if granted:
            revert_url = str(revert_endpoint.get("url") or "")
            revert_method = str(revert_endpoint.get("method") or "DELETE").upper()
            reverted = False
            revert_error = ""
            # DELETE conventionally carries no body. For a non-DELETE revert
            # sibling (e.g. a POST .../remove), try the shape that worked for
            # the grant first (APIs are often symmetric add/remove), then
            # every other shape -- successful cleanup matters more here than
            # a single elegant attempt.
            body_candidates: list[Any] = [None] if revert_method == "DELETE" else [
                shape_fn(target_role)
                for _, shape_fn in sorted(_BODY_SHAPES, key=lambda row: row[0] != successful_shape)
            ]
            for revert_body in body_candidates:
                try:
                    revert_resp = requests.request(
                        revert_method, revert_url, json=revert_body,
                        headers=headers, cookies=cookies, timeout=_HTTP_TIMEOUT, verify=False,
                    )
                except Exception as exc:
                    revert_error = str(exc)
                    continue
                if revert_resp.status_code in (200, 201, 202, 204, 404):
                    break
                revert_error = f"status={revert_resp.status_code}"
            try:
                post = requests.get(roles_endpoint, headers=headers, cookies=cookies, timeout=_HTTP_TIMEOUT, verify=False)
                post_roles = sorted(
                    str(r.get("name") or r.get("id"))
                    for r in _extract_role_objects(post.json() if post.ok else None)
                )
                result["post_rollback_roles"] = post_roles
                reverted = bool(post.ok and post_roles == baseline_roles)
                if not reverted and not revert_error:
                    revert_error = "post_rollback_state_differs_from_baseline"
            except Exception as exc:
                reverted = False
                revert_error = f"post_rollback_readback_failed:{exc}"
            result["reverted"] = reverted
            result["cleanup_status"] = "restored" if reverted else "cleanup_failed"
            if not reverted:
                result["revert_error"] = revert_error
                log_error(
                    f"SELF_GRANT_REVERT_FAILED scan={scan_id} grant_endpoint={grant_endpoint} "
                    f"role={target_role} revert_endpoint={revert_url} last_error={revert_error} -- "
                    "MANUAL CLEANUP REQUIRED: this scan's test identity may still hold an elevated "
                    "role/permission."
                )
    return result
