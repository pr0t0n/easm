#!/usr/bin/env python3
"""Generic self-registration prober — creates a throwaway test account via
the target's own public registration API, GENERICALLY. No target-specific
endpoint path or field names are assumed correct in advance; this tries a
small, common-sense matrix of REST conventions (the same idea as a
directory-fuzzing wordlist), then attempts to log in with the same
credentials it just created.

Many authenticated-only vulnerability classes (IDOR against another user's
data, business-logic abuse, CSRF, basket/session manipulation) can only be
tested once the platform has SOME real, non-admin session of its own — not
a guessed/weak admin credential, but an entirely new, disposable identity
that any "sign up for an account" feature hands out for free to anyone who
asks. This is that generic capability.

argv[1] URL   target root URL

Prints JSON: {"registered": bool, "email":..., "password":..., "endpoint":...,
              "logged_in": bool, "login_endpoint":..., "auth_token":...,
              "set_cookie":...}
"""
import json
import random
import string
import sys
import urllib.error
import urllib.parse
import urllib.request

URL = sys.argv[1] if len(sys.argv) > 1 else ""

# Generic REST registration endpoint conventions — not specific to any one
# application's routing scheme.
_REG_PATHS = [
    "/api/Users", "/api/users", "/api/register", "/api/signup",
    "/rest/user/register", "/register", "/signup", "/api/v1/register",
    "/api/v1/users", "/api/auth/register",
]

_LOGIN_PATHS = [
    "/rest/user/login", "/api/login", "/api/auth/login", "/login", "/api/session",
]


def _rand(n: int = 10) -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


_EMAIL = f"pentest.{_rand(8)}@scriptkiddo.test"
_PASSWORD = f"P{_rand(10)}!9"

# Generic REST field-name conventions for a registration payload — a
# wordlist of common shapes, not knowledge of any specific target's schema.
_REG_FIELD_SETS = [
    {"email": _EMAIL, "password": _PASSWORD, "passwordRepeat": _PASSWORD},
    {"email": _EMAIL, "password": _PASSWORD, "confirmPassword": _PASSWORD},
    {"username": _EMAIL, "password": _PASSWORD, "confirmPassword": _PASSWORD},
    {"email": _EMAIL, "password": _PASSWORD},
    {"username": _EMAIL, "password": _PASSWORD},
]

_LOGIN_FIELD_SETS = [
    {"email": _EMAIL, "password": _PASSWORD},
    {"username": _EMAIL, "password": _PASSWORD},
]


def _post_json(url: str, payload: dict, timeout: int = 10):
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url, data=data, method="POST",
        headers={"Content-Type": "application/json", "User-Agent": "Mozilla/5.0"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read().decode("utf-8", "ignore"), dict(resp.headers)
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", "ignore"), dict(exc.headers or {})
    except Exception as exc:  # noqa: BLE001
        return None, str(exc), {}


def _extract_token(body: str) -> str | None:
    try:
        parsed = json.loads(body)
    except Exception:  # noqa: BLE001
        return None
    for key_path in (("authentication", "token"), ("token",), ("access_token",), ("data", "token")):
        cur = parsed
        for key in key_path:
            cur = cur.get(key) if isinstance(cur, dict) else None
            if cur is None:
                break
        if isinstance(cur, str) and cur:
            return cur
    return None


def main() -> None:
    if not URL:
        print(json.dumps({"error": "no_target_url"}))
        return

    parsed_url = urllib.parse.urlparse(URL)
    origin = f"{parsed_url.scheme}://{parsed_url.netloc}"

    reg_result = None
    for path in _REG_PATHS:
        for fields in _REG_FIELD_SETS:
            status, body, _ = _post_json(origin + path, fields)
            if status is not None and 200 <= status < 300:
                reg_result = {"endpoint": origin + path, "fields_used": list(fields.keys()), "status": status}
                break
        if reg_result:
            break

    if not reg_result:
        print(json.dumps({"registered": False, "email": _EMAIL, "paths_tried": _REG_PATHS}))
        return

    login_result = None
    for path in _LOGIN_PATHS:
        for fields in _LOGIN_FIELD_SETS:
            status, body, headers = _post_json(origin + path, fields)
            if status is not None and 200 <= status < 300:
                login_result = {"endpoint": origin + path, "status": status, "body": body, "headers": headers}
                break
        if login_result:
            break

    out = {
        "registered": True,
        "email": _EMAIL,
        "password": _PASSWORD,
        "registration_endpoint": reg_result["endpoint"],
        "logged_in": bool(login_result),
    }
    if login_result:
        out["login_endpoint"] = login_result["endpoint"]
        out["auth_token"] = _extract_token(login_result["body"])
        out["set_cookie"] = login_result["headers"].get("Set-Cookie")

    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
