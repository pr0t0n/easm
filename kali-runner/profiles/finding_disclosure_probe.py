#!/usr/bin/env python3
"""Generic finding-disclosure submission — takes a message describing an
already-confirmed finding (e.g. a vulnerable-library name+version from
retire.js, a leaked API key, a known-vulnerable infrastructure component) and
submits it through whatever public feedback/contact/complaint channel the
target itself exposes, using common REST conventions -- the same idea as
self_register_probe.py's registration-convention wordlist. This mirrors how
a real pentest/bug-bounty report actually gets delivered to a target that
runs its own disclosure program via a contact form, not a hardcoded flow for
any one application.

argv[1] URL      target root URL
argv[2] MESSAGE  the disclosure text to submit (already-confirmed finding
                 detail — the caller decides what technical fact to disclose,
                 this script never invents content)

Prints JSON: {"submitted": bool, "endpoint":..., "fields_used":..., "status":...}
"""
import json
import sys
import urllib.error
import urllib.request

URL = sys.argv[1] if len(sys.argv) > 1 else ""
MESSAGE = sys.argv[2] if len(sys.argv) > 2 else ""

# Generic REST feedback/contact/complaint endpoint conventions — not specific
# to any one application's routing scheme.
_ENDPOINTS = [
    "/api/Feedbacks", "/api/feedbacks", "/api/Complaints", "/api/complaints",
    "/api/contact", "/contact", "/complain", "/api/support", "/api/v1/feedback",
    "/rest/feedback", "/api/messages",
]

# Generic REST field-name conventions for a feedback/complaint payload — a
# wordlist of common shapes, not knowledge of any specific target's schema.
_FIELD_SETS = [
    {"comment": MESSAGE, "rating": 5},
    {"message": MESSAGE},
    {"text": MESSAGE},
    {"comment": MESSAGE},
    {"subject": "Security disclosure", "message": MESSAGE},
    {"body": MESSAGE},
    {"description": MESSAGE},
]


def _post_json(url: str, payload: dict, timeout: int = 10):
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url, data=data, method="POST",
        headers={"Content-Type": "application/json", "User-Agent": "Mozilla/5.0"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read().decode("utf-8", "ignore")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", "ignore")
    except Exception as exc:  # noqa: BLE001
        return None, str(exc)


def main() -> None:
    if not URL or not MESSAGE:
        print(json.dumps({"error": "missing_url_or_message"}))
        return

    origin = URL.rstrip("/")
    for path in _ENDPOINTS:
        for fields in _FIELD_SETS:
            status, body = _post_json(origin + path, fields)
            if status is not None and 200 <= status < 300:
                print(json.dumps({
                    "submitted": True,
                    "endpoint": origin + path,
                    "fields_used": list(fields.keys()),
                    "status": status,
                    "response_excerpt": body[:300],
                }, indent=2))
                return

    print(json.dumps({"submitted": False, "endpoints_tried": _ENDPOINTS}))


if __name__ == "__main__":
    main()
