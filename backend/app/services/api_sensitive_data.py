"""Sensitive-data classification by VALUE (not field name).

Scans response bodies for PII / financial / secret values using regex + checksum
validation (CPF/CNPJ check digits, credit-card Luhn) to keep false positives low.
Runs fully autonomously on any observed response — no credentials or user input.

Used by the sensitive-data skill to flag OWASP API3 (sensitive data exposure):
an endpoint that returns CPFs, cards, tokens, secrets, etc. in its response.
"""

from __future__ import annotations

import re
from typing import Any

# --------------------------------------------------------------------------- #
# validators (reduce false positives)
# --------------------------------------------------------------------------- #
def _luhn_ok(num: str) -> bool:
    digits = [int(c) for c in num if c.isdigit()]
    if len(digits) < 13:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _cpf_ok(raw: str) -> bool:
    n = [int(c) for c in re.sub(r"\D", "", raw)]
    if len(n) != 11 or len(set(n)) == 1:
        return False
    for k in (9, 10):
        s = sum(n[i] * ((k + 1) - i) for i in range(k))
        d = (s * 10) % 11
        d = 0 if d == 10 else d
        if d != n[k]:
            return False
    return True


def _cnpj_ok(raw: str) -> bool:
    n = [int(c) for c in re.sub(r"\D", "", raw)]
    if len(n) != 14 or len(set(n)) == 1:
        return False
    for size in (12, 13):
        weights = [6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2][13 - size:]
        s = sum(n[i] * weights[i] for i in range(size))
        d = s % 11
        d = 0 if d < 2 else 11 - d
        if d != n[size]:
            return False
    return True


# --------------------------------------------------------------------------- #
# detectors: (type, severity, regex, validator)
# --------------------------------------------------------------------------- #
_DETECTORS: list[tuple[str, str, re.Pattern[str], Any]] = [
    ("cpf", "high", re.compile(r"\b\d{3}\.?\d{3}\.?\d{3}-?\d{2}\b"), _cpf_ok),
    ("cnpj", "high", re.compile(r"\b\d{2}\.?\d{3}\.?\d{3}/?\d{4}-?\d{2}\b"), _cnpj_ok),
    ("credit_card", "critical", re.compile(r"\b(?:\d[ -]?){13,19}\b"), _luhn_ok),
    ("jwt", "high", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"), None),
    ("aws_access_key", "critical", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), None),
    ("private_key", "critical", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"), None),
    ("bearer_token", "high", re.compile(r"\b[Bb]earer\s+[A-Za-z0-9._\-]{20,}\b"), None),
    ("email", "medium", re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"), None),
    # BR mobile only when clearly a phone (DDD in parens or +55 prefix) to avoid
    # matching fragments of CPF/CNPJ/card numbers.
    ("br_phone", "low", re.compile(r"(?:\+55\s?)?\(\d{2}\)\s?9?\d{4}[-.\s]?\d{4}\b"), None),
    ("password_field", "high", re.compile(r'"(?:password|senha|secret|api[_-]?key|token)"\s*:\s*"[^"]{4,}"', re.I), None),
]

# Severity ordering so a finding takes the worst class present.
_SEV_RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}


def _mask(value: str) -> str:
    v = str(value)
    if len(v) <= 6:
        return v[:2] + "***"
    return v[:3] + "***" + v[-2:]


def classify(text: str, *, max_per_type: int = 3) -> dict[str, Any]:
    """Classify sensitive values in a response body. Returns
    ``{types: {type: {count, severity, samples}}, worst_severity, total}``.
    Autonomous — pattern + checksum, no external calls."""
    text = text or ""
    if not text:
        return {"types": {}, "worst_severity": "", "total": 0}
    if len(text) > 200_000:
        text = text[:200_000]
    out: dict[str, Any] = {}
    worst = ""
    total = 0
    for name, sev, rx, validator in _DETECTORS:
        hits: list[str] = []
        for m in rx.finditer(text):
            val = m.group(0)
            if validator is not None and not validator(val):
                continue
            hits.append(val)
            if len(hits) >= 500:
                break
        if not hits:
            continue
        total += len(hits)
        if _SEV_RANK.get(sev, 0) > _SEV_RANK.get(worst, 0):
            worst = sev
        out[name] = {
            "count": len(hits),
            "severity": sev,
            "samples": [_mask(h) for h in hits[:max_per_type]],
        }
    return {"types": out, "worst_severity": worst, "total": total}
