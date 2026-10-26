"""Deterministic OpenAPI variable corpus used by the API fuzzer.

The corpus is deliberately generated instead of checked in as a 10,000-line
payload file.  That keeps the repository small, makes runs reproducible and
avoids accidentally shipping customer identifiers or credentials.  Values are
synthetic and use reserved/example domains wherever a URL or e-mail is needed.

The corpus is a *candidate library*, not a request budget.  A scan opts into a
bounded number of candidates per parameter through ``fuzz_library_budget``;
the runner never sends all 10,000 values to an endpoint by default.
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import date, datetime, timedelta, timezone
from functools import lru_cache
from typing import Any


CORPUS_VERSION = "openapi-variable-corpus-v1"
DEFAULT_CORPUS_SIZE = 10_000
MAX_CORPUS_SIZE = 10_000


# (category, JSON type, OpenAPI format, name hints).  Fifty families x 200
# variants gives an exact 10,000-entry deterministic library.
_CATEGORY_SPECS: tuple[tuple[str, str, str, tuple[str, ...]], ...] = (
    ("identifier", "string", "", ("id", "identifier", "externalId")),
    ("uuid", "string", "uuid", ("id", "uuid", "requestId", "projectId")),
    ("email", "string", "email", ("email", "userEmail", "contact")),
    ("url", "string", "uri", ("url", "uri", "website", "callbackUrl")),
    ("ssrf", "string", "uri", ("url", "uri", "webhook", "callback", "imageUrl")),
    ("date", "string", "date", ("date", "birthDate", "startDate", "endDate")),
    ("datetime", "string", "date-time", ("createdAt", "updatedAt", "timestamp")),
    ("cpf", "string", "", ("cpf", "document", "taxId")),
    ("cnpj", "string", "", ("cnpj", "companyDocument", "taxId")),
    ("phone", "string", "phone", ("phone", "mobile", "telephone")),
    ("integer", "integer", "int64", ("id", "count", "number", "index")),
    ("decimal", "number", "double", ("amount", "price", "balance", "rate")),
    ("boolean", "boolean", "", ("enabled", "active", "verified", "optIn")),
    ("null", "null", "", ("value", "optional", "nullable")),
    ("empty", "string", "", ("value", "name", "description")),
    ("whitespace", "string", "", ("value", "name", "description")),
    ("oversized", "string", "", ("value", "name", "description", "comment")),
    ("unicode", "string", "", ("name", "description", "displayName")),
    ("json", "string", "json", ("payload", "metadata", "data")),
    ("xml", "string", "xml", ("payload", "document", "data")),
    ("sql", "string", "", ("query", "search", "filter", "name")),
    ("nosql", "string", "", ("query", "filter", "where", "selector")),
    ("ssti", "string", "", ("template", "message", "name")),
    ("xss", "string", "", ("html", "content", "name", "description")),
    ("command", "string", "", ("command", "filename", "path")),
    ("traversal", "string", "", ("path", "file", "filename", "directory")),
    ("template", "string", "", ("template", "expression", "format")),
    ("regex", "string", "", ("pattern", "regex", "search")),
    ("html", "string", "", ("html", "content", "description")),
    ("csv", "string", "", ("csv", "import", "rows")),
    ("pagination", "integer", "int32", ("page", "limit", "offset", "cursor")),
    ("sort", "string", "", ("sort", "order", "orderBy", "direction")),
    ("filter", "string", "", ("filter", "where", "criteria", "status")),
    ("search", "string", "", ("q", "query", "search", "term")),
    ("token", "string", "", ("token", "apiKey", "accessToken", "authorization")),
    ("header", "string", "", ("x-api-key", "x-tenant-id", "x-forwarded-for")),
    ("cookie", "string", "", ("session", "cookie", "sid")),
    ("ip", "string", "ipv4", ("ip", "clientIp", "sourceIp", "address")),
    ("host", "string", "hostname", ("host", "hostname", "domain")),
    ("port", "integer", "int32", ("port", "serverPort")),
    ("filename", "string", "", ("filename", "name", "upload")),
    ("filepath", "string", "", ("path", "filePath", "location")),
    ("mime", "string", "media-type", ("contentType", "mimeType", "type")),
    ("base64", "string", "byte", ("data", "content", "file")),
    ("jwt", "string", "", ("token", "jwt", "authorization")),
    ("graphql", "string", "", ("query", "mutation", "operation")),
    ("xml-entity", "string", "xml", ("xml", "document", "payload")),
    ("redirect", "string", "uri", ("redirectUri", "returnUrl", "next")),
    ("origin", "string", "uri", ("origin", "referer", "callback")),
    ("tenant", "string", "", ("tenantId", "organizationId", "accountId")),
    ("currency", "string", "iso-4217", ("currency", "currencyCode", "amount")),
    ("country", "string", "iso-3166", ("country", "countryCode", "locale")),
    ("timezone", "string", "", ("timezone", "tz", "zone")),
    ("latitude", "number", "double", ("lat", "latitude")),
    ("longitude", "number", "double", ("lon", "lng", "longitude")),
    ("semver", "string", "", ("version", "release", "apiVersion")),
    ("cron", "string", "", ("cron", "schedule", "expression")),
    ("idempotency", "string", "", ("idempotencyKey", "requestKey", "correlationId")),
)


def _digest(category: str, index: int) -> str:
    return hashlib.sha256(f"{CORPUS_VERSION}:{category}:{index}".encode()).hexdigest()


def _cpf(index: int) -> str:
    # Deliberately synthetic: fixed prefix plus index, with no customer data.
    return f"000{index:08d}"[-11:]


def _cnpj(index: int) -> str:
    return f"000000{index:08d}"[-14:]


def _value(category: str, index: int) -> Any:
    digest = _digest(category, index)
    if category == "identifier":
        return f"object-{index + 1}"
    if category == "uuid":
        return str(uuid.uuid5(uuid.NAMESPACE_URL, f"https://example.test/{digest}"))
    if category == "email":
        return f"user-{index + 1}@example.test"
    if category == "url":
        return f"https://example.test/resource/{index + 1}"
    if category == "ssrf":
        values = ("http://127.0.0.1/", "http://169.254.169.254/latest/meta-data/", "http://[::1]/", "file:///etc/passwd", "http://0.0.0.0/")
        return values[index % len(values)] + (f"?case={index}" if "?" not in values[index % len(values)] else "")
    if category == "date":
        return (date(1970, 1, 1) + timedelta(days=index)).isoformat()
    if category == "datetime":
        return (datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(minutes=index)).isoformat().replace("+00:00", "Z")
    if category == "cpf":
        return _cpf(index)
    if category == "cnpj":
        return _cnpj(index)
    if category == "phone":
        return f"+551199{index:06d}"
    if category == "integer":
        values = (0, -1, 1, 2_147_483_647, 2_147_483_648, -2_147_483_648, 9_223_372_036_854_775_807)
        return values[index % len(values)] if index < len(values) else index + 1_000_000
    if category == "decimal":
        # Keep the HTTP/JSON representation valid: non-finite numbers are
        # represented as strings so the catalog endpoint remains serializable.
        values = (0, -1, 0.1, 1.5, 2_147_483_647.0, 1e308, "Infinity", "NaN")
        return values[index % len(values)] if index < len(values) else round((index + 1) / 3.0, 6)
    if category == "boolean":
        return (True, False, "true", "false", 1, 0, "yes", None)[index % 8]
    if category == "null":
        return None
    if category == "empty":
        return ""
    if category == "whitespace":
        return " " * (index % 32 + 1)
    if category == "oversized":
        return "A" * (1024 + (index * 137))
    if category == "unicode":
        return ("😀 café Привет العربية ‮" * (index % 4 + 1))[:512]
    if category == "json":
        return '{"case":%d,"nested":{"value":"%s"}}' % (index, digest[:8])
    if category == "xml":
        return f"<root case='{index}'><value>{digest[:8]}</value></root>"
    if category == "sql":
        return ("' OR '1'='1'", "1; DROP TABLE users--", "' UNION SELECT NULL--", "admin'--")[index % 4] + f" /*case-{index}*/"
    if category == "nosql":
        return ("{\"$ne\":null}", "{\"$gt\":\"\"}", "{\"$where\":\"sleep(1)\"}", "{\"$regex\":\".*\"}")[index % 4]
    if category == "ssti":
        return ("{{7*7}}", "${7*7}", "#{7*7}", "<%= 7*7 %>")[index % 4]
    if category in {"xss", "html"}:
        return ("<script>alert(1)</script>", "\"><img src=x onerror=alert(1)>", "javascript:alert(1)")[index % 3]
    if category == "command":
        return ("; id", "| whoami", "$(id)", "`id`", "&& cat /etc/passwd")[index % 5]
    if category == "traversal" or category == "filepath":
        return ("../../../../etc/passwd", "..\\..\\..\\windows\\win.ini", "%2e%2e%2f%2e%2e%2f")[index % 3]
    if category == "template":
        return ("${{7*7}}", "{{config}}", "<%= system('id') %>")[index % 3]
    if category == "regex":
        return (".*", "(a+)+$", "(?=a)", "[\\p{L}]+", "(?i)admin")[index % 5]
    if category == "csv":
        return f'"=HYPERLINK("http://example.test/{index}","click")",value-{index}'
    if category == "pagination":
        return (0, -1, 1, 10, 100, 2_147_483_647, 9_999_999_999)[index % 7]
    if category == "sort":
        return ("id", "-id", "createdAt", "createdAt desc", "unknown", "1;DROP")[index % 6]
    if category in {"filter", "search"}:
        return ("", "*", "null", "admin", "' OR '1'='1", "../../", digest[:16])[index % 7]
    if category == "token":
        return f"Bearer synthetic-{digest[:48]}"
    if category == "header":
        return ("*", "attacker.example", "../../", "null", digest[:32])[index % 5]
    if category == "cookie":
        return f"session=synthetic-{digest[:32]}"
    if category == "ip":
        values = ("127.0.0.1", "0.0.0.0", "169.254.169.254", "10.0.0.1", "192.168.0.1", "::1", "::ffff:127.0.0.1")
        return values[index % len(values)]
    if category == "host":
        return ("localhost", "127.0.0.1", "169.254.169.254", "internal.example.test", "attacker.example")[index % 5]
    if category == "port":
        return (0, 1, 22, 80, 443, 65535, 65536, -1)[index % 8]
    if category == "filename":
        return ("file.txt", "../../etc/passwd", "file.php", "image.svg", "upload.jsp")[index % 5]
    if category == "mime":
        return ("application/json", "text/plain", "image/svg+xml", "application/octet-stream", "text/html")[index % 5]
    if category == "base64":
        return ("", "AA==", "////", "SGVsbG8=", "invalid-base64")[index % 5]
    if category == "jwt":
        return f"eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJzeW50aGV0aWMt{digest[:16]}In0."
    if category == "graphql":
        return ("{__schema{types{name}}}", "mutation{deleteAll}", "query{user(id:1){id}}", "{user{password}}", "query($x:String!){search(q:$x)}")[index % 5]
    if category == "xml-entity":
        return "<!DOCTYPE root [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><root>&xxe;</root>"
    if category in {"redirect", "origin"}:
        return ("https://example.test/return", "https://attacker.example/", "//attacker.example/", "javascript:alert(1)", "data:text/html,alert(1)")[index % 5]
    if category == "tenant":
        return f"tenant-{index + 1}"
    if category == "currency":
        return ("BRL", "USD", "EUR", "XXX", "<script>")[index % 5]
    if category == "country":
        return ("BR", "US", "ZZ", "..", "<script>")[index % 5]
    if category == "timezone":
        return ("UTC", "America/Sao_Paulo", "Etc/GMT+12", "../../etc", "Invalid/Zone")[index % 5]
    if category == "latitude":
        return (0.0, -90.0, 90.0, 90.0001, -90.0001, "NaN")[index % 6]
    if category == "longitude":
        return (0.0, -180.0, 180.0, 180.0001, -180.0001, "NaN")[index % 6]
    if category == "semver":
        return ("0.0.0", "1.2.3", "9999.9999.9999", "v1", "1.0.0-alpha+build")[index % 5]
    if category == "cron":
        return ("* * * * *", "0 0 * * *", "*/0 * * * *", "; id", "invalid")[index % 5]
    if category == "idempotency":
        return f"idem-{digest[:32]}"
    return digest[:32]


@lru_cache(maxsize=4)
def build_openapi_variable_corpus(size: int = DEFAULT_CORPUS_SIZE) -> tuple[dict[str, Any], ...]:
    """Build a stable corpus with exactly ``size`` entries (max 10,000)."""
    try:
        requested = int(size)
    except (TypeError, ValueError):
        requested = DEFAULT_CORPUS_SIZE
    requested = max(1, min(requested, MAX_CORPUS_SIZE))
    entries: list[dict[str, Any]] = []
    per_category, remainder = divmod(requested, len(_CATEGORY_SPECS))
    for category_index, (category, type_hint, fmt, hints) in enumerate(_CATEGORY_SPECS):
        category_size = per_category + (1 if category_index < remainder else 0)
        for index in range(category_size):
            if len(entries) >= requested:
                return tuple(entries)
            entries.append({
                "id": f"{category}:{index:03d}",
                "value": _value(category, index),
                "label": f"library:{category}:{index:03d}",
                "category": category,
                "type_hint": type_hint,
                "format": fmt,
                "name_hints": list(hints),
                "source": CORPUS_VERSION,
            })
    return tuple(entries)


def corpus_categories(size: int = DEFAULT_CORPUS_SIZE) -> list[dict[str, Any]]:
    rows: dict[str, dict[str, Any]] = {}
    for entry in build_openapi_variable_corpus(size):
        category = str(entry["category"])
        row = rows.setdefault(category, {"category": category, "count": 0, "type_hint": entry["type_hint"], "format": entry["format"]})
        row["count"] += 1
    return list(rows.values())


def corpus_catalog(size: int = DEFAULT_CORPUS_SIZE) -> dict[str, Any]:
    entries = build_openapi_variable_corpus(size)
    return {
        "version": CORPUS_VERSION,
        "size": len(entries),
        "max_size": MAX_CORPUS_SIZE,
        "synthetic": True,
        "reserved_domains": ["example.test", "attacker.example"],
        "categories": corpus_categories(size),
    }


def _relevance(param: dict[str, Any], entry: dict[str, Any]) -> int:
    name = str(param.get("name") or "").lower()
    fmt = str(param.get("format") or (param.get("schema") or {}).get("format") or "").lower()
    typ = str(param.get("type_hint") or (param.get("schema") or {}).get("type") or "").lower()
    category = str(entry.get("category") or "")
    hints = [str(item).lower() for item in entry.get("name_hints") or []]
    score = 1
    if name and any(h in name or name in h for h in hints):
        score += 8
    if fmt and fmt in str(entry.get("format") or "").lower():
        score += 8
    if typ and typ == str(entry.get("type_hint") or "").lower():
        score += 3
    if category in {"sql", "nosql", "ssti", "xss", "command", "traversal", "xml-entity", "oversized", "type-confusion"}:
        score += 2
    if any(token in name for token in ("id", "uuid", "request", "project", "tenant", "account", "order")) and category in {"identifier", "uuid", "tenant", "integer"}:
        score += 7
    return score


def select_corpus_values(param: dict[str, Any], *, budget: int = 0, size: int = DEFAULT_CORPUS_SIZE) -> list[tuple[Any, str]]:
    """Select a stable, parameter-aware slice of the corpus.

    Selection is hash-offset based, so different variables do not all receive
    the first N payloads while repeated scans of the same variable remain
    reproducible.
    """
    try:
        limit = max(0, min(int(budget), 256))
    except (TypeError, ValueError):
        limit = 0
    if limit <= 0:
        return []
    entries = list(build_openapi_variable_corpus(size))
    if not entries:
        return []
    key = f"{param.get('name', '')}:{param.get('location', '')}:{param.get('type_hint', '')}:{param.get('format', '')}"
    ranked = sorted(
        entries,
        key=lambda item: (
            -_relevance(param, item),
            hashlib.sha256(f"{key}:{item['id']}".encode()).hexdigest(),
        ),
    )
    ordered = ranked
    out: list[tuple[Any, str]] = []
    seen: set[str] = set()
    for entry in ordered:
        value = entry.get("value")
        marker = repr(value)
        if marker in seen:
            continue
        seen.add(marker)
        out.append((value, str(entry.get("label") or "library")))
        if len(out) >= limit:
            break
    return out
