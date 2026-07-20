"""Classification and redacted analysis for observed sensitive file URLs.

Paths are never guessed here. Only files already observed by discovery enter
this pipeline. Content analysis emits indicator types and fingerprints, never
raw secrets, credentials, private keys or full file bodies.
"""
from __future__ import annotations

import hashlib
import re
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse


EXTENSIONS_BY_CATEGORY: dict[str, set[str]] = {
    "source_code": {
        ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".vue", ".svelte",
        ".php", ".phtml", ".asp", ".aspx", ".jsp", ".jspx", ".cshtml",
        ".py", ".pyc", ".rb", ".java", ".class", ".go", ".rs", ".pl",
        ".cgi", ".sh", ".map",
    },
    "configuration": {
        ".env", ".ini", ".conf", ".config", ".cfg", ".cnf", ".properties",
        ".yaml", ".yml", ".toml", ".xml", ".json", ".json5", ".hcl", ".tf",
        ".tfvars", ".tfstate", ".tfstate.backup", ".dockerfile", ".htaccess",
        ".htpasswd", ".npmrc", ".yarnrc", ".editorconfig", ".gitconfig",
    },
    "api_documentation": {
        ".graphql", ".gql", ".proto", ".wsdl", ".wadl", ".raml", ".har",
        ".http", ".rest", ".postman_collection", ".postman_environment",
        ".swagger", ".openapi", ".md", ".txt",
    },
    "credentials_keys": {
        ".pem", ".key", ".pub", ".crt", ".cer", ".csr", ".p12", ".pfx",
        ".jks", ".keystore", ".kdb", ".ovpn", ".rdp", ".kubeconfig",
        ".credentials",
    },
    "data_database": {
        ".sql", ".db", ".sqlite", ".sqlite3", ".mdb", ".accdb", ".csv",
        ".tsv", ".parquet", ".dump",
    },
    "backup_log_temporary": {
        ".bak", ".backup", ".old", ".orig", ".save", ".swp", ".tmp", ".log",
        ".zip", ".tar.gz",
    },
}

ALL_SENSITIVE_EXTENSIONS = frozenset().union(*EXTENSIONS_BY_CATEGORY.values())
CRITICAL_EXTENSIONS = frozenset({
    ".map", ".env", ".json", ".yaml", ".yml", ".xml", ".config",
    ".properties", ".tfvars", ".tfstate", ".tfstate.backup", ".sql", ".bak",
    ".log", ".har", ".pem", ".key", ".p12", ".jks", ".graphql", ".proto",
    ".htpasswd", ".credentials", ".kubeconfig", ".dump", ".backup",
})

_SORTED_EXTENSIONS = sorted(ALL_SENSITIVE_EXTENSIONS, key=len, reverse=True)
_URL_RE = re.compile(r"https?://[^\s\"'<>\\)]+", re.I)
_INDICATOR_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", re.I)),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")),
    ("cloud_access_key", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
    ("credential_assignment", re.compile(r"(?im)^\s*(?:password|passwd|secret|token|api[_-]?key|access[_-]?key|client[_-]?secret)\s*[:=]\s*[^\s#]{4,}")),
    ("database_connection", re.compile(r"(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis)://[^\s\"']+")),
    ("authorization_header", re.compile(r"(?im)^\s*authorization\s*:\s*(?:bearer|basic)\s+\S+")),
)


def extension_for_url(url: str) -> str:
    path = urlparse(str(url or "")).path.lower().rstrip("/")
    filename = path.rsplit("/", 1)[-1]
    for extension in _SORTED_EXTENSIONS:
        if filename.endswith(extension):
            return extension
    return ""


def classify_sensitive_file_url(url: str) -> dict[str, Any]:
    extension = extension_for_url(url)
    if not extension:
        return {"matched": False, "extension": "", "category": "", "priority": 0}
    category = next(
        (name for name, extensions in EXTENSIONS_BY_CATEGORY.items() if extension in extensions),
        "unknown",
    )
    priority = 95 if extension in CRITICAL_EXTENSIONS else (80 if category in {"credentials_keys", "data_database", "backup_log_temporary"} else 60)
    return {
        "matched": True,
        "extension": extension,
        "category": category,
        "priority": priority,
        "analysis_mode": "observed_read_only_redacted",
        "content_limit_bytes": 131072,
    }


def analyze_sensitive_file_content(content: str | bytes, *, max_bytes: int = 131072) -> dict[str, Any]:
    raw_bytes = content if isinstance(content, bytes) else str(content or "").encode("utf-8", errors="replace")
    sample_bytes = raw_bytes[:max_bytes]
    text = sample_bytes.decode("utf-8", errors="replace")
    indicators: list[dict[str, Any]] = []
    for indicator_type, pattern in _INDICATOR_PATTERNS:
        for match in list(pattern.finditer(text))[:20]:
            value = match.group(0)
            indicators.append({
                "type": indicator_type,
                "line": text.count("\n", 0, match.start()) + 1,
                "fingerprint": hashlib.sha256(value.encode("utf-8", errors="ignore")).hexdigest()[:16],
            })
    endpoints = sorted({_redacted_endpoint(url) for url in _URL_RE.findall(text)})[:200]
    return {
        "bytes_analyzed": len(sample_bytes),
        "truncated": len(raw_bytes) > max_bytes,
        "indicator_count": len(indicators),
        "indicators": indicators[:100],
        "endpoint_count": len(endpoints),
        "endpoints": endpoints,
        "content_retained": False,
    }


def _redacted_endpoint(url: str) -> str:
    parsed = urlparse(str(url or ""))
    query_names = sorted({name for name, _ in parse_qsl(parsed.query, keep_blank_values=True)})
    redacted_query = urlencode([(name, "") for name in query_names])
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, redacted_query, ""))
