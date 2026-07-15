"""Quality rules that prevent scanner noise from becoming vulnerabilities."""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse


SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

WEB_ACTIVE_KEYWORDS = (
    "sql injection", "sqli", "xss", "cross-site scripting", "ssrf", "rce",
    "remote code execution", "command injection", "path traversal", "lfi",
    "local file inclusion", "ssti", "xxe", "idor", "bola", "csrf",
    "open redirect", "prototype pollution", "auth bypass",
)

WEB_ACTIVE_PATTERNS = (
    r"\bsql injection\b", r"\bsqli\b", r"\bxss\b", r"\bcross-site scripting\b",
    r"\bssrf\b", r"\brce\b", r"\bremote code execution\b",
    r"\bcommand injection\b", r"\bpath traversal\b", r"\blfi\b",
    r"\blocal file inclusion\b", r"\bssti\b", r"\bxxe\b", r"\bidor\b",
    r"\bbola\b", r"\bcsrf\b", r"\bopen redirect\b",
    r"\bprototype pollution\b", r"\bauth bypass\b",
)

PASSIVE_INVENTORY_TOOLS = {
    "shodan-cli", "theharvester", "h8mail", "nmap-vulscan", "tech_correlator",
}

WAF_HEADER_KEYS = (
    "cf-ray", "cf-cache-status", "cf-request-id", "x-sucuri-id",
    "x-sucuri-cache", "x-iinfo", "x-akamai", "akamai-origin-hop",
    "x-cdn", "x-cache", "x-waf", "x-distil", "x-ddos", "x-f5",
    "x-incap-client-ip", "x-imperva", "x-amz-cf-id", "x-amz-cf-pop",
    "x-edge-location", "x-azure-ref", "server-timing",
)

WAF_TEXT_MARKERS = (
    "cloudflare", "akamai", "imperva", "incapsula", "sucuri", "aws waf",
    "cloudfront", "fastly", "barracuda", "f5 big-ip", "datadome",
    "access denied", "request blocked", "blocked by", "web application firewall",
    "waf", "captcha", "ray id", "attention required", "bot protection",
)


def cap_severity(severity: str, cap: str) -> str:
    sev = str(severity or "info").lower()
    cap_l = str(cap or "critical").lower()
    if SEVERITY_ORDER.get(sev, 0) > SEVERITY_ORDER.get(cap_l, 4):
        return cap_l
    return sev


def is_active_web_vulnerability(title: str, tool: str = "", details: dict[str, Any] | None = None) -> bool:
    if str(tool or "").lower() in PASSIVE_INVENTORY_TOOLS:
        return False
    if str(title or "").lower().startswith(("tecnologia detectada:", "technology detected:")):
        return False
    blob = " ".join([
        str(title or ""),
        str(tool or ""),
        str((details or {}).get("vuln_family") or ""),
        str((details or {}).get("owasp_category") or ""),
        str((details or {}).get("template_id") or ""),
        str((details or {}).get("step") or ""),
    ]).lower()
    return any(re.search(pattern, blob) for pattern in WEB_ACTIVE_PATTERNS)


def has_concrete_endpoint(location: str | None) -> bool:
    raw = str(location or "").strip()
    if not raw:
        return False
    if not raw.startswith(("http://", "https://")):
        return False
    parsed = urlparse(raw)
    path = parsed.path or ""
    return bool(parsed.hostname and (parsed.query or (path and path != "/")))


def location_from_details(details: dict[str, Any], fallback: str | None = None) -> str:
    for key in ("url", "matched_at", "matched-at", "endpoint", "target_url"):
        val = str(details.get(key) or "").strip()
        if val:
            return val
    return str(fallback or details.get("asset") or "").strip()


def response_looks_like_waf(details: dict[str, Any], text: str = "") -> tuple[bool, dict[str, Any]]:
    """Return whether the observed response is from a WAF/CDN edge."""
    headers = _collect_headers(details)
    evidence_text = " ".join([
        text,
        str(details.get("evidence") or ""),
        str(details.get("response") or ""),
        str(details.get("response_body") or ""),
        str(details.get("body") or ""),
        str(details.get("finding_summary") or ""),
        str(details.get("server") or ""),
    ]).lower()

    header_hits: list[str] = []
    for key, value in headers.items():
        k = str(key or "").lower()
        v = str(value or "").lower()
        if any(marker in k for marker in WAF_HEADER_KEYS):
            header_hits.append(k)
        elif any(marker in v for marker in WAF_TEXT_MARKERS):
            header_hits.append(f"{k}: {str(value)[:80]}")

    text_hits = [marker for marker in WAF_TEXT_MARKERS if marker in evidence_text]
    status = str(details.get("http_status") or details.get("status") or details.get("status_code") or "")
    blocking_status = status in {"403", "406", "409", "429", "503"}
    matched = bool(header_hits or text_hits or blocking_status and ("blocked" in evidence_text or "waf" in evidence_text))
    return matched, {
        "header_hits": header_hits[:8],
        "text_hits": text_hits[:8],
        "http_status": status,
    }


def adjudicate_finding(
    *,
    title: str,
    severity: str,
    tool: str,
    details: dict[str, Any],
    target: str = "",
    url: str | None = None,
) -> tuple[str, str, dict[str, Any]]:
    """Apply root-cause FP rules before persistence/reporting."""
    details = dict(details or {})
    current_status = str(details.get("verification_status") or "candidate").lower()
    auto_reason = str(details.get("false_positive_reason") or "")
    if current_status == "refuted" and auto_reason in {
        "edge_control_response_not_application",
        "missing_concrete_endpoint",
    }:
        current_status = "candidate"
    sev = str(severity or "info").lower()
    location = url or location_from_details(details, target)
    active_web = is_active_web_vulnerability(title, tool, details)
    passive_tool = str(tool or "").lower() in PASSIVE_INVENTORY_TOOLS

    waf_seen, waf_meta = response_looks_like_waf(details, text=title)
    if waf_seen:
        details["edge_control_detected"] = True
        details["edge_control_evidence"] = waf_meta

    if active_web and waf_seen:
        details["false_positive_reason"] = "edge_control_response_not_application"
        details["verification_note"] = (
            "A resposta observada veio de WAF/CDN/bloqueio de borda, nao da aplicacao. "
            "Achado de exploracao web nao deve ser reportado como vulnerabilidade da app."
        )
        return "refuted", "info", details

    if active_web and not has_concrete_endpoint(location):
        details["false_positive_reason"] = "missing_concrete_endpoint"
        details["verification_note"] = (
            "Vulnerabilidade web ativa exige URL/endpoint concreto com path ou parametro. "
            "Dominio/apex isolado e apenas inventario, nao prova SQLi/XSS/etc."
        )
        return "refuted", "info", details

    if auto_reason in {"edge_control_response_not_application", "missing_concrete_endpoint"}:
        details.pop("false_positive_reason", None)
        if str(details.get("verification_note") or "").startswith(("A resposta observada veio", "Vulnerabilidade web ativa exige")):
            details.pop("verification_note", None)

    if passive_tool:
        details.setdefault("inventory_only", True)
        current_status = "hypothesis"
        sev = cap_severity(sev, "medium")

    if str(details.get("header_issue") or "").lower() == "missing" and current_status == "candidate" and sev == "info":
        sev = "low"

    if current_status == "hypothesis":
        sev = cap_severity(sev, "medium")
    elif current_status == "candidate":
        sev = cap_severity(sev, "high")

    return current_status, sev, details


def is_actionable_for_vulnerability_inventory(
    *,
    title: str,
    severity: str,
    tool: str,
    details: dict[str, Any],
    verification_status: str,
    url: str | None = None,
) -> bool:
    status = str(verification_status or "").lower()
    sev = str(severity or "").lower()
    if status in {"refuted", "hypothesis"}:
        return False
    if sev not in {"low", "medium", "high", "critical"}:
        return False
    if bool(details.get("inventory_only")):
        return False
    if str(tool or "").lower() in PASSIVE_INVENTORY_TOOLS:
        return False
    if is_active_web_vulnerability(title, tool, details):
        location = url or location_from_details(details)
        if not has_concrete_endpoint(location):
            return False
        waf_seen, _ = response_looks_like_waf(details, text=title)
        if waf_seen:
            return False
    return True


def _collect_headers(details: dict[str, Any]) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    def visit(obj: Any) -> None:
        if isinstance(obj, dict):
            for key, value in obj.items():
                k = str(key or "").lower()
                if k in {"headers", "response_headers", "security_headers", "http_headers"} and isinstance(value, dict):
                    for hk, hv in value.items():
                        headers[str(hk).lower()] = hv
                elif "header" in k and isinstance(value, str):
                    _parse_header_lines(value, headers)
                elif isinstance(value, (dict, list)):
                    visit(value)
        elif isinstance(obj, list):
            for item in obj:
                visit(item)

    visit(details)
    for key in ("evidence", "response", "raw_response", "stdout", "stdout_preview", "stdout_full"):
        _parse_header_lines(str(details.get(key) or ""), headers)
    return headers


def _parse_header_lines(text: str, headers: dict[str, Any]) -> None:
    for line in str(text or "").splitlines():
        if ":" not in line:
            continue
        name, value = line.split(":", 1)
        name = name.strip()
        if not name or len(name) > 80 or " " in name:
            continue
        headers.setdefault(name.lower(), value.strip())
