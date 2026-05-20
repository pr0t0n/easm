from __future__ import annotations

import re
from typing import Any
from urllib.parse import parse_qs, urlparse


def _clean(value: Any) -> str:
    return " ".join(str(value or "").strip().split())


def _unique_rows(rows: list[dict[str, Any]], key_fields: tuple[str, ...]) -> list[dict[str, Any]]:
    seen: set[tuple[str, ...]] = set()
    out: list[dict[str, Any]] = []
    for row in rows:
        key = tuple(str(row.get(field) or "").strip().lower() for field in key_fields)
        if key in seen:
            continue
        seen.add(key)
        out.append(row)
    return out


def _urls_from_text(text: str) -> list[str]:
    return [
        match.rstrip(".,);]\"'")
        for match in re.findall(r"https?://[^\s'\"<>]+", str(text or ""), flags=re.IGNORECASE)
    ]


def _params_from_url(url: str) -> list[str]:
    try:
        parsed = urlparse(str(url or ""))
        return sorted(parse_qs(parsed.query).keys())
    except Exception:
        return []


def _skill_hint_for_param(param: str) -> tuple[list[str], list[str], str]:
    p = str(param or "").strip().lower()
    if not p:
        return [], [], ""
    if re.search(r"^(id|uid|user_?id|account_?id|order_?id|tenant_?id|org_?id|owner_?id|role|is_?admin)$", p):
        return ["vuln-idor-access-control", "vuln-injection"], ["curl-headers", "sqlmap", "arjun"], "identifier_or_authorization_param"
    if re.search(r"^(q|s|search|query|keyword|name|category|filter|sort)$", p):
        return ["vuln-injection", "vuln-information-disclosure"], ["sqlmap", "dalfox", "arjun"], "search_or_reflection_param"
    if re.search(r"^(url|uri|link|redirect|next|return|callback|webhook|src|image)$", p):
        return ["vuln-ssrf-redirect", "vuln-injection"], ["curl-headers", "interactsh-client"], "url_like_param"
    if re.search(r"^(token|jwt|access_?token|refresh_?token|auth)$", p):
        return ["vuln-auth-bypass", "weak-cryptography"], ["jwt_tool", "curl-headers"], "token_param"
    return ["vuln-injection"], ["arjun", "curl-headers"], "generic_param"


def normalize_recon_signals(
    *,
    target: str,
    tools: list[str],
    findings: list[dict[str, Any]],
    ports: list[int],
    assets: list[str],
    port_evidence: dict[int, dict[str, Any]],
    tech_stack: list[str] | None = None,
) -> list[dict[str, Any]]:
    """Convert noisy tool output/findings into actionable RECON signals.

    The graph/pentester should consume these signals, not raw stdout. Each
    signal says what was observed, where, which tool saw it and which skills
    should be considered next.
    """
    source_tools = [str(tool).strip().lower() for tool in list(tools or []) if str(tool or "").strip()]
    default_tool = source_tools[0] if source_tools else "recon"
    signals: list[dict[str, Any]] = []

    for asset in assets or []:
        host = _clean(asset).lower()
        if host:
            signals.append(
                {
                    "type": "asset",
                    "asset": host,
                    "source_tool": default_tool,
                    "evidence": f"asset discovered: {host}",
                    "confidence": 0.72,
                    "recommended_skills": ["recon-subdomain-enum", "recon-port-service"],
                    "recommended_tools": ["dnsx", "httpx", "naabu"],
                    "next_phase": "asset_discovery",
                }
            )

    for port in ports or []:
        evidence = dict(port_evidence.get(int(port)) or {})
        service = _clean(evidence.get("service"))
        signals.append(
            {
                "type": "service",
                "asset": target,
                "port": int(port),
                "service": service,
                "source_tool": evidence.get("tool") or default_tool,
                "evidence": evidence.get("evidence") or f"open port {port}",
                "confidence": 0.78,
                "recommended_skills": ["recon-port-service", "tech-http-fingerprint"],
                "recommended_tools": ["nmap", "httpx", "whatweb"] if service in {"http", "https", ""} else ["nmap"],
                "next_phase": "asset_discovery",
            }
        )

    text_blobs: list[str] = []
    for finding in findings or []:
        if not isinstance(finding, dict):
            continue
        details = finding.get("details") if isinstance(finding.get("details"), dict) else {}
        tool = _clean(details.get("tool") or finding.get("source_worker") or default_tool).lower()
        asset = _clean(details.get("asset") or details.get("url") or target)
        evidence = _clean(details.get("evidence") or finding.get("title") or "")
        text_blobs.extend([evidence, _clean(details.get("stdout")), _clean(details.get("http_headers_raw"))])

        candidate_urls: list[str] = []
        for key in (
            "url",
            "asset",
            "endpoint",
            "location",
            "discovered_urls",
            "candidate_urls",
            "sensitive_urls",
            "endpoints",
            "sensitive_api_urls",
        ):
            value = details.get(key)
            if isinstance(value, str):
                candidate_urls.extend(_urls_from_text(value) or ([value] if value.startswith(("http://", "https://")) else []))
            elif isinstance(value, list):
                for item in value:
                    candidate_urls.extend(_urls_from_text(str(item)))

        for url in candidate_urls:
            signals.append(
                {
                    "type": "endpoint",
                    "asset": asset or target,
                    "url": url,
                    "source_tool": tool,
                    "evidence": evidence or f"endpoint discovered: {url}",
                    "confidence": 0.76,
                    "recommended_skills": ["recon-web-crawl", "vuln-information-disclosure"],
                    "recommended_tools": ["katana", "curl-headers"],
                    "next_phase": "risk_assessment" if _params_from_url(url) else "asset_discovery",
                }
            )
            for param in _params_from_url(url):
                skills, rec_tools, reason = _skill_hint_for_param(param)
                signals.append(
                    {
                        "type": "parameter",
                        "asset": asset or target,
                        "url": url,
                        "name": param,
                        "source_tool": tool,
                        "evidence": f"parameter {param} discovered in {url}",
                        "confidence": 0.86,
                        "reason": reason,
                        "recommended_skills": skills,
                        "recommended_tools": rec_tools,
                        "next_phase": "risk_assessment",
                    }
                )

        form_inputs = details.get("form_inputs") or []
        if isinstance(form_inputs, list) and form_inputs:
            form_url = _clean(details.get("url") or details.get("asset") or target)
            signals.append(
                {
                    "type": "form",
                    "asset": asset or target,
                    "url": form_url,
                    "method": _clean(details.get("form_method") or "GET").upper(),
                    "source_tool": tool,
                    "evidence": evidence or f"form discovered on {form_url}",
                    "confidence": 0.8,
                    "recommended_skills": ["vuln-auth-bypass", "vuln-injection"],
                    "recommended_tools": ["curl-headers", "sqlmap", "dalfox"],
                    "next_phase": "risk_assessment",
                }
            )
            for item in form_inputs:
                if not isinstance(item, dict):
                    continue
                name = _clean(item.get("name"))
                if not name:
                    continue
                skills, rec_tools, reason = _skill_hint_for_param(name)
                signals.append(
                    {
                        "type": "parameter",
                        "asset": asset or target,
                        "url": form_url,
                        "name": name,
                        "method": _clean(details.get("form_method") or "GET").upper(),
                        "source_tool": tool,
                        "evidence": f"form parameter {name} discovered on {form_url}",
                        "confidence": 0.82,
                        "reason": reason,
                        "recommended_skills": skills,
                        "recommended_tools": rec_tools,
                        "next_phase": "risk_assessment",
                    }
                )

        finding_text = " ".join([finding.get("title", ""), evidence, asset]).lower()
        if any(token in finding_text for token in ["waf", "cloudflare", "akamai", "imperva"]):
            signals.append(
                {
                    "type": "defensive_context",
                    "asset": asset or target,
                    "source_tool": tool,
                    "evidence": evidence or "WAF/CDN signal detected",
                    "confidence": 0.78,
                    "recommended_skills": ["waf-aware-validation", "tech-http-fingerprint"],
                    "recommended_tools": ["wafw00f", "curl-headers", "nuclei"],
                    "next_phase": "risk_assessment",
                }
            )
        if any(token in finding_text for token in ["missing", "header", "hsts", "csp", "x-frame-options"]):
            signals.append(
                {
                    "type": "header",
                    "asset": asset or target,
                    "source_tool": tool,
                    "evidence": evidence or "security header signal detected",
                    "confidence": 0.74,
                    "recommended_skills": ["tech-owasp-header-analysis", "vuln-information-disclosure"],
                    "recommended_tools": ["curl-headers", "nikto", "nuclei"],
                    "next_phase": "risk_assessment",
                }
            )

    for tag in tech_stack or []:
        clean_tag = _clean(tag).lower()
        if clean_tag:
            signals.append(
                {
                    "type": "technology",
                    "asset": target,
                    "technology": clean_tag,
                    "source_tool": default_tool,
                    "evidence": f"technology detected: {clean_tag}",
                    "confidence": 0.72,
                    "recommended_skills": ["tech-http-fingerprint"],
                    "recommended_tools": ["whatweb", "curl-headers", "nuclei"],
                    "next_phase": "risk_assessment",
                }
            )

    return _unique_rows(signals, ("type", "asset", "url", "name", "port", "technology", "source_tool"))
