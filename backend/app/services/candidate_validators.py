"""Candidate validation — classificação passiva/ativa e catálogo de validators.

Plano: docs/PLANO_CANDIDATE_VALIDATION_2026-11-07.md (Fases 1-2).

Princípio: achado PASSIVO (porta aberta, header ausente, fingerprint, OSINT
corroborado) confirma via reprodução da mesma probe (re-probe concordante) —
não exige semântica de exploit. Achado ATIVO (injection, auth bypass, rce...)
mantém o contrato completo (proof pack, baseline_vs_exploit, negative
control). Essa fronteira é regra dura.
"""
from __future__ import annotations

import re
from typing import Any


# Famílias passivas validáveis automaticamente. Cada entrada define o
# validator que materializa a re-probe e os sinais essenciais comparados.
FAMILY_VALIDATORS: dict[str, dict[str, Any]] = {
    "exposed_service": {
        "validator": "passive_reprobe",
        "expected_signals": {"positive": "mesma porta aberta com serviço concordante", "negative": "porta fechada/filtrada na re-probe"},
        "reprobe_tool": "nmap",
        "reprobe_profile": "nmap",
    },
    "security_headers": {
        "validator": "nuclei-headers",
        "expected_signals": {"positive": "header ainda ausente no template nuclei", "negative": "header presente (corrigido/volátil)"},
        "reprobe_tool": "nuclei-headers",
        "reprobe_profile": "nuclei_headers",
    },
    "tech_fingerprint": {
        "validator": "passive_reprobe",
        "expected_signals": {"positive": "mesma tecnologia/banner na re-probe", "negative": "fingerprint divergente"},
        "reprobe_tool": "whatweb",
        "reprobe_profile": "whatweb",
    },
    "osint_exposure": {
        "validator": "osint_corroboration",
        "expected_signals": {"positive": "segunda fonte independente confirma", "negative": "fonte única sem corroboração"},
        "reprobe_tool": "",
        "reprobe_profile": "",
    },
    "exposed_files": {
        "validator": "nuclei-exposure",
        "expected_signals": {"positive": "arquivo/segredo ainda exposto", "negative": "não mais exposto"},
        "reprobe_tool": "nuclei-exposure",
        "reprobe_profile": "nuclei_exposure",
    },
}

# Tools cujos achados são observações passivas por natureza.
_PASSIVE_TOOLS = {
    "nmap", "naabu", "masscan", "shodan-cli", "whatweb", "httpx",
    "wafw00f", "theharvester", "h8mail", "curl-headers", "nuclei-headers",
}

_PORT_TITLE_RE = re.compile(r"\b(porta|port)\b", re.IGNORECASE)
_HEADER_TITLE_PREFIXES = (
    "header de seguranca", "header de segurança", "missing security header",
    "http missing security headers",
)
_FINGERPRINT_TITLE_PREFIXES = (
    "tecnologia detectada", "technology detected", "tecnologias detectadas",
    "stack tecnológico", "cdn/waf detectado", "waf detectado", "host http ativo",
    "informação de servidor exposta", "informacao de servidor exposta",
)
_OSINT_TITLE_PREFIXES = (
    "e-mail", "email", "portas expostas (shodan)", "informação de servidor exposta em cabeçalhos http (shodan)",
)


def classify_candidate_family(title: str, tool: str, details: dict[str, Any] | None = None) -> str | None:
    """Mapeia um finding para a família passiva validável, ou None se ativo/desconhecido.

    Não usa classify_family (que resolve famílias de vulnerabilidade) — aqui o
    eixo é COMO validar, e a decisão vem de tool + padrões de título + campos
    estruturados do parser.
    """
    details = dict(details or {})
    tool_l = str(tool or "").lower().strip()
    title_l = str(title or "").lower().strip()

    if str(details.get("header_name") or "").strip() or title_l.startswith(_HEADER_TITLE_PREFIXES):
        return "security_headers"
    if _PORT_TITLE_RE.search(title_l) or (
        tool_l in {"nmap", "naabu", "masscan", "shodan-cli"}
        and re.search(r"\b\d{1,5}/tcp\b", f"{title_l} {str(details.get('evidence') or '').lower()}")
    ):
        if tool_l in {"nmap", "naabu", "masscan", "shodan-cli"}:
            return "exposed_service"
    if tool_l in {"theharvester", "h8mail"} or title_l.startswith(_OSINT_TITLE_PREFIXES):
        return "osint_exposure"
    if tool_l in {"whatweb", "httpx", "wafw00f", "tech_correlator"} or title_l.startswith(_FINGERPRINT_TITLE_PREFIXES):
        return "tech_fingerprint"
    if tool_l in {"gitleaks", "trufflehog", "nuclei-exposure"}:
        return "exposed_files"
    return None


def is_passive_observation(title: str, tool: str, details: dict[str, Any] | None = None) -> bool:
    """True se o finding é uma observação passiva validável por re-probe.

    Fronteira dura: títulos/famílias de exploit ativo (injection, bypass, rce)
    nunca entram aqui — classify_candidate_family só casa padrões passivos.
    """
    if classify_candidate_family(title, tool, details) is not None:
        return True
    # Fallback conservador: tool passiva + título sem qualquer sinal ativo.
    tool_l = str(tool or "").lower().strip()
    title_l = str(title or "").lower()
    if tool_l not in _PASSIVE_TOOLS:
        return False
    from app.services.finding_quality_gate import is_active_web_vulnerability
    return not is_active_web_vulnerability(title, tool, details)


# ─────────────────────────────────────────────────────────────
# Re-probe — extração do sinal essencial para comparação
# ─────────────────────────────────────────────────────────────

def needs_nc_probe(finding_title: str, details: dict[str, Any] | None = None) -> bool:
    """True se a evidência sugere tcpwrapped/inconcluso — o re-probe nmap
    reproduz o mesmo resultado vago; o nc -z é o teste mínimo que refuta."""
    text = f"{finding_title} {str((details or {}).get('evidence') or '')} {str((details or {}).get('version') or '')}".lower()
    return "tcpwrapped" in text or ("inconclusiv" in text and "porta" in text)


def extract_passive_signal(finding_title: str, tool: str, details: dict[str, Any] | None = None) -> dict[str, Any]:
    """Sinal essencial que a re-probe precisa reproduzir para confirmar."""
    details = dict(details or {})
    family = classify_candidate_family(finding_title, tool, details) or ""
    signal: dict[str, Any] = {"family": family}

    if family == "exposed_service":
        text = f"{finding_title} {details.get('evidence') or ''}"
        match = re.search(r"\b(\d{1,5})/tcp\b", str(text)) or re.search(r":(\d{1,5})\b", str(text))
        if match:
            signal["port"] = int(match.group(1))
        svc = re.search(r"\b(open|aberta?)\s+([a-z0-9\-_/\.]+)", str(text).lower())
        if svc:
            signal["service_hint"] = svc.group(2)
    elif family == "security_headers":
        signal["header_name"] = str(details.get("header_name") or "").strip().lower()
    elif family == "tech_fingerprint":
        signal["fingerprint_terms"] = [
            term for term in re.findall(r"[a-z0-9][a-z0-9\.\-]{2,}", str(finding_title).lower())
            if term not in {"detectada", "detectado", "tecnologia", "tecnologias", "stack", "http", "https"}
        ][:6]
    elif family == "exposed_files":
        signal["path_hint"] = str(details.get("matched_at") or details.get("url") or "").strip().lower()
    return signal


def signals_match(original: dict[str, Any], reprobe_stdout: str) -> tuple[bool, str]:
    """Compara o sinal extraído do finding com a stdout da re-probe."""
    stdout_l = str(reprobe_stdout or "").lower()
    family = str(original.get("family") or "")

    if family == "exposed_service":
        port = original.get("port")
        if port:
            # Marcadores do nc_probe (bash /dev/tcp): sem ambiguidade de parse
            if "easm_tcp_open" in stdout_l:
                return True, f"port {port} open (tcp connect succeeded)"
            if "easm_tcp_refused" in stdout_l:
                return False, f"port {port} refused on tcp probe"
            if "easm_tcp_timeout" in stdout_l:
                return False, f"port {port} probe timed out — not negative proof"
            # nc -z clássico (caso o binário exista)
            if re.search(rf"\b{int(port)}\b[^\n]*(succeeded|open)", stdout_l):
                return True, f"port {port} open (nc connect succeeded)"
            if re.search(rf"\b{int(port)}\b[^\n]*(refused|failed)", stdout_l):
                return False, f"port {port} refused on nc probe"
            # timeout NÃO é prova negativa (rede lenta/filtrada ≠ fechada)
            if re.search(rf"\b{int(port)}/tcp\s+open\b", stdout_l) or re.search(rf":{int(port)}\b", stdout_l):
                return True, f"port {port} still open"
            if re.search(rf"\b{int(port)}/tcp\s+(closed|filtered)", stdout_l):
                return False, f"port {port} closed/filtered on re-probe"
            return False, f"port {port} not observed on re-probe"
        return False, "no port signal to compare"
    if family == "security_headers":
        header = str(original.get("header_name") or "").strip().lower()
        if header:
            present = re.search(rf"(?im)^\s*{re.escape(header)}\s*:", stdout_l) is not None
            # re-probe do tipo nuclei-headers: template ausente → não casou
            if not present and "missing" in stdout_l or not present:
                return True, f"header {header} still missing"
            return False, f"header {header} now present"
        return False, "no header signal"
    if family == "tech_fingerprint":
        terms = [t for t in (original.get("fingerprint_terms") or []) if len(t) > 3]
        if terms:
            hits = sum(1 for t in terms if t in stdout_l)
            return (hits >= max(1, len(terms) // 2)), f"{hits}/{len(terms)} fingerprint terms matched"
        return False, "no fingerprint terms"
    if family == "exposed_files":
        hint = str(original.get("path_hint") or "")
        if hint:
            return (hint in stdout_l), f"path {hint} in reprobe output" if hint in stdout_l else f"path {hint} absent"
        return False, "no path hint"
    return False, "unknown family"
