"""Classificação de CLASSE/FAMÍLIA de vulnerabilidade — fonte única.

Toda vulnerabilidade exibida (página + relatório) deve liderar pela sua
classe. Este módulo classifica QUALQUER finding/vuln (não só os semeados por
aprendizado) numa família canônica, usando título + ferramenta + OWASP + CVE,
e fornece o rótulo de exibição.
"""

from __future__ import annotations

# Rótulos de exibição por família (lidera a vulnerabilidade na UI/relatório).
FAMILY_LABELS: dict[str, str] = {
    "xss": "Cross-Site Scripting (XSS)",
    "sqli": "SQL Injection (SQLi)",
    "rce": "Execução Remota de Código (RCE)",
    "ssrf": "Server-Side Request Forgery (SSRF)",
    "idor": "IDOR — Referência Direta Insegura",
    "broken_access_control": "Controle de Acesso Quebrado",
    "csrf": "Cross-Site Request Forgery (CSRF)",
    "lfri": "Inclusão de Arquivo (LFI/RFI)",
    "path_traversal": "Path Traversal",
    "xxe": "XML External Entity (XXE)",
    "open_redirect": "Open Redirect",
    "cors": "CORS — Configuração Insegura",
    "jwt_oauth": "JWT / OAuth",
    "auth_bypass": "Bypass de Autenticação",
    "graphql_api": "GraphQL / API",
    "info_exposure": "Exposição de Informação",
    "security_headers": "Cabeçalhos de Segurança",
    "subdomain_takeover": "Subdomain Takeover",
    "race_condition": "Race Condition",
    "header_injection": "Header Injection / CRLF",
    "business_logic": "Regras de Negócio",
    "file_upload": "Upload de Arquivo Inseguro",
    "deserialization": "Desserialização Insegura",
    "vulnerable_dependency": "Dependência Vulnerável (CVE)",
    "tls_ssl": "TLS / SSL",
    "secrets": "Segredos Expostos",
    "misconfiguration": "Misconfiguração",
    "dos": "Negação de Serviço (DoS)",
    "outros": "Outros",
}

# Regras por SUBSTRING no texto (título + tipo). Ordem importa — primeira vence.
_KEYWORD_RULES: list[tuple[tuple[str, ...], str]] = [
    (("cross-site scripting", "xss"), "xss"),
    (("sql injection", "sqli", "sql-injection"), "sqli"),
    (("remote code execution", "command injection", "rce", "code execution", "os command"), "rce"),
    (("server-side request forgery", "ssrf"), "ssrf"),
    (("insecure direct object", "idor"), "idor"),
    (("cross-site request forgery", "csrf"), "csrf"),
    (("local file inclusion", "remote file inclusion", "lfi", "rfi", "file inclusion"), "lfri"),
    (("path traversal", "directory traversal", "../"), "path_traversal"),
    (("xml external", "xxe"), "xxe"),
    (("open redirect", "unvalidated redirect"), "open_redirect"),
    (("cors", "cross-origin resource sharing"), "cors"),
    (("jwt", "json web token", "oauth"), "jwt_oauth"),
    (("subdomain takeover", "dangling", "takeover"), "subdomain_takeover"),
    (("graphql", "introspection"), "graphql_api"),
    (("race condition",), "race_condition"),
    (("crlf", "header injection", "response splitting"), "header_injection"),
    (("deserial", "insecure deserialization"), "deserialization"),
    (("file upload", "unrestricted upload", "webshell"), "file_upload"),
    (("business logic", "logic flaw", "price manipulation", "rate limit"), "business_logic"),
    (("authentication bypass", "auth bypass", "default credential", "default password",
      "weak password", "brute force"), "auth_bypass"),
    (("privilege escalation", "improper access control", "broken access",
      "authorization", "missing authorization", "unauthorized access"), "broken_access_control"),
    (("clickjacking", "x-frame-options", "content-security-policy", "csp",
      "hsts", "security header", "missing header"), "security_headers"),
    (("tls", "ssl", "cipher", "certificate", "heartbleed", "poodle", "weak protocol"), "tls_ssl"),
    (("secret", "api key", "apikey", "credential leak", "hardcoded", "token expos",
      "private key", ".env", "gitleaks", "exposed git"), "secrets"),
    (("information disclosure", "information exposure", "sensitive data",
      "info leak", "data exposure", "directory listing", "debug"), "info_exposure"),
    (("denial of service", "uncontrolled resource", "dos"), "dos"),
    (("misconfig", "default config", "exposed panel", "exposed dashboard"), "misconfiguration"),
]

# Pistas por FERRAMENTA quando o texto é ambíguo.
_TOOL_HINTS: dict[str, str] = {
    "sqlmap": "sqli", "dalfox": "xss", "wpscan": "vulnerable_dependency",
    "testssl": "tls_ssl", "sslscan": "tls_ssl",
    "gitleaks": "secrets", "trufflehog": "secrets",
    "subjack": "subdomain_takeover", "jwt_tool": "jwt_oauth",
    "nuclei-xss": "xss", "nuclei-sqli": "sqli", "nuclei-ssrf": "ssrf",
    "nuclei-rce": "rce", "nuclei-lfi": "lfri", "nuclei-xxe": "xxe",
    "nuclei-idor": "idor", "nuclei-redirect": "open_redirect",
    "nuclei-cors": "cors", "nuclei-jwt": "jwt_oauth", "nuclei-auth": "auth_bypass",
    "nuclei-graphql": "graphql_api", "nuclei-exposure": "info_exposure",
    "nuclei-headers": "security_headers", "nuclei-takeover": "subdomain_takeover",
    "nuclei-crlf": "header_injection", "nuclei-csrf": "csrf", "wapiti": "business_logic",
    "trivy": "vulnerable_dependency", "retire": "vulnerable_dependency",
    "nikto": "misconfiguration",
}


def classify_family(
    title: str | None = None,
    tool: str | None = None,
    owasp: str | None = None,
    cve: str | None = None,
    learning_family: str | None = None,
) -> str:
    """Retorna o id de família canônico para uma vulnerabilidade.

    Precedência: família do aprendizado (já classificada) > palavras-chave do
    título/tipo > CVE (dependência vulnerável) > pista de ferramenta > 'outros'.
    """
    if learning_family and learning_family in FAMILY_LABELS:
        return learning_family

    hay = f"{title or ''} {owasp or ''}".lower()
    for needles, fam in _KEYWORD_RULES:
        if any(n in hay for n in needles):
            return fam

    if cve and str(cve).upper().startswith("CVE-"):
        return "vulnerable_dependency"

    t = str(tool or "").lower().strip()
    if t in _TOOL_HINTS:
        return _TOOL_HINTS[t]
    # nuclei genérico com CVE no título já tratado; fallback por prefixo
    for prefix, fam in _TOOL_HINTS.items():
        if t and t.startswith(prefix):
            return fam

    return "outros"


def family_label(family_id: str | None) -> str:
    """Rótulo de exibição da família."""
    return FAMILY_LABELS.get(str(family_id or "outros"), "Outros")
