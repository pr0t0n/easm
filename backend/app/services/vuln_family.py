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
    # ── Fase 1: lacunas web/API in-scope (ingestão Anthropic-Cybersecurity-Skills)
    "nosql_injection": "NoSQL Injection",
    "websocket": "WebSocket — Auth Bypass / Injeção",
    "mass_assignment": "Mass Assignment (API)",
    "bola_bfla": "BOLA / BFLA — Autorização de Objeto/Função (API)",
    "excessive_data_exposure": "Exposição Excessiva de Dados (API)",
    "prototype_pollution": "Prototype Pollution (JS)",
    "type_juggling": "Type Juggling (PHP)",
    "outros": "Outros",
}

# Regras por SUBSTRING no texto (título + tipo). Ordem importa — primeira vence.
_KEYWORD_RULES: list[tuple[tuple[str, ...], str]] = [
    (("nosql injection", "nosql", "mongodb injection", "$where", "$ne"), "nosql_injection"),
    (("websocket", "ws://", "wss://"), "websocket"),
    (("mass assignment", "autobind", "over-posting"), "mass_assignment"),
    (("bola", "bfla", "broken object level", "broken function level", "object level authorization"), "bola_bfla"),
    (("excessive data exposure", "over-fetch", "excessive data"), "excessive_data_exposure"),
    (("prototype pollution", "__proto__", "constructor.prototype"), "prototype_pollution"),
    (("type juggling", "loose comparison", "php type"), "type_juggling"),
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
      "private key", ".env", "gitleaks", "exposed git",
      # PT + client-side: exposição de dados sensíveis / token em storage
      "exposicao_dados", "exposicao de dados", "dados sensiveis", "dados_sensiveis",
      "localstorage", "sessionstorage", "auth_token", "jwt", "id_token", "access_token"), "secrets"),
    (("information disclosure", "information exposure", "sensitive data",
      "info leak", "data exposure", "directory listing", "debug"), "info_exposure"),
    # "dos" CRU removido — casava substring dentro de "da-DOS" (dados). Usa termos
    # inequívocos de negação de serviço.
    (("denial of service", "uncontrolled resource", "resource exhaustion",
      "ddos", "slowloris", "amplification", "dos attack"), "dos"),
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
    "nuclei-js-secrets": "secrets", "nuclei-js-analysis": "info_exposure",
    "nuclei-misconfiguration": "misconfiguration", "nuclei-file-upload": "file_upload",
    "nuclei-swagger": "info_exposure",
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


# Item 36 — Descrição técnica por família: O QUE é, COMO o ataque funciona e o
# IMPACTO para o ambiente. Usada quando o finding não traz descrição própria
# (antes mostrava "Sem descrição técnica registrada para este achado").
FAMILY_DESCRIPTIONS: dict[str, str] = {
    "xss": "Cross-Site Scripting: a aplicação reflete/armazena entrada do usuário sem sanitizar, permitindo injetar JavaScript que executa no navegador da vítima. Ataque: o atacante insere um payload (ex.: <script>) num parâmetro/campo; quando renderizado, roda no contexto da vítima. Impacto: roubo de sessão/cookies, ações em nome da vítima, desfiguração e phishing.",
    "sqli": "SQL Injection: entrada do usuário é concatenada na query SQL sem parametrização, permitindo alterar a lógica da consulta. Ataque: o atacante injeta operadores/comandos SQL num parâmetro. Impacto: leitura/alteração não autorizada do banco, bypass de autenticação e, em casos graves, execução de comandos no SGBD. (Aqui só MAPEAMOS estrutura — sem extração de dados.)",
    "rce": "Execução Remota de Código: a aplicação executa entrada controlada pelo atacante como código/comando do sistema. Ataque: injeção em função de execução, deserialização ou template. Impacto: controle total do servidor — o mais crítico.",
    "ssrf": "Server-Side Request Forgery: o servidor faz requisições a URLs fornecidas pelo usuário sem validar o destino. Ataque: o atacante força o servidor a acessar recursos internos (metadata cloud, serviços internos). Impacto: acesso a rede interna, vazamento de credenciais cloud, pivot para serviços não expostos.",
    "idor": "IDOR (Referência Direta Insegura a Objeto): o app expõe identificadores de objeto (ex.: /api/user/123) e não valida se o usuário autenticado tem permissão sobre aquele objeto. Ataque: o atacante troca o ID e acessa o objeto de outro usuário. Impacto: vazamento/alteração de dados de terceiros, quebra de confidencialidade e integridade.",
    "broken_access_control": "Controle de Acesso Quebrado: a aplicação não aplica corretamente restrições de autorização entre usuários/papéis. Ataque: acessar funções/recursos para os quais o usuário não tem permissão (forçar URL, trocar papel, parâmetro). Impacto: escalonamento de privilégio, acesso a dados/funções administrativas.",
    "bola_bfla": "BOLA/BFLA (Autorização quebrada de Objeto/Função em API): a API não verifica se o usuário pode acessar AQUELE objeto (BOLA) ou AQUELA função (BFLA). Ataque: usuário A requisita objeto/endpoint de B e a API responde sem checar dono/papel — provado por resposta diferencial entre identidades. Impacto: acesso a dados/operações de outros usuários — falha #1 de APIs (OWASP API1/API5).",
    "csrf": "Cross-Site Request Forgery: a app aceita ações sensíveis sem token anti-CSRF, então uma página maliciosa pode forçar o navegador autenticado da vítima a executá-las. Impacto: mudança de estado em nome da vítima (trocar e-mail/senha, transferências).",
    "jwt_oauth": "Falha em JWT/OAuth: validação fraca de token (algoritmo none, assinatura não verificada, segredo fraco, claims não checados). Ataque: forjar/alterar o token para assumir outra identidade. Impacto: bypass de autenticação e escalonamento.",
    "auth_bypass": "Bypass de Autenticação: é possível acessar recursos protegidos sem credenciais válidas (lógica falha, default creds, endpoint desprotegido). Impacto: acesso não autorizado direto à aplicação.",
    "cors": "CORS mal configurado: a app reflete a origem ou usa wildcard com credenciais, permitindo que sites maliciosos leiam respostas autenticadas. Impacto: vazamento de dados sensíveis cross-origin.",
    "open_redirect": "Open Redirect: a app redireciona para uma URL controlada pelo usuário sem validar. Ataque: link confiável que leva a site malicioso. Impacto: phishing e roubo de token em fluxos OAuth.",
    "xxe": "XML External Entity: o parser XML processa entidades externas. Ataque: documento XML que referencia arquivos locais ou URLs internas. Impacto: leitura de arquivos do servidor, SSRF e DoS.",
    "path_traversal": "Path Traversal: entrada usada em caminho de arquivo sem sanitização permite sair do diretório esperado (../). Impacto: leitura/escrita de arquivos arbitrários do servidor.",
    "lfri": "Inclusão de Arquivo (LFI/RFI): a app inclui arquivos cujo caminho vem do usuário. Impacto: leitura de arquivos sensíveis, e (RFI) execução de código remoto.",
    "ssti": "Server-Side Template Injection: entrada do usuário é avaliada pelo motor de templates. Impacto: execução de código no servidor (frequentemente RCE).",
    "deserialization": "Desserialização Insegura: a app desserializa dados não confiáveis. Ataque: objeto serializado malicioso. Impacto: execução de código remoto e adulteração de estado.",
    "graphql_api": "Falha em GraphQL/API: introspecção exposta, ausência de rate-limit/depth-limit, ou autorização por campo ausente. Impacto: enumeração do schema, abuso de queries e acesso indevido a dados.",
    "mass_assignment": "Mass Assignment: a API vincula campos da requisição direto ao objeto sem allowlist. Ataque: enviar campos extras (ex.: role=admin). Impacto: escalonamento de privilégio/alteração indevida.",
    "excessive_data_exposure": "Exposição Excessiva de Dados (API): o endpoint retorna mais campos do que o cliente precisa, confiando no front para filtrar. Impacto: vazamento de dados sensíveis na resposta.",
    "nosql_injection": "NoSQL Injection: operadores NoSQL ($ne, $gt, $where) injetados em consultas. Impacto: bypass de autenticação e leitura indevida de documentos.",
    "header_injection": "Header Injection/CRLF: entrada injeta CR/LF em cabeçalhos de resposta. Impacto: response splitting, envenenamento de cache, XSS via header.",
    "race_condition": "Race Condition: ausência de controle de concorrência permite executar uma operação múltiplas vezes antes da validação. Impacto: duplicação de saldo/cupom, bypass de limites.",
    "info_exposure": "Exposição de Informação: a app revela dados internos (stack trace, versões, caminhos, e-mails, tokens). Impacto: facilita ataques direcionados; tokens/segredos expostos permitem acesso direto.",
    "secrets": "Segredos Expostos: credenciais/chaves/tokens acessíveis (em JS, localStorage, repositórios, respostas). Ataque: usar o segredo direto. Impacto: acesso não autorizado a contas/APIs/infra.",
    "business_logic": "Falha de Regra de Negócio: o fluxo da aplicação pode ser abusado de forma não prevista (pular etapas, valores negativos, reuso de token). Impacto: fraude, acesso indevido, perda financeira — depende do contexto do negócio.",
    "subdomain_takeover": "Subdomain Takeover: subdomínio aponta (CNAME) para serviço de terceiro não reclamado. Ataque: reivindicar o serviço e servir conteúdo no domínio da vítima. Impacto: phishing com domínio legítimo, roubo de cookies.",
    "security_headers": "Cabeçalhos de Segurança ausentes (CSP, HSTS, X-Frame-Options...): não exploráveis sozinhos, mas ampliam o risco de XSS, clickjacking e downgrade de transporte. Impacto: enfraquecem as defesas em profundidade.",
    "tls_ssl": "Falha de TLS/SSL: protocolo/cifra fraca, certificado inválido ou expirado. Impacto: interceptação/adulteração do tráfego (MITM).",
    "vulnerable_dependency": "Dependência Vulnerável (CVE): componente em versão com vulnerabilidade pública conhecida. Impacto: varia conforme o CVE — desde DoS até RCE; priorizar por EPSS/explorabilidade.",
    "file_upload": "Upload de Arquivo Inseguro: a app aceita upload sem validar tipo/conteúdo/caminho. Ataque: subir webshell ou arquivo malicioso. Impacto: execução de código, sobrescrita de arquivos.",
    "misconfiguration": "Misconfiguração de Segurança: configuração insegura (debug ligado, diretório listável, serviço default exposto). Impacto: vazamento de informação e superfície de ataque ampliada.",
    "dos": "Negação de Serviço: condição que exaure recursos e derruba o serviço. (NÃO é testada/explorada por esta plataforma — apenas reportada quando inferida de configuração.)",
    "websocket": "Falha em WebSocket: ausência de autenticação/validação de origem no handshake ou injeção no canal. Impacto: acesso não autorizado ao canal e abuso de mensagens.",
    "prototype_pollution": "Prototype Pollution (JS): entrada altera o protótipo de objetos (__proto__). Impacto: bypass de lógica, DoS e, encadeado, RCE no Node.",
    "type_juggling": "Type Juggling (PHP): comparações soltas (==) permitem bypass de checagens (ex.: senha/hash). Impacto: bypass de autenticação.",
}


def family_description(family_id: str | None) -> str:
    """Descrição técnica da família (o quê / como ataca / impacto). Item 36."""
    return FAMILY_DESCRIPTIONS.get(str(family_id or "outros"), "")


# Item 38 — Mapa offline CURADO de CVE→produto (alta confiança), p/ quando o
# NVD não está acessível. Só entradas confiáveis — NUNCA inventar produto.
# Em produção, o cve_enrichment_service (NVD) popula details['product'] e este
# mapa é o fallback. Estender conforme aprendido.
_CVE_PRODUCT: dict[str, str] = {
    "CVE-2024-5458": "PHP",   # filter_var FILTER_VALIDATE_URL bypass (PHP)
}


def cve_product_label(cve_id: str | None, details: dict | None = None) -> str:
    """Produto/componente afetado por um CVE, p/ compor título descritivo.
    Prioridade: details enriquecido (NVD/shodan) → mapa curado → vazio
    (NÃO inventa). Item 38."""
    details = details or {}
    cid = str(cve_id or "").strip().upper()
    for k in ("product", "cve_product", "affected_product", "vendor_product", "service"):
        v = str(details.get(k) or "").strip()
        if v:
            return v
    return _CVE_PRODUCT.get(cid, "")


def descriptive_cve_title(cve_id: str | None, details: dict | None = None) -> str:
    """Título descritivo de CVE: '<produto> — CVE-XXXX' quando o produto é
    conhecido; senão só o CVE (honesto, sem inventar). Item 38."""
    cid = str(cve_id or "").strip().upper()
    if not cid.startswith("CVE-"):
        return str(cve_id or "")
    prod = cve_product_label(cid, details)
    return f"{prod} — {cid}" if prod else cid


# Prefixos de status que poluem o TÍTULO do achado (o status já tem coluna
# própria — coluna evidência / verification_status). Item 35.
import re as _re_title


def clean_finding_title(title: str | None) -> str:
    """Remove prefixos de status/ferramenta do título ([CONFIRMADA], [ZAP],
    [WAF-BYPASS], [HIPOTESE]...). O status vai na coluna de evidência. Item 35."""
    t = str(title or "").strip()
    # remove um ou mais prefixos entre colchetes no início
    while True:
        m = _re_title.match(r"^\s*\[[^\]]{1,40}\]\s*", t)
        if not m:
            break
        t = t[m.end():]
    return t.strip() or str(title or "").strip()
