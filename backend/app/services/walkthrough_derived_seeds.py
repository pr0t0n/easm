"""Generic, transferable seeds derived from analyzing pentest walkthroughs.

The seeds in this file describe TECHNIQUE PATTERNS that an autonomous agent
can apply against ANY vulnerable web application — not against one specific
training app. We learn from real walkthroughs (e.g. OWASP Juice Shop) by
extracting the underlying class of vulnerability + the recipe to validate it,
then strip every app-specific detail (no `/ftp`, no `score-board`, no
`sanitize-html` version pin, no challenge numbers).

Each seed follows the same shape as `vulnerability_learning_catalog._seed()`
so they merge naturally into `all_curated_seeds()`.

Why a separate file?
  - Walkthroughs are a rich source of battle-tested probes; we want to
    absorb them without polluting the OWASP/CWE-organized base catalog.
  - When we add a new walkthrough source in the future, dropping seeds
    here makes provenance explicit.
"""
from __future__ import annotations

from typing import Any

from app.services.vulnerability_learning_catalog import _seed


# ─────────────────────────────────────────────────────────────────────────────
# WALKTHROUGH-DERIVED PATTERNS
# Every entry must be applicable to ANY target, not a specific training app.
# ─────────────────────────────────────────────────────────────────────────────

WALKTHROUGH_DERIVED_SEEDS: list[dict[str, Any]] = [
    # ── Information disclosure via static client artifacts ───────────────────
    _seed(
        "info-disclosure-client-artifacts",
        "Hidden routes / secrets exposed in HTML comments or JS bundles",
        "Information Disclosure",
        ["html comment leak", "js bundle leak", "hidden route", "leaked path"],
        ["InformationExposure"],
        ["P03", "P05", "P22"],
        ["recon-web-crawl", "vuln-information-disclosure", "code-secrets-sast"],
        ["katana", "hakrawler", "gau", "curl-headers", "trufflehog"],
        [
            "comentário HTML deixado em produção referencia rota privada",
            "string literal em JS bundle aponta para path admin / debug / staging",
            "robots.txt ou sitemap.xml lista endpoint que não é navegável",
        ],
        [
            "baixar HTML inicial e procurar comentários <!-- ... -->",
            "extrair JS/source-map e grep por strings de rota e tokens",
            "comparar URLs via gau/wayback com rotas atuais para detectar drift",
            "registrar a rota descoberta sem acessar conteúdo sensível além do necessário",
        ],
        "Atacante descobre painel admin, endpoints internos ou flags ocultas sem autenticação.",
        "Remover comentários de produção, minificar+ofuscar JS, mover rotas privadas para domínio com auth obrigatório, scanear builds com gitleaks/trufflehog antes do deploy.",
    ),

    # ── Verbose SQL error disclosure ─────────────────────────────────────────
    _seed(
        "sqli-error-disclosure",
        "Verbose SQL error reveals database engine and table names",
        "SQL Injection — Error-based recon",
        ["sql error", "stack trace", "verbose error", "dbms fingerprint"],
        ["ErrorBasedSQLi"],
        ["P11", "P12"],
        ["vuln-injection", "vuln-information-disclosure"],
        ["sqlmap", "curl-headers", "nuclei"],
        [
            "single quote em parâmetro retorna stack trace identificando o ORM",
            "mensagem inclui nome de tabela/coluna + dialeto",
            "diferença de status (500 vs 200) ao injetar caractere especial",
        ],
        [
            "enviar quote único e backtick em cada parâmetro descoberto pelo crawler",
            "comparar response normal vs anômalo (tamanho, status, mensagem)",
            "registrar trecho do erro sem extrair dados além do dialeto",
        ],
        "Erro verboso entrega o esquema do banco e indica os pontos de injeção mais prováveis.",
        "Capturar exceções no servidor, retornar mensagem genérica ao cliente, logar stack apenas server-side com PII redatada.",
    ),

    # ── Auth bypass via tautological/LIKE/regex SQLi ────────────────────────
    _seed(
        "sqli-login-bypass-tautology",
        "Authentication bypass via tautological SQL injection in login form",
        "SQL Injection — Auth bypass",
        ["login bypass", "or 1=1", "auth bypass sqli", "like operator"],
        ["LoginBypassSQLi"],
        ["P12", "P14"],
        ["vuln-injection", "vuln-auth-bypass"],
        ["sqlmap", "burp-cli", "ffuf"],
        [
            "campo de email/usuário aceita aspas sem escape",
            "payload tautológico autentica como o primeiro registro retornado",
            "operador LIKE / regex em payload roteia para conta-alvo específica",
        ],
        [
            "no campo email enviar quote único — observar erro vs login",
            "tentar payload tautológico minimal (`' OR 1=1--`) e medir status 200 + token",
            "validar com payload incorreto (`' OR 1=2--`) que NÃO há fallback genérico",
            "registrar request/response sem persistir credenciais",
        ],
        "Atacante autentica-se como qualquer usuário (incluindo admin) sem conhecer senha.",
        "Substituir queries por bind parameters, hash com bcrypt/argon2 + salt, separar accounts admin de e-commerce, MFA obrigatório, rate-limit por email/IP.",
    ),

    # ── Reflected XSS in query/search parameter ──────────────────────────────
    _seed(
        "xss-reflected-query-param",
        "Reflected XSS via unsanitized search/query parameter",
        "Cross-Site Scripting — Reflected",
        ["reflected xss", "search xss", "query string xss"],
        ["ReflectedXSS"],
        ["P12", "P16"],
        ["vuln-injection", "vuln-api-graphql"],
        ["dalfox", "nuclei", "wapiti", "katana", "arjun"],
        [
            "parâmetro de busca/filtro reflete valor em HTML sem escape",
            "Content-Type text/html + body com atributo controlado pelo input",
            "DOM mostra valor injetado dentro de tag/atributo",
        ],
        [
            "fuzzear parâmetros descobertos com payload de detecção (não-persistente)",
            "validar reflexão com curl simples antes de qualquer payload ativo",
            "documentar contexto da reflexão (atributo, tag, JS literal)",
        ],
        "Atacante executa JS no contexto da vítima, roubando sessão/JWT.",
        "Output encoding por contexto (HTML/attr/JS), CSP estrita, framework com auto-escape, sanitização server-side em qualquer entrada renderizada.",
    ),

    # ── Stored XSS via direct API bypassing client validation ───────────────
    _seed(
        "xss-stored-client-validation-bypass",
        "Stored XSS via direct API request bypassing client-side validation",
        "Cross-Site Scripting — Stored / Persisted",
        ["stored xss", "persistent xss", "client validation bypass"],
        ["StoredXSS"],
        ["P12", "P16"],
        ["vuln-injection", "vuln-api-graphql"],
        ["dalfox", "burp-cli", "nuclei", "arjun"],
        [
            "campo aceita payload via POST direto ao endpoint (filtro só no JS do front)",
            "PUT/PATCH em recurso compartilhado aceita HTML em campo de descrição",
            "biblioteca de sanitização desatualizada deixa tags específicas passarem",
        ],
        [
            "interceptar requisição de criação/edição com proxy HTTP",
            "remover validação client-side e reenviar payload pequeno",
            "verificar persistência em GET subsequente",
        ],
        "Payload persistido dispara para qualquer visitante futuro — comprometimento em massa.",
        "Validação server-side obrigatória, sanitização robusta atualizada, CSP, escapar ao armazenar e ao renderizar, autenticação em mutações.",
    ),

    # ── UNION-based extraction ──────────────────────────────────────────────
    _seed(
        "sqli-union-extraction",
        "UNION-based SQL injection to extract authoritative data",
        "SQL Injection — UNION extraction",
        ["union select", "credential dump", "sqli union"],
        ["UNIONSQLi"],
        ["P12"],
        ["vuln-injection"],
        ["sqlmap", "burp-cli"],
        [
            "endpoint de busca/listagem reflete colunas no body",
            "ORDER BY n+1 dispara erro indicando número de colunas",
            "UNION SELECT NULL,NULL,... passa sem filtro",
        ],
        [
            "descobrir número de colunas via ORDER BY iterativo",
            "construir UNION SELECT mínimo para confirmar exfiltração viável",
            "registrar evidência sem extrair dados sensíveis fora do escopo",
        ],
        "Atacante extrai credenciais e PII de toda base.",
        "Queries parametrizadas, hashing forte, separar leitor de escritor no DB, WAF com detecção de UNION em produção.",
    ),

    # ── Reversible password hashing (MD5/SHA1 sem salt) ─────────────────────
    _seed(
        "weak-hash-reversible",
        "Reversible password hashes (MD5/SHA1 without salt) via rainbow tables",
        "Broken Cryptography — reversible hash",
        ["md5", "rainbow table", "broken hash", "no salt"],
        ["WeakHash"],
        ["P11", "P14", "P22"],
        ["vuln-auth-bypass", "weak-cryptography"],
        ["nuclei", "trufflehog", "retire", "hashcat"],
        [
            "32 hex chars (MD5) ou 40 hex chars (SHA1) armazenados sem salt",
            "fingerprint do framework com default de hash inseguro",
            "lookup em rainbow table retorna senha em segundos",
        ],
        [
            "identificar formato do hash em dump autorizado",
            "validar contra rainbow table sem upload de plaintext sensível",
            "registrar % de hashes quebráveis em amostra",
        ],
        "Comprometimento total das credenciais persistidas; reuso entre serviços expande o impacto.",
        "Migrar para argon2id/bcrypt com salt único e cost ≥12, forçar reset, monitorar HIBP, MFA obrigatório.",
    ),

    # ── Encoding-as-encryption misuse ───────────────────────────────────────
    _seed(
        "weak-encoding-as-encryption",
        "Encodings (Base64/ROT13/z85) misused as if they were cryptography",
        "Cryptography Misuse — encoding-as-encryption",
        ["base64 cookie", "rot13", "z85", "base85", "encoding misuse"],
        ["EncodingMisuse"],
        ["P11", "P14"],
        ["vuln-auth-bypass", "weak-cryptography"],
        ["jwt_tool", "burp-cli", "trufflehog"],
        [
            "cookie/token decodável trivialmente em cascata (b64 → ascii)",
            "campo de cupom/voucher segue header conhecido (base85, z85)",
            "valores diferentes mantêm o mesmo prefixo → mesmo IV/sem cifragem",
        ],
        [
            "interceptar cookies/tokens e tentar decode em cascata",
            "comparar dois valores diferentes para inferir esquema",
            "documentar achado sem replay de privilégios",
        ],
        "Cookies/cupons forjáveis; bypass de auth ou descontos arbitrários.",
        "Usar AES-GCM/ChaCha20-Poly1305 com chave rotacionável, JWT HS256+key forte ou EdDSA, HMAC nas integrações.",
    ),

    # ── Broken Access Control: admin endpoints unauthenticated ──────────────
    _seed(
        "broken-access-control-admin-endpoints",
        "Admin endpoints reachable without authentication",
        "Broken Access Control — missing auth",
        ["bac", "missing auth", "unauthenticated admin"],
        ["BrokenAccessControl"],
        ["P14", "P19"],
        ["vuln-auth-bypass", "vuln-api-graphql"],
        ["nuclei", "ffuf", "burp-cli", "katana"],
        [
            "rota admin acessível sem header Authorization",
            "DELETE/PUT em recurso administrativo aceita sem token",
            "diferença de status entre acesso anônimo e autenticado é nula",
        ],
        [
            "enumerar rotas admin via gau + dirsearch + JS strings",
            "tentar GET sem auth e comparar com auth de usuário comum",
            "documentar diff sem alterar dados",
        ],
        "Qualquer visitante consegue ler, editar e remover dados administrativos.",
        "Middleware de autorização por rota, RBAC server-side, deny-by-default, testes automatizados de auth para todos os endpoints.",
    ),

    # ── IDOR ────────────────────────────────────────────────────────────────
    _seed(
        "idor-direct-object-reference",
        "IDOR: direct object reference without ownership check",
        "Insecure Direct Object Reference",
        ["idor", "object reference", "horizontal privesc"],
        ["IDOR"],
        ["P19"],
        ["vuln-api-graphql", "vuln-auth-bypass"],
        ["nuclei", "burp-cli", "arjun"],
        [
            "endpoint /resource/{id} responde 200 para id de outro usuário",
            "POST aceita user_id arbitrário no body",
            "JWT do user A consegue ler/escrever recurso do user B trocando o id",
        ],
        [
            "criar 2 contas autorizadas, autenticar como A",
            "trocar id na URL/payload pelo id de B e medir resposta",
            "registrar evidência sem persistir alteração no recurso de B",
        ],
        "Quebra de confidencialidade entre tenants/usuários do mesmo serviço.",
        "Validar ownership server-side em TODA consulta, UUID v4 não-sequencial, policy authorization (ABAC/OPA), audit log por acesso a recurso de outro user.",
    ),

    # ── Open redirect ───────────────────────────────────────────────────────
    _seed(
        "open-redirect-allowlist-bypass-generic",
        "Open redirect via allowlist bypass with `@` userinfo or null byte",
        "Open Redirect",
        ["open redirect", "url=", "redirect bypass", "null byte"],
        ["OpenRedirect"],
        ["P12", "P13"],
        ["vuln-injection", "vuln-api-graphql"],
        ["nuclei", "burp-cli", "katana", "interactsh-client"],
        [
            "param ?to/?next/?url retorna 30x sem validação de host",
            "allowlist contornada via `@` (https://allowed.com@evil.com)",
            "bypass com %00/%0a entre allowlist e domínio do atacante",
        ],
        [
            "extrair endpoints com ?redirect/?next/?url do crawler",
            "testar payloads canônicos read-only",
            "confirmar redirect via Location header",
        ],
        "Phishing de alta taxa de sucesso (URL legítima leva ao atacante), token leak via Referer.",
        "Allowlist por path absoluto, comparar host após canonicalização, sanitizar bytes de controle, jamais aceitar URL externa em redirect.",
    ),

    # ── Business logic / numeric validation ─────────────────────────────────
    _seed(
        "business-logic-numeric-bypass",
        "Business logic flaws: negative quantity, oversize value, forgeable coupon",
        "Business Logic — Numeric Validation",
        ["negative quantity", "race condition", "coupon forge", "logic flaw"],
        ["BusinessLogic"],
        ["P12", "P16"],
        ["vuln-api-graphql", "vuln-injection"],
        ["burp-cli", "arjun"],
        [
            "endpoint de checkout aceita quantity: -1 e crédito no total",
            "endpoint /coupon/apply valida apenas formato do código",
            "campos numéricos aceitam strings sem coerção",
        ],
        [
            "interceptar request e injetar limites (-1, 0, 999999, NaN)",
            "comparar total calculado vs esperado sem finalizar pedido",
            "para cupom forjável: gerar com algoritmo conhecido e validar resposta",
        ],
        "Fraude financeira direta — pedidos com valor negativo, cupons infinitos, manipulação de saldo.",
        "Validação server-side de tipos e ranges, schema validator, assinatura HMAC em cupons, idempotency keys, regras de negócio fora do payload.",
    ),

    # ── Path traversal + null-byte filter bypass ────────────────────────────
    _seed(
        "path-traversal-nullbyte-bypass",
        "Path traversal with null-byte / double-URL-encoded extension bypass",
        "Path Traversal",
        ["lfi", "directory traversal", "null byte", "double url encode"],
        ["PathTraversal"],
        ["P12", "P15", "P17"],
        ["vuln-directory-enum", "vuln-injection"],
        ["ffuf", "feroxbuster", "burp-cli", "nuclei"],
        [
            "rota serve diretório indexado sem auth",
            "filtro de extensão bloqueia .bak mas aceita .bak%2500.md",
            "encoding double-URL (%252e%252e) bypassa input filter",
        ],
        [
            "verificar listing direto e variantes case",
            "tentar payload com null byte em sufixo permitido",
            "testar double-URL-encoded ../../ sem extrair conteúdo do arquivo final",
        ],
        "Vazamento de backups (DB dumps, configs com chaves), credenciais e PII.",
        "Servir arquivos via API com allowlist por nome, jamais expor diretório, normalizar+validar path absoluto, bloquear bytes de controle.",
    ),

    # ── Vulnerable frontend dependency ──────────────────────────────────────
    _seed(
        "vulnerable-frontend-dependency-generic",
        "Outdated frontend library with known sanitization bypass CVE",
        "Vulnerable Dependency — frontend",
        ["vulnerable lib", "supply chain", "outdated jquery", "html sanitizer cve"],
        ["VulnerableDependency"],
        ["P22"],
        ["code-secrets-sast", "code-supply-chain-deps"],
        ["retire", "trivy", "nuclei", "semgrep"],
        [
            "package.json/JS bundle expõe versão de lib com CVE conhecido",
            "Snyk/Retire flag dependency com severity high",
            "lib específica conhecidamente bypassa sanitização",
        ],
        [
            "extrair JS bundle e rodar retire.js -j",
            "cruzar versões com OSV/NVD",
            "PoC mínimo para confirmar bypass sem persistir payload",
        ],
        "Bypass de sanitização cliente, viabiliza Stored XSS persistente em todo o e-commerce.",
        "Renovate/Dependabot, lockfile review obrigatório, Trivy/SBOM no CI, sanitização também no servidor (nunca confiar só no front).",
    ),

    # ── Server misconfiguration via nikto scan ───────────────────────────────
    _seed(
        "server-misconfiguration-nikto-scan",
        "Server misconfiguration and exposed sensitive paths detected by web scanner",
        "Server Misconfiguration — Exposed Paths",
        ["admin panel exposed", "backup file accessible", "directory listing", "ftp exposed", "outdated server", "debug endpoint"],
        ["ServerMisconfiguration", "InformationExposure"],
        ["P03", "P05", "P11", "P12"],
        ["vuln-information-disclosure", "vuln-directory-enum", "recon-web-crawl"],
        ["nikto", "nuclei", "ffuf", "feroxbuster"],
        [
            "diretório /ftp/ ou /backup/ acessível sem autenticação retorna listagem",
            "painel de administração acessível via rota não autenticada (/admin, /administration)",
            "arquivos sensíveis (.env, .bak, .sql, acquisitions.md) expostos publicamente",
            "cabeçalho Server expõe versão com CVE conhecido",
            "endpoint de debug (/console, /actuator, /api/swagger) responde 200",
        ],
        [
            "executar nikto -h URL para varredura automática de 6700+ misconfigs",
            "verificar /ftp/, /admin, /backup, /console, /actuator sem autenticação",
            "confirmar listagem de diretório com GET simples e anotar arquivos expostos",
            "registrar conteúdo dos metadados sem baixar dados sensíveis além do nome",
        ],
        "Atacante acessa documentos internos, backups de DB, credenciais e configs de infra sem autenticação.",
        "Desabilitar listagem de diretório, proteger rotas admin com autenticação obrigatória, remover arquivos temporários do build, security headers.",
    ),

    # ── Directory fuzzing with wordlist (ffuf/feroxbuster) ───────────────────
    _seed(
        "directory-fuzzing-wordlist-discovery",
        "Hidden endpoints and admin routes discovered via wordlist-based directory fuzzing",
        "Information Disclosure — Hidden Endpoints",
        ["dir busting", "directory fuzzing", "hidden admin", "wordlist enumeration", "content discovery"],
        ["InformationExposure", "BrokenAccessControl"],
        ["P03", "P05", "P15"],
        ["vuln-directory-enum", "vuln-information-disclosure", "recon-web-crawl"],
        ["ffuf", "feroxbuster", "gobuster", "dirsearch", "nikto"],
        [
            "rota /admin, /score-board, /management retorna 200 sem aparecer na navegação",
            "endpoint /api/internal, /api/admin retorna dados privilegiados para qualquer cliente",
            "arquivo de configuração /config.js, /env.js, /.env exposto em path padrão",
            "rota sensível encontrada via raft-small-directories wordlist",
        ],
        [
            "executar ffuf com raft-small-directories wordlist contra a raiz do alvo",
            "filtrar respostas por status 200, 301, 302 excluindo 404 e 403 padrão",
            "confirmar conteúdo de cada rota descoberta sem autenticar",
            "registrar nome da rota e tipo de dado exposto sem extrair PII",
        ],
        "Rotas administrativas ou de diagnóstico acessíveis expõem dados de usuários, configurações e mecanismos de controle.",
        "Implementar autenticação em todas as rotas, remover endpoints de debug em produção, security.txt com policy de divulgação.",
    ),

    # ── Comprehensive black-box web vulnerability scan (wapiti) ──────────────
    _seed(
        "comprehensive-blackbox-web-vuln-scan",
        "Comprehensive black-box web application vulnerability scan via autonomous scanner",
        "Comprehensive Web Vulnerability — SQLi, XSS, Path Traversal",
        ["wapiti scan", "blackbox scan", "autonomous web scan", "sqli xss path traversal combined"],
        ["SQLi", "XSS", "PathTraversal", "SSRF"],
        ["P12", "P14", "P16", "P19"],
        ["vuln-injection", "vuln-api-graphql", "vuln-auth-bypass"],
        ["wapiti", "nikto", "nuclei", "dalfox"],
        [
            "scanner autônomo descobre SQL injection em endpoints de busca/filtro REST",
            "scanner detecta XSS refletido em parâmetros de query e campos de formulário",
            "endpoint vulnerável a path traversal identificado na fase de crawling interno",
            "SSRF interno detectado via resposta com timing ou conteúdo interno",
        ],
        [
            "executar wapiti -u URL -f json --flush-session -d 2 para varredura completa",
            "aguardar relatório JSON com seções por tipo de vulnerabilidade",
            "confirmar cada achado com payload mínimo read-only antes de reportar",
            "registrar endpoint, método HTTP, parâmetro afetado e resposta anômala",
        ],
        "Vulnerabilidades de injeção, XSS e traversal expostas em endpoints de produção permitem comprometimento de dados e execução de código.",
        "Parametrizar queries, output encoding por contexto, validação server-side de paths, CSP, WAF com regras de injeção.",
    ),

    # ── DOM XSS and reflected XSS in SPA via dalfox ─────────────────────────
    _seed(
        "dom-xss-spa-dalfox-scan",
        "DOM-based and reflected XSS in single-page application detected via automated XSS scanner",
        "Cross-Site Scripting — DOM/Reflected SPA",
        ["dom xss", "spa xss", "angular xss", "iframe javascript src", "reflected xss parameter"],
        ["DOMXSS", "ReflectedXSS"],
        ["P12", "P16"],
        ["vuln-injection"],
        ["dalfox", "wapiti", "nuclei", "katana"],
        [
            "parâmetro de busca/filtro renderizado no DOM sem sanitização via framework Angular/React/Vue",
            "iframe com src controlado por parâmetro URL aceita javascript: scheme",
            "campo de input com ng-bind ou v-html reflete payload XSS sem escape",
            "endpoint retorna JSON com campo HTML não sanitizado renderizado diretamente",
        ],
        [
            "executar dalfox url URL para varredura XSS abrangente incluindo DOM",
            "testar parâmetros de busca com payload <script>alert(1)</script> e variantes encode",
            "verificar contexto de renderização (innerHTML, setAttribute, eval) sem executar payload destrutivo",
            "documentar parâmetro vulnerável, contexto DOM e método de escape ausente",
        ],
        "Atacante executa código arbitrário no browser da vítima, comprometendo sessão, cookies e dados sensíveis.",
        "Sanitização server-side e client-side, DOMPurify para conteúdo HTML dinâmico, CSP strict-dynamic, jamais usar innerHTML com dados não-confiáveis.",
    ),

    # ── CVE and template-driven vulnerability scan (nuclei) ──────────────────
    _seed(
        "cve-template-driven-nuclei-scan",
        "CVE and known vulnerability detection via template-driven scanner",
        "Known CVE — Template-Driven Detection",
        ["nuclei cve", "cve detection", "known vulnerability", "security misconfiguration nuclei"],
        ["KnownCVE", "SecurityMisconfiguration"],
        ["P11", "P12", "P14"],
        ["vuln-injection", "vuln-auth-bypass", "vuln-information-disclosure"],
        ["nuclei", "nikto", "wapiti", "retire"],
        [
            "CVE conhecido detectado via template nuclei na versão de software exposta",
            "cabeçalho de resposta ou banner revela versão com vulnerabilidade pública",
            "endpoint com configuração padrão fraca identificado por template de misconfiguration",
            "biblioteca JavaScript com CVE detectada via fingerprint de versão",
        ],
        [
            "executar nuclei -u URL -severity critical,high,medium,low para cobertura ampla",
            "cruzar versões identificadas com NVD/OSV para CVEs aplicáveis",
            "confirmar exploitabilidade com request read-only antes de reportar",
            "registrar CVE-ID, CVSS score, evidência de versão e endpoint afetado",
        ],
        "CVEs conhecidos permitem comprometimento remoto sem necessidade de descoberta de zero-day.",
        "Patch management automatizado, asset inventory com versões, SCA no CI/CD, monitoramento de CVEs por stack tecnológico.",
    ),

    # ── REST API parameter injection (wapiti + arjun) ────────────────────────
    _seed(
        "rest-api-parameter-injection",
        "SQL injection and parameter pollution in REST API endpoints via automated discovery",
        "SQL Injection — REST API Parameter",
        ["rest api sqli", "api parameter injection", "json sqli", "search api injection"],
        ["RESTAPISQLi", "ParameterPollution"],
        ["P12", "P19"],
        ["vuln-injection", "vuln-api-graphql"],
        ["wapiti", "arjun", "sqlmap", "ffuf"],
        [
            "endpoint REST /api/search?q= ou /rest/products/search aceita payload SQLi",
            "parâmetro JSON em POST body não sanitizado resulta em erro de DB ou dados extras",
            "endpoint de login /api/auth aceita payload tautológico via JSON body",
            "campo 'q' em endpoint de busca retorna resultado diferente com quote único",
        ],
        [
            "descobrir parâmetros de API com arjun antes de injetar",
            "executar wapiti para crawling + injeção automática em endpoints REST",
            "testar endpoint de busca com payload SQLi minimal e comparar contagem de resultados",
            "registrar endpoint, payload e diferença de resposta sem persistir alteração",
        ],
        "Extração de dados, bypass de autenticação ou comprometimento total do banco via injeção em API.",
        "Queries parametrizadas em toda camada ORM/DB, validação de schema em inputs JSON, rate limiting em endpoints de busca.",
    ),
]


def walkthrough_derived_seeds() -> list[dict[str, Any]]:
    """Returns a defensive copy of the walkthrough-derived seeds."""
    return [dict(seed) for seed in WALKTHROUGH_DERIVED_SEEDS]
