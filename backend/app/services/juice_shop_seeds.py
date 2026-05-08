"""Curated seeds extracted from the OWASP Juice Shop walkthrough.

Source: https://github.com/bsqrl/juice-shop-walkthrough (single README.md, 26
challenges). This file translates each documented challenge into a structured
seed compatible with `vulnerability_learning_catalog._seed()`. Goals:

  1. Every existing skill (xss, sqli, idor, info-exposure, broken-crypto, ...)
     gains battle-tested probes proven to fire on a real vulnerable app.
  2. We introduce new keys for categories the original catalog didn't cover
     (broken-access-control, business-logic-numeric, weak-encoding-misuse,
     null-byte-bypass, ftp-directory-exposure, base64-cookie-leak).

All steps are READ-ONLY signals — no destructive payloads. Each entry follows
the same shape as `CURATED_VULNERABILITY_LEARNINGS` so the existing
`_normalize_learning_payload` and learning index pick them up automatically.
"""
from __future__ import annotations

from typing import Any

from app.services.vulnerability_learning_catalog import _seed


# ─────────────────────────────────────────────────────────────────────────────
# JUICE SHOP — 26 walkthrough challenges → seeds
#
# Each tuple maps to a `_seed(...)` call:
#   key, title, vulnerability_type, aliases, github_paths, phases, skills,
#   tools, signals, steps, impact, remediation
# Phase IDs follow `mission.PENTEST_PHASES` (P01–P22).
# ─────────────────────────────────────────────────────────────────────────────

JUICE_SHOP_SEEDS: list[dict[str, Any]] = [
    # ── Challenge 1, 22, 24 — Information Exposure ───────────────────────────
    _seed(
        "info-exposure-html-comments",
        "Score Board / Easter Eggs revealed via HTML comments and JS bundles",
        "Information Exposure",
        ["html comment", "easter egg", "scoreboard", "leaked path"],
        ["JuiceShop", "InformationExposure"],
        ["P03", "P05", "P22"],
        ["recon-web-crawl", "vuln-information-exposure", "code-secrets"],
        ["katana", "hakrawler", "gau", "curl-headers", "trufflehog"],
        [
            "comentário HTML revelando rota oculta (ex.: /#/score-board)",
            "JS bundle com strings 'admin', 'easteregg', 'ftp' não-minificadas",
            "rota não roteada visível em robots.txt ou sitemap.xml",
        ],
        [
            "baixar a SPA inicial e procurar comentários <!-- ... -->",
            "extrair JS principal e grep em strings de rota",
            "comparar links derivados via gau/wayback com rotas ativas",
            "registrar evidência sem acessar conteúdo sensível além do necessário",
        ],
        "Atacante descobre rotas de admin, FTP, scoreboard ou easter eggs sem autenticação.",
        "Remover comentários HTML em produção, minificar+ofuscar JS, mover rotas privadas para subdomínio com auth, escanear builds com gitleaks/trufflehog.",
    ),

    # ── Challenge 2 — SQL error verbose ──────────────────────────────────────
    _seed(
        "sqli-error-verbose",
        "Verbose SQL error disclosure",
        "SQL Injection (error-based recon)",
        ["sql error", "stack trace", "sequelize error"],
        ["JuiceShop", "ErrorBasedSQLi"],
        ["P11", "P12"],
        ["vuln-injection", "vuln-information-exposure"],
        ["sqlmap", "curl-headers", "nuclei"],
        [
            "single quote em campo retorna stack trace com nome de tabela",
            "mensagem 'SequelizeDatabaseError' / 'SQLITE_ERROR' no body",
            "diferença de status 500 vs 400 ao injetar caractere especial",
        ],
        [
            "enviar quote único e backtick em cada parâmetro identificado pelo crawler",
            "comparar response normal vs anômalo (tamanho/status/mensagem)",
            "registrar trecho do erro retornado sem extrair dados",
        ],
        "Erro verboso entrega esquema do banco, dialeto, e indica pontos prováveis de injeção.",
        "Capturar exceções no backend, retornar mensagem genérica, logar stack apenas server-side.",
    ),

    # ── Challenges 3, 4, 5 — Authentication bypass via SQLi ──────────────────
    _seed(
        "sqli-login-bypass",
        "Authentication bypass via SQL injection in login form",
        "SQL Injection (auth bypass)",
        ["login bypass", "or 1=1", "sqli auth"],
        ["JuiceShop", "LoginBypassSQLi"],
        ["P12", "P14"],
        ["vuln-injection", "vuln-auth-broken"],
        ["sqlmap", "burp-cli", "ffuf"],
        [
            "payload \"' OR 1=1--\" autentica como primeiro usuário (admin)",
            "operador LIKE em payload \"jim@%--\" autentica como Jim",
            "regex em payload \"%' OR email LIKE '%bender%'--\" passa por pattern",
            "campo email aceita aspas sem sanitização",
        ],
        [
            "no campo email enviar quote único — observar erro vs login",
            "tentar payload tautológico read-only e medir status 200 + JWT na resposta",
            "validar com payload incorreto (1=2) que NÃO há fallback genérico",
            "registrar request/response sem persistir credencial obtida",
        ],
        "Atacante autentica-se sem senha como qualquer usuário (incluindo admin), comprometendo todo o tenant.",
        "Substituir queries por ORM com bind parameters, hash de senha bcrypt/argon2, conta admin separada de e-commerce, MFA, rate-limit por IP/email.",
    ),

    # ── Challenge 6 — Reflected XSS ──────────────────────────────────────────
    _seed(
        "xss-reflected-search",
        "Reflected XSS via unsanitized search/query parameter",
        "Cross-Site Scripting (Reflected)",
        ["reflected xss", "search xss", "query string xss"],
        ["JuiceShop", "ReflectedXSS"],
        ["P12", "P16"],
        ["vuln-injection", "vuln-api-graphql"],
        ["dalfox", "nuclei", "wapiti", "katana", "arjun"],
        [
            "parâmetro 'q' / 'search' / 'name' refletido em HTML sem escape",
            "Content-Type text/html + body com <script> não filtrado",
            "DOM mostra valor injetado dentro de <iframe src> ou atributo",
        ],
        [
            "fuzzear parâmetros descobertos com payload <iframe src=javascript:alert()> usando dalfox",
            "validar reflexão via curl simples antes de qualquer payload ativo",
            "documentar contexto da reflexão (atributo, tag, JS literal)",
        ],
        "Atacante consegue executar JS no contexto do alvo, roubando JWT/session de usuários.",
        "Output encoding por contexto (HTML/attr/JS), CSP estrita, sanitização server-side, framework com auto-escape.",
    ),

    # ── Challenges 7-9 — Stored XSS via API ──────────────────────────────────
    _seed(
        "xss-stored-api-bypass",
        "Stored XSS via direct API request bypassing client-side validation",
        "Cross-Site Scripting (Stored)",
        ["stored xss", "persistent xss", "client validation bypass"],
        ["JuiceShop", "StoredXSS"],
        ["P12", "P16"],
        ["vuln-injection", "vuln-api-graphql"],
        ["dalfox", "burp-cli", "nuclei", "arjun"],
        [
            "campo aceita payload via POST direto mesmo após filtro JS",
            "PUT em /api/Products/{id} sem auth aceita HTML em description",
            "biblioteca sanitize-html (versão vulnerável) deixa <iframe> passar",
        ],
        [
            "interceptar POST de criação de comentário/produto com Burp",
            "remover restrição client-side (DevTools) e reenviar com payload curto",
            "verificar persistência em GET subsequente sem autenticação",
        ],
        "Payload persiste no banco e dispara para qualquer visitante futuro — comprometimento em massa.",
        "Validação server-side obrigatória, sanitização robusta (DOMPurify atualizado), CSP, escapar HTML antes de armazenar, autenticação em endpoints de mutação.",
    ),

    # ── Challenge 10 — UNION-based credential extraction ─────────────────────
    _seed(
        "sqli-union-credential-extract",
        "UNION-based SQL injection to extract user credentials",
        "SQL Injection (UNION extraction)",
        ["union select", "credential dump", "sqli union"],
        ["JuiceShop", "UNIONSQLi"],
        ["P12"],
        ["vuln-injection"],
        ["sqlmap", "burp-cli"],
        [
            "endpoint search retorna colunas refletidas (ID, name, description, price)",
            "ORDER BY n+1 dispara erro indicando número de colunas",
            "UNION SELECT NULL,NULL,... passa sem filtro",
        ],
        [
            "descobrir número de colunas via ORDER BY iterativo",
            "construir UNION SELECT email,password,NULL,NULL FROM Users LIMIT 1",
            "registrar evidência em escopo autorizado e não persistir credenciais extraídas",
        ],
        "Atacante extrai hashes de senha (MD5 reversível) e PII de toda base.",
        "Queries parametrizadas, hash forte (bcrypt+pepper), separar acesso ao schema de leitura/escrita, monitorar consultas anômalas com WAF.",
    ),

    # ── Challenges 11, 20, 23, 25 — Broken cryptography / weak encoding ──────
    _seed(
        "weak-crypto-md5-rainbow",
        "Reversible MD5 password hashes via public rainbow tables",
        "Broken Cryptography (MD5 rainbow)",
        ["md5", "rainbow table", "broken hash", "crackstation"],
        ["JuiceShop", "MD5Rainbow"],
        ["P11", "P14", "P22"],
        ["vuln-auth-broken", "weak-crypto"],
        ["nuclei", "trufflehog", "retire", "hashcat"],
        [
            "32 hex chars armazenados sem salt no campo password",
            "lookup em rainbow table retorna senha em segundos",
            "fingerprint de framework com default MD5 (vulnerable lib version)",
        ],
        [
            "identificar formato do hash em dump autorizado (32 hex)",
            "validar no CrackStation/HashesOrg sem upload de plaintext sensível",
            "registrar % de hashes quebráveis em amostra, não toda base",
        ],
        "Comprometimento total das credenciais persistidas; reuso de senha cruza para outros sistemas.",
        "Migrar para bcrypt/argon2id com salt único por usuário e cost ≥12, forçar reset, monitorar HIBP, MFA obrigatório para admin.",
    ),
    _seed(
        "weak-encoding-base64-rot13",
        "Misuse of encodings (Base64 / ROT13 / z85) as if they were encryption",
        "Cryptography Misuse (encoding-as-encryption)",
        ["base64 cookie", "rot13", "z85", "base85"],
        ["JuiceShop", "EncodingMisuse"],
        ["P11", "P14"],
        ["vuln-auth-broken", "weak-crypto"],
        ["jwt_tool", "burp-cli", "trufflehog"],
        [
            "cookie session com payload Base64 decodável trivialmente",
            "campo coupon segue Base85/z85 com header conhecido",
            "valor 'criptografado' decifra como texto plano após rot13",
        ],
        [
            "interceptar cookies/tokens com Burp e tentar decode em cascata (b64 → rot13 → b85)",
            "comparar dois valores diferentes para inferir esquema (mesmo prefixo, mesmo IV)",
            "documentar achado sem replay de privilégios obtidos",
        ],
        "Cookies/cupons forjáveis sem chave; bypass de auth ou gerar descontos infinitos.",
        "Usar AES-GCM/ChaCha20-Poly1305 com chave por aplicação rotacionada, JWT com HS256+key forte ou EdDSA, HMAC nas integrações.",
    ),

    # ── Challenges 12, 13, 15, 19, 21 — Broken Access Control / IDOR ────────
    _seed(
        "broken-access-control-admin",
        "Broken Access Control: admin endpoints reachable unauthenticated",
        "Broken Access Control",
        ["bac", "missing auth", "unauthenticated admin", "broken access"],
        ["JuiceShop", "BrokenAccessControl"],
        ["P14", "P19"],
        ["vuln-auth-broken", "vuln-api-graphql"],
        ["nuclei", "ffuf", "burp-cli", "katana"],
        [
            "/#/administration acessível sem JWT",
            "DELETE /api/Feedbacks/{id} aceita sem token de admin",
            "PUT /api/Products/{id} responde 200 sem Authorization header",
        ],
        [
            "enumerar rotas admin via gau + dirsearch + JS strings",
            "tentar GET sem auth e comparar status com auth de usuário comum",
            "documentar diff de comportamento sem alterar dados",
        ],
        "Qualquer visitante consegue ler, editar e remover dados administrativos.",
        "Middleware de autorização por rota, RBAC server-side, deny-by-default, testes automatizados de auth para todos os endpoints.",
    ),
    _seed(
        "idor-basket-feedback",
        "IDOR: direct object reference without ownership check",
        "Insecure Direct Object Reference",
        ["idor", "basket id", "object reference", "horizontal privesc"],
        ["JuiceShop", "IDOR"],
        ["P19"],
        ["vuln-api-graphql", "vuln-auth-broken"],
        ["nuclei", "burp-cli", "arjun"],
        [
            "/rest/basket/{id} responde 200 para id de outro usuário",
            "POST /api/Feedbacks aceita user_id arbitrário no body",
            "JWT do user A consegue ler dados do user B trocando o id",
        ],
        [
            "criar 2 contas autorizadas no escopo, autenticar como A",
            "trocar id na URL/payload pelo id de B e medir resposta",
            "registrar evidência sem persistir alteração no recurso de B",
        ],
        "Quebra de confidencialidade entre tenants/usuários do mesmo serviço.",
        "Validar ownership server-side em TODA consulta, usar UUID v4 não-sequencial, aplicar policy authorization (ABAC/OPA).",
    ),

    # ── Challenge 14 — Open Redirect / null byte ─────────────────────────────
    _seed(
        "open-redirect-allowlist-bypass",
        "Open Redirect via allowlist bypass with null byte / parameter pollution",
        "Open Redirect",
        ["open redirect", "url=", "redirect bypass", "null byte"],
        ["JuiceShop", "OpenRedirect"],
        ["P12", "P13"],
        ["vuln-injection", "vuln-api-graphql"],
        ["nuclei", "burp-cli", "katana", "interactsh-client"],
        [
            "param ?to=https://atacante.com retorna 30x sem validação",
            "allowlist contornada via @ no userinfo (https://allowed.com@evil.com)",
            "bypass com %00 / %0a entre allowlist e domínio atacante",
        ],
        [
            "extrair endpoints com ?redirect/?next/?url do crawler",
            "testar payloads canônicos e null-byte read-only",
            "confirmar redirect via Location header sem clicar",
        ],
        "Phishing de alto sucesso (URL legítima leva ao atacante), token leak via Referer.",
        "Allowlist estrita por path absoluto, nunca aceitar URL externa em redirect, sanitizar bytes de controle, comparar host após canonicalização.",
    ),

    # ── Challenges 16, 26 — Business logic / numeric validation ─────────────
    _seed(
        "business-logic-numeric-validation",
        "Business logic flaw: negative quantity / forged coupon",
        "Business Logic — Numeric Validation",
        ["negative quantity", "race condition", "coupon forge"],
        ["JuiceShop", "BusinessLogic"],
        ["P12", "P16"],
        ["vuln-api-graphql", "vuln-injection"],
        ["burp-cli", "arjun"],
        [
            "POST /api/BasketItems aceita quantity: -1 e CRÉDITO no total",
            "endpoint /rest/coupon/apply valida apenas formato z85 do código",
            "aceita strings em campos numéricos sem coerção",
        ],
        [
            "interceptar request de checkout/quantity e injetar valores limites (-1, 0, 999999, NaN)",
            "comparar total calculado vs esperado em response sem finalizar pedido",
            "para cupom: gerar código com algoritmo z85 conhecido e validar resposta sem efetivar desconto",
        ],
        "Fraude financeira direta — pedidos com valor negativo, cupons infinitos, manipulação de saldo.",
        "Validação server-side de tipos e ranges, schema validator (zod/joi), assinatura HMAC em cupons, idempotency keys, regras de negócio fora do payload.",
    ),

    # ── Challenges 17, 18 — Path Traversal + null byte FTP ──────────────────
    _seed(
        "path-traversal-ftp-nullbyte",
        "Path traversal in /ftp endpoint with null-byte extension bypass",
        "Path Traversal",
        ["lfi", "directory traversal", "null byte", "ftp dir"],
        ["JuiceShop", "PathTraversal"],
        ["P12", "P15", "P17"],
        ["vuln-directory-enum", "vuln-injection"],
        ["ffuf", "feroxbuster", "burp-cli", "nuclei"],
        [
            "/ftp serve diretório sem auth (Apache index)",
            "filtro de extensão bloqueia .bak mas aceita .bak%2500.md",
            "encoding double-URL (%252e%252e) bypassa input filter",
        ],
        [
            "verificar listing direto em /ftp e variantes case",
            "tentar payload com null byte em sufixo permitido",
            "testar double-URL-encoded ../../ sem extrair conteúdo do arquivo final",
        ],
        "Vazamento de backups (DB dumps, configs com chaves), credenciais e PII.",
        "Servir arquivos via API com allowlist por nome, jamais expor diretório, normalizar+validar path absoluto, bloquear bytes de controle, mover artefatos para storage offline.",
    ),

    # ── Challenge 22 — Vulnerable dependency ─────────────────────────────────
    _seed(
        "vulnerable-frontend-dependency",
        "Vulnerable JS sanitizer (sanitize-html outdated) leaking iframe",
        "Vulnerable Dependency (frontend)",
        ["sanitize-html", "vulnerable lib", "supply chain"],
        ["JuiceShop", "VulnerableDependency"],
        ["P22"],
        ["code-secrets", "code-supply-chain"],
        ["retire", "trivy", "nuclei", "semgrep"],
        [
            "package.json/JS bundle expõe sanitize-html < 2.x",
            "CVE conhecido permite passar tag específica não filtrada",
            "Snyk/Retire flag dependency com severity high",
        ],
        [
            "extrair JS bundle via katana e rodar retire.js -j",
            "cruzar versões com OSV/NVD",
            "registrar PoC via challenge XSS Tier 3 e nada além",
        ],
        "Bypass de sanitização cliente, viabiliza Stored XSS persistente em todo o e-commerce.",
        "Renovate/Dependabot, lockfile review obrigatório, Trivy/SBOM no CI, sanitização também no servidor (nunca confiar só no front).",
    ),
]


def juice_shop_curated_seeds() -> list[dict[str, Any]]:
    """Returns a defensive copy of the Juice Shop seeds for ingestion."""
    return [dict(seed) for seed in JUICE_SHOP_SEEDS]
