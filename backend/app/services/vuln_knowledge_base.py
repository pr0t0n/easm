"""
vuln_knowledge_base.py — Base de conhecimento de vulnerabilidades EASM.

Fornece explicações executivas e técnicas padronizadas para categorias de
vulnerabilidades encontradas por ZAP, supply chain analyzer, business logic
analyzer e ferramentas de infraestrutura.

Uso:
    from app.services.vuln_knowledge_base import get_vuln_explanation
    exp = get_vuln_explanation(title, tool, details)
    executive = exp.get("executive", "")
    technical = exp.get("technical", "")
"""

from __future__ import annotations

# Chave = substring do título em minúsculas
# Valor = dict com "executive" e "technical"
VULN_KNOWLEDGE_BASE: dict[str, dict[str, str]] = {

    # ── HTTP Security Headers ─────────────────────────────────────────────────

    "content security policy": {
        "executive": (
            "A ausência do cabeçalho Content Security Policy (CSP) expõe a aplicação a "
            "ataques de injeção de scripts (Cross-Site Scripting — XSS). Um atacante que "
            "consiga injetar código JavaScript pode roubar sessões de usuários, capturar "
            "credenciais em tempo real e executar ações em nome do usuário autenticado. "
            "Scripts maliciosos injetados via CDN comprometido ou através de terceiros "
            "(ex: Google Tag Manager) também são viabilizados pela falta de CSP. "
            "Risco regulatório direto: vazamento de dados sensíveis sujeito a multas "
            "LGPD/GDPR e impacto reputacional severo."
        ),
        "technical": (
            "O Content Security Policy é um mecanismo declarativo que instrui o navegador "
            "a aceitar apenas recursos (scripts, estilos, imagens) de origens explicitamente "
            "autorizadas. Sem CSP, qualquer código injetado via XSS, CDN comprometido ou "
            "extensão maliciosa executa livremente no contexto da aplicação.\n\n"
            "Remediação recomendada:\n"
            "  1. Implementar CSP restritivo via load balancer/CDN (nginx/CloudFlare):\n"
            "     Content-Security-Policy: default-src 'self'; "
            "script-src 'self' 'nonce-{NONCE}'; "
            "style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; "
            "connect-src 'self'; frame-ancestors 'none'; object-src 'none';\n"
            "  2. Iniciar com modo report-only para capturar violações antes de enforçar:\n"
            "     Content-Security-Policy-Report-Only: ...; report-uri /csp-violations\n"
            "  3. Eliminar uso de 'unsafe-inline' e 'unsafe-eval' — usar nonces ou hashes.\n"
            "  4. Para Single Page Applications (SPAs): implementar nonces por request.\n\n"
            "Ferramentas de validação: securityheaders.com, CSP Evaluator (csp-evaluator.withgoogle.com)\n"
            "Referências: OWASP A05:2021 – Security Misconfiguration, CWE-693, NIST SP 800-95."
        ),
    },

    "anti-clickjacking": {
        "executive": (
            "A ausência de proteção anti-clickjacking (cabeçalho X-Frame-Options ou diretiva "
            "frame-ancestors no CSP) permite que atacantes incorporem as páginas da aplicação "
            "em iframes invisíveis em sites maliciosos. O usuário acredita estar interagindo "
            "com um site legítimo, mas na prática está clicando em elementos da aplicação real "
            "por baixo de uma camada invisível — podendo confirmar transferências, alterar "
            "configurações críticas ou autorizar operações sem perceber. Aplicações financeiras, "
            "painéis administrativos e sistemas de autorização são alvos de alto valor."
        ),
        "technical": (
            "Clickjacking explora ausência de restrições de framing. Atacantes usam CSS opacity:0 "
            "e posicionamento absoluto para sobrepor a aplicação real em um iframe.\n\n"
            "Remediação:\n"
            "  1. Adicionar header: X-Frame-Options: DENY\n"
            "     (ou SAMEORIGIN se iframes de mesmo domínio forem necessários)\n"
            "  2. Alternativa moderna (mais granular, sobrepõe X-Frame-Options):\n"
            "     Content-Security-Policy: frame-ancestors 'none';\n"
            "  3. Implementar no nginx/load balancer para aplicação global automática:\n"
            "     add_header X-Frame-Options DENY always;\n\n"
            "Referências: OWASP A05:2021, CWE-1021 (UI Redressing), NIST AC-4."
        ),
    },

    "x-frame-options": {
        "executive": (
            "A ausência do cabeçalho X-Frame-Options (proteção anti-clickjacking) "
            "permite que atacantes incorporem as páginas da aplicação em iframes "
            "invisíveis em sites maliciosos. O usuário acredita estar clicando em "
            "elementos legítimos mas está, na verdade, interagindo com a aplicação "
            "real através de uma camada invisível — podendo executar ações não "
            "intencionais, como transferências financeiras ou alterações de configuração."
        ),
        "technical": (
            "Remediação:\n"
            "  1. Adicionar: X-Frame-Options: DENY (ou SAMEORIGIN)\n"
            "  2. Alternativa CSP: frame-ancestors 'none';\n"
            "  3. Aplicar no load balancer para cobertura total.\n"
            "Referências: OWASP A05:2021, CWE-1021."
        ),
    },

    "x-content-type-options": {
        "executive": (
            "A ausência do cabeçalho X-Content-Type-Options expõe usuários a ataques de "
            "MIME-type confusion (MIME sniffing). O navegador pode interpretar um arquivo "
            "de texto como JavaScript e executá-lo, ou tratar um arquivo de imagem como HTML. "
            "Combinado com upload de arquivos ou CDNs comprometidos, esse vetor permite "
            "execução de código malicioso sem nenhuma vulnerabilidade adicional na aplicação."
        ),
        "technical": (
            "O header X-Content-Type-Options: nosniff instrui o navegador a respeitar "
            "estritamente o Content-Type declarado pelo servidor, sem especulação.\n\n"
            "Remediação:\n"
            "  1. Adicionar: X-Content-Type-Options: nosniff\n"
            "  2. Aplicar globalmente via load balancer/CDN.\n"
            "  3. Garantir que endpoints de upload/download usem Content-Type correto e explícito.\n"
            "  4. Revisar endpoints que servem arquivos enviados por usuários.\n\n"
            "Referências: OWASP A05:2021, CWE-430."
        ),
    },

    "strict-transport-security": {
        "executive": (
            "A ausência do HSTS (HTTP Strict Transport Security) permite ataques de "
            "SSL-stripping em que um atacante em posição Man-in-the-Middle (rede pública, "
            "Wi-Fi corporativo comprometido, ponto de acesso malicioso) redireciona "
            "conexões HTTPS para HTTP sem que o usuário perceba. Isso expõe cookies de "
            "sessão, tokens JWT e credenciais em tráfego não criptografado. "
            "O impacto potencial inclui comprometimento massivo de contas de usuários "
            "que acessam a partir de redes não confiáveis (home office, mobilidade)."
        ),
        "technical": (
            "HSTS instrui os navegadores a sempre usar HTTPS para o domínio, mesmo que "
            "o usuário tente acessar via HTTP — e a rejeitar certificados inválidos.\n\n"
            "Remediação:\n"
            "  1. Adicionar header: Strict-Transport-Security: max-age=31536000; "
            "includeSubDomains; preload\n"
            "  2. Verificar que TODOS os subdomínios suportam HTTPS antes de usar includeSubDomains.\n"
            "  3. Submeter o domínio para a HSTS preload list: https://hstspreload.org\n"
            "  4. Configurar redirect 301 de HTTP para HTTPS em todos os endpoints.\n\n"
            "Referências: RFC 6797, OWASP A02:2021 – Cryptographic Failures, CWE-319."
        ),
    },

    "subresource integrity": {
        "executive": (
            "Scripts e estilos carregados de CDNs externos sem verificação de integridade "
            "(SRI – Subresource Integrity) podem ser substituídos por versões maliciosas "
            "caso o CDN seja comprometido. Este é o mecanismo central de ataques de "
            "supply chain como Magecart, o ataque ao Polyfill.io (2024, afetou 100 mil+ sites) "
            "e campanhas via Google Tag Manager comprometido. Um único arquivo JS "
            "alterado pode instalar um keylogger em TODAS as páginas da aplicação, "
            "capturando credenciais e dados de cartão de crédito de cada usuário em tempo real, "
            "sem nenhuma alteração no código da própria empresa."
        ),
        "technical": (
            "SRI usa hashes criptográficos (SHA-256/SHA-384/SHA-512) para verificar a "
            "integridade de recursos externos antes de executá-los. Se o conteúdo do CDN "
            "for alterado, o hash não corresponde e o navegador bloqueia a execução.\n\n"
            "Remediação:\n"
            "  1. Adicionar atributos integrity e crossorigin a todas as tags <script> e <link> externas:\n"
            "     <script src='https://cdn.example.com/lib.min.js'\n"
            "             integrity='sha384-AbCdEf...'\n"
            "             crossorigin='anonymous'></script>\n"
            "  2. Gerar o hash SRI: curl -s https://cdn.example.com/lib.js | "
            "openssl dgst -sha384 -binary | openssl base64 -A\n"
            "  3. Ou usar o gerador online: https://www.srihash.org\n"
            "  4. Adicionar ao CSP: require-sri-for script style;\n"
            "  5. Auditar scripts carregados via Google Tag Manager — cada tag requer SRI.\n"
            "  6. Considerar self-hosting de bibliotecas críticas para eliminar dependência de CDN.\n\n"
            "Referências: W3C SRI spec, OWASP A08:2021 – Software and Data Integrity Failures, CWE-494."
        ),
    },

    "referrer-policy": {
        "executive": (
            "A ausência do cabeçalho Referrer-Policy pode vazar URLs internas, tokens de "
            "sessão e identificadores de usuário para sites externos. Quando um usuário clica "
            "em um link externo, o navegador pode enviar a URL completa da página atual "
            "(incluindo parâmetros de query com tokens e IDs) para o site de destino via "
            "cabeçalho Referer. Sites de análise, parceiros e potencialmente atacantes "
            "podem receber e armazenar essas informações sensíveis."
        ),
        "technical": (
            "Remediação:\n"
            "  1. Adicionar: Referrer-Policy: strict-origin-when-cross-origin\n"
            "     (não envia path/query para origens cruzadas, apenas domínio de origem)\n"
            "  2. Para maior restrição: Referrer-Policy: no-referrer\n"
            "  3. Aplicar via load balancer para todos os domínios.\n"
            "  4. Revisar URLs que contêm tokens/IDs sensíveis em query strings.\n\n"
            "Referências: MDN Referrer-Policy, OWASP A02:2021."
        ),
    },

    "permissions-policy": {
        "executive": (
            "A ausência do Permissions-Policy (anteriormente Feature-Policy) permite que "
            "scripts de terceiros ou maliciosos acessem funcionalidades sensíveis do "
            "navegador — câmera, microfone, geolocalização, sensor de pagamento — sem "
            "restrição explícita. Em cenários de XSS ou CDN comprometido, isso pode "
            "ser usado para vigilância não autorizada de usuários."
        ),
        "technical": (
            "Remediação:\n"
            "  1. Adicionar: Permissions-Policy: camera=(), microphone=(), "
            "geolocation=(), payment=(self), usb=()\n"
            "  2. Listar apenas o que a aplicação realmente precisa.\n"
            "  3. Aplicar via load balancer/CDN.\n\n"
            "Referências: W3C Permissions Policy, OWASP A05:2021."
        ),
    },

    # ── Supply Chain ──────────────────────────────────────────────────────────

    "node_modules": {
        "executive": (
            "O diretório node_modules está acessível publicamente via HTTP. Esse diretório "
            "contém o código-fonte completo de todas as dependências do projeto, incluindo "
            "potencialmente arquivos .env, chaves de API incorporadas em packages e "
            "configurações de banco de dados. Atacantes podem mapear exatamente quais "
            "bibliotecas e versões estão em uso, selecionar CVEs públicos e explorar "
            "vulnerabilidades específicas com precisão cirúrgica. Em ambientes de "
            "desenvolvimento expostos, o risco inclui escalada para comprometimento "
            "completo do servidor via exploração de dependências vulneráveis."
        ),
        "technical": (
            "O diretório node_modules nunca deve ser exposto via web server. A presença "
            "de index.html ou arquivos .js acessíveis no path da raiz web é uma "
            "misconfiguration crítica.\n\n"
            "Remediação imediata:\n"
            "  1. Bloquear no nginx:\n"
            "     location ~* /node_modules { deny all; return 403; }\n"
            "  2. Bloquear no Apache (.htaccess):\n"
            "     RewriteRule ^node_modules/ - [F,L]\n"
            "  3. Mover a aplicação para fora do document root do web server.\n"
            "  4. Build Docker: copiar apenas artefatos compilados, nunca node_modules source.\n"
            "  5. Implementar WAF rule para bloquear paths contendo /node_modules/.\n"
            "  6. Auditoria imediata: verificar se .env, config.json, ou outros arquivos "
            "sensíveis também estão expostos no mesmo servidor.\n\n"
            "Referências: CWE-552 – Files or Directories Accessible to External Parties, "
            "OWASP A05:2021 – Security Misconfiguration."
        ),
    },

    "package.json": {
        "executive": (
            "Arquivos de manifesto de dependências (package.json, composer.json, "
            "requirements.txt, Gemfile) estão acessíveis publicamente. Esses arquivos "
            "listam cada biblioteca do projeto com versão exata, criando um mapa "
            "detalhado de componentes para um atacante. Com essa informação, é possível "
            "identificar automaticamente CVEs aplicáveis em bancos de dados públicos "
            "(NVD, Exploit-DB) e selecionar exploits sem interagir com a aplicação. "
            "Isso reduz drasticamente o tempo e esforço de reconhecimento de um ataque dirigido."
        ),
        "technical": (
            "Information disclosure de manifests de dependência viabiliza ataques de "
            "componentes vulneráveis (OWASP A06:2021).\n\n"
            "Remediação:\n"
            "  1. Bloquear acesso a arquivos de manifesto no nginx:\n"
            "     location ~* \\.(json|lock|txt|xml|ini|env)$ { deny all; return 403; }\n"
            "     (ajustar para não bloquear assets legítimos)\n"
            "  2. Mover arquivos de configuração para fora do document root.\n"
            "  3. Implementar WAF rule para padrões: package.json, composer.json, "
            "requirements.txt, Gemfile, yarn.lock, package-lock.json\n"
            "  4. Revisar quais arquivos ficam no diretório raiz da aplicação web.\n\n"
            "Referências: CWE-200 – Information Exposure, OWASP A06:2021 – Vulnerable Components."
        ),
    },

    "composer.json": {
        "executive": (
            "O arquivo composer.json (manifesto de dependências PHP) está acessível "
            "publicamente, revelando toda a stack de dependências do projeto com versões "
            "exatas. Isso permite que atacantes identifiquem vulnerabilidades conhecidas "
            "em bibliotecas específicas e planejem exploits direcionados."
        ),
        "technical": (
            "Remediação:\n"
            "  1. Bloquear acesso: location = /composer.json { deny all; return 403; }\n"
            "  2. Verificar também composer.lock, .env, config.php.\n"
            "  3. Mover esses arquivos para fora do document root.\n\n"
            "Referências: CWE-200, OWASP A06:2021."
        ),
    },

    "requirements.txt": {
        "executive": (
            "O arquivo requirements.txt (dependências Python) está exposto publicamente, "
            "revelando bibliotecas e versões exatas. Atacantes podem usar ferramentas "
            "automatizadas para cruzar essas versões com CVEs públicos e identificar "
            "vetores de exploit sem nenhum conhecimento prévio da aplicação."
        ),
        "technical": (
            "Remediação:\n"
            "  1. Bloquear: location = /requirements.txt { deny all; return 403; }\n"
            "  2. Verificar também setup.py, pyproject.toml, Pipfile.\n"
            "  3. Mover para fora do document root.\n\n"
            "Referências: CWE-200, OWASP A06:2021."
        ),
    },

    "supply chain": {
        "executive": (
            "Dependências de terceiros sem controle de integridade constituem um vetor "
            "de supply chain attack de alta eficácia. Campanhas como Magecart, o ataque "
            "ao Polyfill.io (2024) e injeções via Google Tag Manager comprometeram "
            "dezenas de milhares de sites com um único arquivo alterado. O impacto afeta "
            "100% dos usuários ativos: keyloggers, skimmers de pagamento e roubo de "
            "credenciais em tempo real, sem nenhuma alteração perceptível na aplicação."
        ),
        "technical": (
            "Controles de supply chain recomendados:\n"
            "  1. SRI (Subresource Integrity) para todos os scripts externos.\n"
            "  2. CSP com nonces para bloquear scripts não autorizados dinamicamente.\n"
            "  3. Auditoria de todas as tags carregadas via Google Tag Manager.\n"
            "  4. Revisar permissões de conta GTM — princípio de menor privilégio.\n"
            "  5. Monitoramento de mudanças em scripts externos via CSP violation reports.\n"
            "  6. Self-hosting de bibliotecas críticas (jQuery, Moment, etc.).\n"
            "  7. Pinagem de versões com lock files auditados (npm audit, pip audit).\n\n"
            "Referências: OWASP A08:2021 – Software and Data Integrity Failures, CWE-494."
        ),
    },

    "google tag manager": {
        "executive": (
            "O Google Tag Manager (GTM) está em uso na aplicação. O GTM pode executar "
            "qualquer JavaScript nas páginas da aplicação. Se a conta GTM for comprometida "
            "por credential stuffing, phishing ou acesso indevido de ex-funcionários, "
            "um atacante pode implantar um keylogger em produção em segundos. "
            "O acesso à conta GTM é, para fins práticos, equivalente a acesso ao "
            "código JavaScript de produção."
        ),
        "technical": (
            "Controles para uso seguro de GTM:\n"
            "  1. Habilitar MFA na conta Google que gerencia o GTM.\n"
            "  2. Revisar todos os usuários com acesso ao GTM — remover ex-colaboradores.\n"
            "  3. Implementar aprovação de duas pessoas para publicação de tags.\n"
            "  4. Usar CSP com nonces gerados dinamicamente para bloquear scripts não autorizados.\n"
            "  5. Monitorar alterações no container GTM via GTM History API.\n"
            "  6. Implementar SRI nos scripts carregados pelo GTM onde possível.\n\n"
            "Referências: OWASP A08:2021, CWE-494 – Download of Code Without Integrity Check."
        ),
    },

    # ── Infrastructure / Business Logic ───────────────────────────────────────

    "docker api": {
        "executive": (
            "A API do Docker está exposta sem autenticação adequada. A Docker API "
            "fornece controle total sobre todos os containers em execução, com capacidade "
            "de criar containers privilegiados com acesso direto ao filesystem do host. "
            "Um atacante com acesso à API Docker pode: escalar para root no servidor host, "
            "extrair todas as variáveis de ambiente (chaves de API, senhas de DB, tokens JWT), "
            "comprometer todos os serviços em execução e movimentar-se lateralmente para "
            "toda a infraestrutura. Este é um dos vetores mais críticos de comprometimento "
            "total de ambiente cloud/on-premise."
        ),
        "technical": (
            "Docker API sem autenticação exposta externamente equivale a acesso root ao host.\n\n"
            "Remediação imediata:\n"
            "  1. Desabilitar exposição TCP da Docker API na rede pública:\n"
            "     Remover -H tcp://0.0.0.0:2375 do arquivo de configuração do dockerd\n"
            "     (/etc/docker/daemon.json ou systemd override)\n"
            "  2. Usar exclusivamente socket Unix local: /var/run/docker.sock\n"
            "  3. Se acesso remoto for necessário, usar TLS mútuo:\n"
            "     dockerd --tlsverify --tlscacert=ca.pem "
            "--tlscert=server-cert.pem --tlskey=server-key.pem -H=0.0.0.0:2376\n"
            "  4. Bloquear portas 2375/2376 no firewall/security group.\n"
            "  5. Auditoria: inspecionar containers em execução e variáveis de ambiente.\n\n"
            "Referências: CWE-306 – Missing Authentication for Critical Function, "
            "OWASP A07:2021 – Identification and Authentication Failures."
        ),
    },

    "portainer": {
        "executive": (
            "O Portainer (interface web de gerenciamento Docker/Kubernetes) está "
            "acessível externamente sem proteção adequada. Portainer com credenciais "
            "padrão, fracas ou sem autenticação fornece controle completo sobre toda a "
            "infraestrutura de containers — incluindo acesso a secrets, databases e "
            "serviços internos. Ambientes de produção e homologação compartilhando o "
            "mesmo Portainer multiplicam o raio de impacto de um único comprometimento."
        ),
        "technical": (
            "Remediação:\n"
            "  1. Mover o Portainer para trás de VPN — NUNCA expor diretamente na internet.\n"
            "  2. Implementar IP allowlist: apenas IPs corporativos aprovados.\n"
            "  3. Habilitar autenticação de dois fatores (2FA) no Portainer.\n"
            "  4. Alterar senha padrão imediatamente e usar senhas fortes (20+ chars).\n"
            "  5. Usar Portainer RBAC para conceder acesso mínimo necessário por usuário.\n"
            "  6. Auditar logs de acesso ao Portainer em busca de acessos suspeitos.\n\n"
            "Referências: CWE-284 – Improper Access Control, NIST AC-3, OWASP A01:2021."
        ),
    },

    "information disclosure": {
        "executive": (
            "A aplicação está revelando informações internas (versões de servidor, stack "
            "tecnológica, mensagens de erro detalhadas ou arquivos de configuração) que "
            "auxiliam atacantes no planejamento de exploits. Information disclosure reduz "
            "significativamente o esforço necessário para um ataque: em vez de tentar "
            "diversas técnicas, o atacante pode selecionar diretamente as vulnerabilidades "
            "conhecidas para as versões específicas expostas."
        ),
        "technical": (
            "Remediação:\n"
            "  1. Remover headers de versão: Server, X-Powered-By, X-AspNet-Version.\n"
            "     nginx: server_tokens off;\n"
            "     Apache: ServerTokens Prod; ServerSignature Off;\n"
            "  2. Configurar páginas de erro customizadas (não revelar stack traces).\n"
            "  3. Bloquear acesso a arquivos de configuração, logs e backups.\n"
            "  4. Revisar responses de API — remover campos internos desnecessários.\n\n"
            "Referências: CWE-200 – Information Exposure, OWASP A05:2021."
        ),
    },

    "server leaks": {
        "executive": (
            "O servidor web está expondo informações de versão e configuração nos "
            "cabeçalhos HTTP. Atacantes utilizam essas informações para identificar "
            "versões vulneráveis e selecionar exploits específicos, reduzindo "
            "drasticamente o tempo de reconhecimento."
        ),
        "technical": (
            "Remediação:\n"
            "  1. nginx: server_tokens off;\n"
            "  2. Apache: ServerTokens Prod; ServerSignature Off;\n"
            "  3. Remover ou ocultar cabeçalhos Server, X-Powered-By, X-Generator.\n"
            "  4. Configurar no load balancer para aplicação uniforme.\n\n"
            "Referências: CWE-200, OWASP A05:2021."
        ),
    },

    "cross-domain": {
        "executive": (
            "Política de Cross-Origin mal configurada pode permitir que sites externos "
            "acessem dados sensíveis da aplicação via requisições cross-origin. "
            "Isso pode expor dados de sessão, perfis de usuários e informações "
            "da organização para domínios não autorizados."
        ),
        "technical": (
            "Remediação:\n"
            "  1. Revisar configuração CORS — não usar Access-Control-Allow-Origin: *\n"
            "  2. Definir whitelist explícita de origens permitidas.\n"
            "  3. Não enviar credenciais em requests cross-origin sem necessidade.\n"
            "  4. Validar Origin header no servidor antes de aceitar requests.\n\n"
            "Referências: OWASP A01:2021, CWE-942."
        ),
    },

}


def get_vuln_explanation(
    title: str,
    tool: str = "",
    details: dict | None = None,
) -> dict[str, str]:
    """
    Retorna dict com "executive" e "technical" para a vulnerabilidade informada.

    Estratégia de busca (em ordem de prioridade):
    1. Substring matching do título contra as chaves do KB
    2. Matching por ferramenta
    3. Fallback com description do details
    """
    if details is None:
        details = {}

    title_lower = (title or "").lower()
    tool_lower = (tool or "").lower()

    # 1. Busca por substring no título
    for key, explanation in VULN_KNOWLEDGE_BASE.items():
        if key in title_lower:
            return explanation

    # 2. Matching por ferramenta
    if "supply_chain" in tool_lower:
        return VULN_KNOWLEDGE_BASE.get("supply_chain", {})
    if "business_logic" in tool_lower:
        return {
            "executive": (
                "Vulnerabilidade de lógica de negócio identificada na aplicação. "
                "Esse tipo de falha é difícil de detectar por scanners automatizados e "
                "representa risco operacional e financeiro direto: pode ser explorada "
                "para bypass de regras de negócio, fraude, escalada de privilégios ou "
                "acesso não autorizado a recursos de outros usuários."
            ),
            "technical": str(
                details.get("description") or details.get("evidence") or
                "Revisar a lógica de negócio identificada. Implementar validações "
                "server-side para todas as operações críticas."
            )[:2000],
        }

    # 3. Fallback com description do details
    description = (
        details.get("description") or
        details.get("cve_description") or
        details.get("desc") or
        details.get("solution") or
        ""
    )
    if description:
        return {
            "executive": "",
            "technical": str(description)[:2000],
        }

    return {}
