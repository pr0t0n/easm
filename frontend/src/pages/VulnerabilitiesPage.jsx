import { Fragment, useEffect, useState } from "react";
import client from "../api/client";

const SEV_CLASS = {
  critical: "b-critical",
  high: "b-high",
  medium: "b-medium",
  low: "b-low",
  info: "b-info",
};

const SEVERITIES = ["critical", "high", "medium", "low", "info"];

const ANSI_RE = new RegExp(String.fromCharCode(27) + "\\[[0-9;]*m", "g");
const CTRL_RE = new RegExp("[\\x00-\\x1F\\x7F]", "g");

const sanitizeText = (value) => {
  if (value == null) return "";
  return String(value)
    .replace(ANSI_RE, "")
    .replace(CTRL_RE, " ")
    .replace(/\s+/g, " ")
    .trim();
};

// ─── Intelligence enrichment ──────────────────────────────────────────────────
// Derives ATT&CK, OWASP, ISO 27001, CIS Controls, PCI DSS, discovery method,
// real problem description, and environment impact from raw finding data.
// All fields fall back gracefully when backend data is missing.

const TOOL_INTELLIGENCE = {
  subfinder:   { discovery: "Enumeração passiva de subdomínios via agregação de fontes públicas (Certificate Transparency, VirusTotal, Shodan, DNS passivo). Identifica ativos não inventariados expostos na Internet.", mitre: [{ id: "T1590.001", name: "Gather Victim Network Info: Domain Properties" }, { id: "T1596.001", name: "Search Open Technical Databases: DNS/Passive DNS" }], owasp: ["A05:2021 – Security Misconfiguration"], iso: ["ISO 27001 A.8.9 – Configuration Management"], cis: ["CIS 1 – Inventory and Control of Enterprise Assets"], pci: ["PCI DSS 6.3.2 – Inventory of Bespoke Software"] },
  amass:       { discovery: "Reconhecimento ativo e passivo de DNS: brute-force de subdomínios, análise de zone transfers, correlação com registros SPF/MX/DMARC e raspagem de fontes OSINT.", mitre: [{ id: "T1590.001", name: "Gather Victim Network Info: Domain Properties" }, { id: "T1590.002", name: "Gather Victim Network Info: DNS" }], owasp: ["A05:2021 – Security Misconfiguration"], iso: ["ISO 27001 A.8.9 – Configuration Management", "ISO 27001 A.5.9 – Inventory of Assets"], cis: ["CIS 1 – Inventory and Control of Enterprise Assets"], pci: ["PCI DSS 12.3.1 – Targeted Risk Analysis"] },
  nmap:        { discovery: "Varredura TCP/UDP com identificação de portas abertas, fingerprinting de versão de serviços e detecção de SO via análise de respostas de pacotes.", mitre: [{ id: "T1046", name: "Network Service Discovery" }, { id: "T1595.001", name: "Active Scanning: Scanning IP Blocks" }], owasp: ["A05:2021 – Security Misconfiguration", "A06:2021 – Vulnerable and Outdated Components"], iso: ["ISO 27001 A.8.8 – Management of Technical Vulnerabilities"], cis: ["CIS 7 – Continuous Vulnerability Management", "CIS 12 – Network Infrastructure Management"], pci: ["PCI DSS 6.3.3 – Patch Management", "PCI DSS 11.3.1 – External Penetration Testing"] },
  httpx:       { discovery: "Probe HTTP/HTTPS com detecção de tecnologias, headers de segurança, redirects, status codes e fingerprint de servidores. Identifica endpoints ativos e configurações expostas.", mitre: [{ id: "T1590.005", name: "Gather Victim Network Info: IP Addresses" }, { id: "T1046", name: "Network Service Discovery" }], owasp: ["A05:2021 – Security Misconfiguration"], iso: ["ISO 27001 A.8.9 – Configuration Management"], cis: ["CIS 4 – Secure Configuration of Enterprise Assets"], pci: ["PCI DSS 6.2.4 – Software Engineering Techniques"] },
  nuclei:      { discovery: "Correspondência de templates de vulnerabilidade (CVEs, exposições de configuração, headers ausentes, endpoints sensíveis) contra cada endpoint HTTP ativo do escopo.", mitre: [{ id: "T1190", name: "Exploit Public-Facing Application" }, { id: "T1203", name: "Exploitation for Client Execution" }], owasp: ["A06:2021 – Vulnerable and Outdated Components", "A05:2021 – Security Misconfiguration"], iso: ["ISO 27001 A.8.8 – Management of Technical Vulnerabilities"], cis: ["CIS 7 – Continuous Vulnerability Management"], pci: ["PCI DSS 6.3.3 – Patch Management", "PCI DSS 11.3.2 – Internal Penetration Testing"] },
  dirsearch:   { discovery: "Fuzzing de caminhos HTTP via wordlist especializada para detecção de diretórios e arquivos expostos: backups, painéis admin, arquivos de configuração, endpoints de debug.", mitre: [{ id: "T1083", name: "File and Directory Discovery" }, { id: "T1595.003", name: "Active Scanning: Wordlist Scanning" }], owasp: ["A01:2021 – Broken Access Control", "A05:2021 – Security Misconfiguration"], iso: ["ISO 27001 A.8.3 – Information Access Restriction", "ISO 27001 A.8.9 – Configuration Management"], cis: ["CIS 4 – Secure Configuration of Enterprise Assets", "CIS 6 – Access Control Management"], pci: ["PCI DSS 7.2 – Access Control Systems", "PCI DSS 6.2.4 – Software Engineering Techniques"] },
  gobuster:    { discovery: "Enumeração de diretórios/arquivos e subdomínios via force brute DNS e HTTP. Detecta recursos não linkados publicamente que permanecem acessíveis sem controle de acesso adequado.", mitre: [{ id: "T1083", name: "File and Directory Discovery" }, { id: "T1595.003", name: "Active Scanning: Wordlist Scanning" }], owasp: ["A01:2021 – Broken Access Control", "A05:2021 – Security Misconfiguration"], iso: ["ISO 27001 A.8.3 – Information Access Restriction"], cis: ["CIS 4 – Secure Configuration of Enterprise Assets"], pci: ["PCI DSS 7.2 – Access Control Systems"] },
  sqlmap:      { discovery: "Injeção automatizada de payloads SQL com análise diferencial de respostas (tempo, conteúdo, erros) para identificar pontos de injeção exploráveis em parâmetros HTTP, cookies e headers.", mitre: [{ id: "T1190", name: "Exploit Public-Facing Application" }, { id: "T1059.004", name: "Command and Scripting Interpreter: Unix Shell" }], owasp: ["A03:2021 – Injection"], iso: ["ISO 27001 A.8.26 – Application Security Requirements", "ISO 27001 A.8.28 – Secure Coding"], cis: ["CIS 16 – Application Software Security"], pci: ["PCI DSS 6.2.4 – Software Engineering Techniques", "PCI DSS 11.3.1 – External Penetration Testing"] },
  trufflehog:  { discovery: "Análise de repositórios Git, arquivos de configuração e responses HTTP para detecção de segredos, tokens de API, chaves privadas e credenciais hardcoded via pattern matching e entropia.", mitre: [{ id: "T1552", name: "Unsecured Credentials" }, { id: "T1552.001", name: "Unsecured Credentials: Credentials In Files" }], owasp: ["A02:2021 – Cryptographic Failures", "A07:2021 – Identification and Authentication Failures"], iso: ["ISO 27001 A.8.13 – Information Backup", "ISO 27001 A.8.24 – Use of Cryptography"], cis: ["CIS 3 – Data Protection", "CIS 5 – Account Management"], pci: ["PCI DSS 3.5 – Protection of Stored Account Data", "PCI DSS 8.6.1 – System Accounts"] },
  wpscan:      { discovery: "Fingerprinting e enumeração de instalação WordPress: plugins vulneráveis, temas desatualizados, usuários expostos via API REST/author enumeration, versão do core e configurações inseguras.", mitre: [{ id: "T1190", name: "Exploit Public-Facing Application" }, { id: "T1589.001", name: "Gather Victim Identity Information: Credentials" }], owasp: ["A06:2021 – Vulnerable and Outdated Components", "A07:2021 – Identification and Authentication Failures"], iso: ["ISO 27001 A.8.8 – Management of Technical Vulnerabilities"], cis: ["CIS 7 – Continuous Vulnerability Management", "CIS 4 – Secure Configuration of Enterprise Assets"], pci: ["PCI DSS 6.3.3 – Patch Management"] },
  wafw00f:     { discovery: "Fingerprinting de WAF por análise de cabeçalhos HTTP, comportamento de respostas a payloads maliciosos e padrões específicos de cada vendor. Determina se há ou não proteção de perímetro ativa.", mitre: [{ id: "T1518.001", name: "Security Software Discovery" }, { id: "T1592.002", name: "Gather Victim Host Information: Software" }], owasp: ["A05:2021 – Security Misconfiguration"], iso: ["ISO 27001 A.8.22 – Segregation of Networks"], cis: ["CIS 12 – Network Infrastructure Management", "CIS 13 – Network Monitoring and Defense"], pci: ["PCI DSS 6.4.1 – Web Application Security", "PCI DSS 11.3.1 – External Penetration Testing"] },
  whatweb:     { discovery: "Identificação de tecnologias web: CMS, frameworks, bibliotecas JS, linguagens de servidor, versões e headers reveladores. Mapeia a stack tecnológica completa de cada endpoint.", mitre: [{ id: "T1592.002", name: "Gather Victim Host Information: Software" }, { id: "T1590.004", name: "Gather Victim Network Info: Network Topology" }], owasp: ["A05:2021 – Security Misconfiguration", "A06:2021 – Vulnerable and Outdated Components"], iso: ["ISO 27001 A.5.9 – Inventory of Assets"], cis: ["CIS 1 – Inventory and Control of Enterprise Assets", "CIS 4 – Secure Configuration of Enterprise Assets"], pci: ["PCI DSS 12.3.1 – Targeted Risk Analysis"] },
  "curl-probe": { discovery: "Sondagem HTTP manual de endpoints, análise de headers de segurança (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Permissions-Policy) e verificação de configurações de TLS/SSL.", mitre: [{ id: "T1590.005", name: "Gather Victim Network Info: IP Addresses" }, { id: "T1046", name: "Network Service Discovery" }], owasp: ["A05:2021 – Security Misconfiguration", "A02:2021 – Cryptographic Failures"], iso: ["ISO 27001 A.8.20 – Networks Security", "ISO 27001 A.8.24 – Use of Cryptography"], cis: ["CIS 4 – Secure Configuration of Enterprise Assets", "CIS 12 – Network Infrastructure Management"], pci: ["PCI DSS 4.2.1 – Strong Cryptography in Transit"] },
};

const TITLE_INTELLIGENCE = [
  { pattern: /sql.?inject/i, mitre: [{ id: "T1190", name: "Exploit Public-Facing Application" }], owasp: ["A03:2021 – Injection"], iso: ["ISO 27001 A.8.26 – Application Security Requirements", "ISO 27001 A.8.28 – Secure Coding"], cis: ["CIS 16 – Application Software Security"], pci: ["PCI DSS 6.2.4 – Software Engineering Techniques"], problem: "Injeção SQL permite que um atacante manipule consultas ao banco de dados enviando entrada não sanitizada. Pode resultar em exfiltração de dados, bypass de autenticação, modificação de registros e, em casos graves, execução de comandos no servidor de banco de dados.", impact: "Acesso não autorizado a dados sensíveis armazenados, possível escalação de privilégios e comprometimento total do banco de dados da aplicação." },
  { pattern: /xss|cross.?site.?script/i, mitre: [{ id: "T1059.007", name: "Command and Scripting Interpreter: JavaScript" }, { id: "T1185", name: "Browser Session Hijacking" }], owasp: ["A03:2021 – Injection"], iso: ["ISO 27001 A.8.26 – Application Security Requirements"], cis: ["CIS 16 – Application Software Security"], pci: ["PCI DSS 6.2.4 – Software Engineering Techniques"], problem: "Cross-Site Scripting (XSS) permite injeção de scripts maliciosos no contexto de outros usuários. Viabiliza roubo de sessão, keylogging, defacement e redirecionamento para sites maliciosos.", impact: "Comprometimento de sessões de usuários autenticados, roubo de credenciais e potencial movimentação lateral via contas privilegiadas capturadas." },
  { pattern: /rce|remote.?code|command.?inject/i, mitre: [{ id: "T1190", name: "Exploit Public-Facing Application" }, { id: "T1059", name: "Command and Scripting Interpreter" }], owasp: ["A03:2021 – Injection"], iso: ["ISO 27001 A.8.28 – Secure Coding", "ISO 27001 A.8.8 – Management of Technical Vulnerabilities"], cis: ["CIS 16 – Application Software Security", "CIS 7 – Continuous Vulnerability Management"], pci: ["PCI DSS 6.2.4 – Software Engineering Techniques", "PCI DSS 11.3.1 – External Penetration Testing"], problem: "Execução Remota de Código (RCE) é a vulnerabilidade de maior severidade: permite ao atacante executar comandos arbitrários no servidor sem autenticação. Uma única instância pode resultar em comprometimento total do ambiente.", impact: "Controle total do servidor comprometido, possibilidade de pivoting para redes internas, exfiltração de dados, instalação de backdoors e ransomware." },
  { pattern: /ssrf/i, mitre: [{ id: "T1090", name: "Proxy" }, { id: "T1046", name: "Network Service Discovery" }], owasp: ["A10:2021 – Server-Side Request Forgery"], iso: ["ISO 27001 A.8.20 – Networks Security", "ISO 27001 A.8.22 – Segregation of Networks"], cis: ["CIS 12 – Network Infrastructure Management", "CIS 16 – Application Software Security"], pci: ["PCI DSS 1.3.2 – Restricting Inbound/Outbound Traffic"], problem: "Server-Side Request Forgery (SSRF) força o servidor a fazer requisições para recursos internos ou externos em nome do atacante. Permite acesso a metadados de cloud (AWS IMDSv1, GCP metadata), serviços internos e bypass de firewall.", impact: "Acesso a instâncias de metadados cloud com credenciais IAM, enumeração de redes internas e potencial escalação para comprometimento da conta cloud." },
  { pattern: /idor|insecure.?direct.?object/i, mitre: [{ id: "T1078", name: "Valid Accounts" }, { id: "T1530", name: "Data from Cloud Storage" }], owasp: ["A01:2021 – Broken Access Control"], iso: ["ISO 27001 A.8.3 – Information Access Restriction", "ISO 27001 A.5.15 – Access Control"], cis: ["CIS 6 – Access Control Management"], pci: ["PCI DSS 7.2 – Access Control Systems", "PCI DSS 8.2 – User Identification and Authentication"], problem: "Insecure Direct Object Reference (IDOR) ocorre quando referências a objetos internos (IDs, nomes de arquivo) são expostas sem verificação de autorização. Permite acesso e manipulação de dados de outros usuários.", impact: "Acesso não autorizado a dados de outros usuários/clientes, possibilidade de modificar ou excluir registros alheios e violação de privacidade em larga escala." },
  { pattern: /subdomain.?takeover|dangling.?cname/i, mitre: [{ id: "T1584.001", name: "Compromise Infrastructure: Domains" }, { id: "T1608", name: "Stage Capabilities" }], owasp: ["A05:2021 – Security Misconfiguration"], iso: ["ISO 27001 A.5.9 – Inventory of Assets", "ISO 27001 A.8.9 – Configuration Management"], cis: ["CIS 1 – Inventory and Control of Enterprise Assets", "CIS 4 – Secure Configuration of Enterprise Assets"], pci: ["PCI DSS 12.3.1 – Targeted Risk Analysis"], problem: "Subdomain takeover ocorre quando um subdomínio aponta via CNAME para um serviço externo descontinuado que pode ser reivindicado por um atacante. O atacante passa a controlar o subdomínio legítimo da organização.", impact: "Subdomínio sob controle do atacante pode ser usado para phishing crível, roubo de cookies de sessão (same-site), distribuição de malware e engenharia social direcionada." },
  { pattern: /cve-/i, mitre: [{ id: "T1190", name: "Exploit Public-Facing Application" }, { id: "T1203", name: "Exploitation for Client Execution" }], owasp: ["A06:2021 – Vulnerable and Outdated Components"], iso: ["ISO 27001 A.8.8 – Management of Technical Vulnerabilities"], cis: ["CIS 7 – Continuous Vulnerability Management"], pci: ["PCI DSS 6.3.3 – Patch Management"], problem: "Componente com CVE publicada: a vulnerabilidade tem exploit documentado publicamente. Atacantes com acesso a bases como Exploit-DB ou Metasploit podem comprometer o alvo sem desenvolver técnicas próprias.", impact: "Exploração direta com ferramentas automáticas. Tempo de exposição (age) e EPSS score determinam a probabilidade de exploração ativa no ambiente." },
  { pattern: /open.?redirect/i, mitre: [{ id: "T1598", name: "Phishing for Information" }, { id: "T1566", name: "Phishing" }], owasp: ["A01:2021 – Broken Access Control"], iso: ["ISO 27001 A.8.26 – Application Security Requirements"], cis: ["CIS 16 – Application Software Security"], pci: ["PCI DSS 6.2.4 – Software Engineering Techniques"], problem: "Redirecionamento aberto permite usar URLs legítimas da organização como vetor de phishing. O domínio confiável serve como ponte para redirecionar vítimas a sites maliciosos.", impact: "Ataques de phishing de alta credibilidade usando o domínio da organização, bypass de filtros de e-mail e browsers que confiam no domínio original." },
  { pattern: /path.?travers|directory.?travers/i, mitre: [{ id: "T1083", name: "File and Directory Discovery" }, { id: "T1005", name: "Data from Local System" }], owasp: ["A01:2021 – Broken Access Control"], iso: ["ISO 27001 A.8.3 – Information Access Restriction"], cis: ["CIS 6 – Access Control Management", "CIS 16 – Application Software Security"], pci: ["PCI DSS 6.2.4 – Software Engineering Techniques"], problem: "Path traversal permite ao atacante ler arquivos arbitrários do servidor usando sequências como `../../`. Pode expor código-fonte, credenciais em arquivos de configuração e dados sensíveis.", impact: "Leitura de arquivos de sistema, chaves privadas, arquivos .env com credenciais e configurações de banco de dados diretamente do servidor." },
  { pattern: /xxe|xml.?external/i, mitre: [{ id: "T1190", name: "Exploit Public-Facing Application" }, { id: "T1005", name: "Data from Local System" }], owasp: ["A05:2021 – Security Misconfiguration"], iso: ["ISO 27001 A.8.26 – Application Security Requirements"], cis: ["CIS 16 – Application Software Security"], pci: ["PCI DSS 6.2.4 – Software Engineering Techniques"], problem: "XML External Entity (XXE) explora parsers XML mal configurados para ler arquivos locais ou realizar SSRF. Pode escalar para leitura de /etc/passwd, chaves SSH e exfiltração via DNS.", impact: "Exfiltração de arquivos sensíveis do sistema e potencial SSRF para acesso a serviços internos não expostos publicamente." },
  { pattern: /deseri[al]+iz/i, mitre: [{ id: "T1190", name: "Exploit Public-Facing Application" }, { id: "T1059", name: "Command and Scripting Interpreter" }], owasp: ["A08:2021 – Software and Data Integrity Failures"], iso: ["ISO 27001 A.8.28 – Secure Coding"], cis: ["CIS 16 – Application Software Security"], pci: ["PCI DSS 6.2.4 – Software Engineering Techniques"], problem: "Desserialização insegura de dados fornecidos pelo usuário pode levar a RCE, bypass de autenticação e denial of service. Payloads maliciosos são desserializados como objetos legítimos pela aplicação.", impact: "Execução arbitrária de código no servidor com as permissões da aplicação, potencial comprometimento total do sistema." },
  { pattern: /auth.?bypass|broken.?auth/i, mitre: [{ id: "T1078", name: "Valid Accounts" }, { id: "T1110", name: "Brute Force" }], owasp: ["A07:2021 – Identification and Authentication Failures"], iso: ["ISO 27001 A.5.15 – Access Control", "ISO 27001 A.8.2 – Privileged Access Rights"], cis: ["CIS 5 – Account Management", "CIS 6 – Access Control Management"], pci: ["PCI DSS 8.2 – User Identification and Authentication", "PCI DSS 8.4 – Multi-Factor Authentication"], problem: "Falha de autenticação permite acesso a recursos protegidos sem credenciais válidas. Pode ser por tokens JWT fracos, session fixation, lógica de verificação defeituosa ou exposição de endpoints administrativos.", impact: "Acesso não autorizado a painéis administrativos, dados de usuários e funcionalidades restritas — comprometimento direto de contas privilegiadas." },
  { pattern: /exposed|information.?disclosure|sensitive.?data/i, mitre: [{ id: "T1552", name: "Unsecured Credentials" }, { id: "T1005", name: "Data from Local System" }], owasp: ["A02:2021 – Cryptographic Failures"], iso: ["ISO 27001 A.8.12 – Data Leakage Prevention"], cis: ["CIS 3 – Data Protection"], pci: ["PCI DSS 3.5 – Protection of Stored Account Data"], problem: "Dados sensíveis expostos sem criptografia adequada ou controle de acesso: credenciais, PII, dados financeiros ou informações de configuração interna acessíveis sem autenticação.", impact: "Violação de privacidade de usuários/clientes, possível impacto regulatório (LGPD/GDPR) e uso das informações para preparar ataques mais sofisticados." },
  { pattern: /cors/i, mitre: [{ id: "T1185", name: "Browser Session Hijacking" }, { id: "T1539", name: "Steal Web Session Cookie" }], owasp: ["A05:2021 – Security Misconfiguration"], iso: ["ISO 27001 A.8.26 – Application Security Requirements"], cis: ["CIS 4 – Secure Configuration of Enterprise Assets", "CIS 16 – Application Software Security"], pci: ["PCI DSS 6.2.4 – Software Engineering Techniques"], problem: "Configuração CORS permissiva (origin: *) permite que sites maliciosos façam requisições autenticadas à API em nome de usuários logados, lendo respostas sensíveis que deveriam ser restritas por same-origin policy.", impact: "Exfiltração de dados autenticados via domínios maliciosos — o atacante usa o navegador da vítima como vetor de ataque contra a API." },
  { pattern: /csrf/i, mitre: [{ id: "T1185", name: "Browser Session Hijacking" }], owasp: ["A01:2021 – Broken Access Control"], iso: ["ISO 27001 A.8.26 – Application Security Requirements"], cis: ["CIS 16 – Application Software Security"], pci: ["PCI DSS 6.2.4 – Software Engineering Techniques"], problem: "Cross-Site Request Forgery (CSRF) força usuários autenticados a executar ações indesejadas. Sem tokens CSRF, um site malicioso pode submeter formulários ou chamadas de API em nome da vítima.", impact: "Ações não autorizadas executadas com a sessão da vítima: transferências, alterações de senha, modificações de configuração e exclusão de dados." },
  { pattern: /rate.?limit|brute.?force/i, mitre: [{ id: "T1110", name: "Brute Force" }, { id: "T1110.001", name: "Brute Force: Password Guessing" }], owasp: ["A07:2021 – Identification and Authentication Failures"], iso: ["ISO 27001 A.8.2 – Privileged Access Rights", "ISO 27001 A.5.15 – Access Control"], cis: ["CIS 5 – Account Management"], pci: ["PCI DSS 8.3 – Protect Individual Non-Consumer User Accounts"], problem: "Ausência de rate limiting permite tentativas ilimitadas de brute force em endpoints de autenticação. Um atacante pode automatizar tentativas de senha contra contas de usuário sem bloqueio ou detecção.", impact: "Comprometimento de contas via password spraying, credential stuffing com listas de vazamentos públicos ou dicionários especializados." },
  { pattern: /secret|token|api.?key|credential/i, mitre: [{ id: "T1552", name: "Unsecured Credentials" }, { id: "T1078", name: "Valid Accounts" }], owasp: ["A02:2021 – Cryptographic Failures", "A07:2021 – Identification and Authentication Failures"], iso: ["ISO 27001 A.8.13 – Information Backup", "ISO 27001 A.8.24 – Use of Cryptography"], cis: ["CIS 3 – Data Protection", "CIS 5 – Account Management"], pci: ["PCI DSS 3.5 – Protection of Stored Account Data"], problem: "Credenciais ou tokens de API expostos publicamente (em repositórios, responses HTTP ou arquivos de configuração acessíveis). Permitem acesso direto a serviços e plataformas com o nível de privilégio do token.", impact: "Acesso a serviços cloud, APIs de terceiros e sistemas internos com as permissões do token comprometido — potencial exfiltração massiva de dados e custos indevidos em cloud." },
  { pattern: /header|hsts|csp|x-frame|content.?security/i, mitre: [{ id: "T1185", name: "Browser Session Hijacking" }], owasp: ["A05:2021 – Security Misconfiguration"], iso: ["ISO 27001 A.8.20 – Networks Security"], cis: ["CIS 4 – Secure Configuration of Enterprise Assets"], pci: ["PCI DSS 6.2.4 – Software Engineering Techniques"], problem: "Headers de segurança HTTP ausentes ou mal configurados: HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy e Permissions-Policy. Cada header ausente abre um vetor de ataque específico.", impact: "Exposição a clickjacking, injeção de conteúdo via MIME sniffing, downgrade de HTTPS e ataques de injeção de scripts em contexto de conteúdo misto." },
  { pattern: /open.?port|exposed.?service|servi[çc]o.?exposto/i, mitre: [{ id: "T1046", name: "Network Service Discovery" }, { id: "T1133", name: "External Remote Services" }], owasp: ["A05:2021 – Security Misconfiguration"], iso: ["ISO 27001 A.8.20 – Networks Security", "ISO 27001 A.8.22 – Segregation of Networks"], cis: ["CIS 12 – Network Infrastructure Management"], pci: ["PCI DSS 1.2 – Configuration Standards for All Network Components"], problem: "Serviço de rede exposto publicamente que deveria ser acessível apenas internamente. Portas de administração, bancos de dados, cache e serviços de monitoramento expostos na Internet aumentam drasticamente a superfície de ataque.", impact: "Acesso direto a serviços internos por qualquer IP na Internet, podendo incluir bases de dados, serviços de mensageria e painéis de administração sem camada adicional de proteção." },
  { pattern: /ssl|tls|certif/i, mitre: [{ id: "T1557", name: "Adversary-in-the-Middle" }, { id: "T1040", name: "Network Sniffing" }], owasp: ["A02:2021 – Cryptographic Failures"], iso: ["ISO 27001 A.8.24 – Use of Cryptography"], cis: ["CIS 4 – Secure Configuration of Enterprise Assets", "CIS 12 – Network Infrastructure Management"], pci: ["PCI DSS 4.2.1 – Strong Cryptography in Transit"], problem: "Configuração TLS/SSL fraca ou certificado inválido/expirado: suporte a protocolos obsoletos (SSLv3, TLS 1.0/1.1), cipher suites fracas ou certificado autoassinado sem validação.", impact: "Tráfego sensível pode ser interceptado em ataques MITM, downgrade de protocolo ou decriptação retroativa de sessões capturadas." },
];

function deriveIntelligence(item) {
  const details = (item?.details && typeof item.details === "object") ? item.details : {};
  const repro = (details.reproduction && typeof details.reproduction === "object") ? details.reproduction : {};
  const tool = String(item.tool || details.tool || details.source_tool || "").toLowerCase().replace(/-/g, "").replace(/_/g, "");
  const title = String(item.title || "").toLowerCase();

  // Use backend data when available
  const backendMitre = Array.isArray(details.mitre_attack) ? details.mitre_attack : [];
  const backendOwasp = Array.isArray(details.owasp_top10) ? details.owasp_top10 : [];
  const backendIso = Array.isArray(details.iso27001) ? details.iso27001 : [];
  const backendCis = Array.isArray(details.cis_controls) ? details.cis_controls : [];
  const backendPci = Array.isArray(details.pci_dss) ? details.pci_dss : [];

  // Find best tool match
  const toolKey = Object.keys(TOOL_INTELLIGENCE).find((k) => tool.includes(k.replace(/-/g, "").replace(/_/g, "")));
  const toolIntel = toolKey ? TOOL_INTELLIGENCE[toolKey] : null;

  // Find best title pattern match
  const titleIntel = TITLE_INTELLIGENCE.find((t) => t.pattern.test(title));

  const mitre = backendMitre.length > 0 ? backendMitre : (titleIntel?.mitre || toolIntel?.mitre || []);
  const owasp = backendOwasp.length > 0 ? backendOwasp : (titleIntel?.owasp || toolIntel?.owasp || []);
  const iso = backendIso.length > 0 ? backendIso : (titleIntel?.iso || toolIntel?.iso || []);
  const cis = backendCis.length > 0 ? backendCis : (titleIntel?.cis || toolIntel?.cis || []);
  const pci = backendPci.length > 0 ? backendPci : (titleIntel?.pci || toolIntel?.pci || []);

  const discoveryMethod = repro.discovery_method
    || details.discovery_method
    || toolIntel?.discovery
    || "";

  const realProblem = repro.problem_description
    || details.problem_description
    || item.cve_description
    || details.cve_description
    || details.description
    || titleIntel?.problem
    || "";

  const envImpact = repro.environment_impact
    || details.environment_impact
    || (titleIntel?.impact ? `${titleIntel.impact} Alvo afetado: ${String(item.target_query || details.asset || "").split(",")[0] || "escopo do scan"}.` : "")
    || "";

  return { mitre, owasp, iso, cis, pci, discoveryMethod, realProblem, envImpact };
}

function locationForFinding(item) {
  const details = item?.details && typeof item.details === "object" ? item.details : {};
  const nested = details.details && typeof details.details === "object" ? details.details : {};
  const primary = sanitizeText(
    item?.url
    || item?.subdomain
    || item?.target
    || details.url
    || details.request_url
    || details.target_url
    || details.endpoint
    || details["matched-at"]
    || details.matched_at
    || details.subdomain
    || details.hostname
    || details.host
    || details.asset
    || nested.url
    || nested.request_url
    || nested.target_url
    || nested.endpoint
    || nested["matched-at"]
    || nested.matched_at
    || nested.subdomain
    || nested.hostname
    || nested.host
    || nested.asset
    || item?.domain
    || item?.target_query
  );
  const scanTarget = sanitizeText(item?.target_query || "");
  const secondary = scanTarget && scanTarget !== primary ? scanTarget : "";
  return { primary: primary || "—", secondary };
}


// ── Verification status config ────────────────────────────────────────────────
const VSTATUS_CFG = {
  confirmed:  { label: "✅ Confirmado",  color: "#15803d", bg: "#dcfce7", title: "Ferramenta provou a condição diretamente" },
  candidate:  { label: "⚠️ Candidato",   color: "#b45309", bg: "#fef3c7", title: "Precisa de verificação secundária" },
  hypothesis: { label: "💭 Hipótese",    color: "#6b7280", bg: "var(--surface-soft)", title: "Correlação passiva — não testou a condição" },
  refuted:    { label: "❌ Refutado",    color: "#dc2626", bg: "#fee2e2", title: "Verificação concluiu que é falso positivo" },
};

function VerificationBadge({ status }) {
  const cfg = VSTATUS_CFG[status];
  if (!cfg) return null;
  return (
    <span title={cfg.title} style={{
      display: "inline-flex", alignItems: "center",
      padding: "2px 7px", borderRadius: 4, fontSize: 10.5,
      fontWeight: 600, color: cfg.color, background: cfg.bg,
      whiteSpace: "nowrap",
    }}>
      {cfg.label}
    </span>
  );
}

export default function VulnerabilitiesPage() {
  const [rows, setRows] = useState([]);
  const [targets, setTargets] = useState([]);
  const [scans, setScans] = useState([]);
  const [page, setPage] = useState({ total: 0, limit: 50, offset: 0 });
  const [severityCounts, setSeverityCounts] = useState({ critical: 0, high: 0, medium: 0, low: 0, info: 0 });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [severitiesFilter, setSeveritiesFilter] = useState([...SEVERITIES]);
  const [statusFilter, setStatusFilter] = useState("open");
  const [targetQuery, setTargetQuery] = useState("");
  const [scanFilter, setScanFilter] = useState("");
  const [sortMode, setSortMode] = useState("severity");
  const [expandedId, setExpandedId] = useState(null);
  // New: verification status filter — null = all, otherwise "confirmed"|"candidate"|"hypothesis"
  const [vstatus, setVstatus] = useState(null);

  const loadTargets = async () => {
    try {
      const { data } = await client.get("/api/targets/summary");
      setTargets((Array.isArray(data) ? data : []).map((t) => t.target).sort());
    } catch (err) {
      console.error("Falha ao carregar targets:", err);
    }
  };

  const loadScans = async () => {
    try {
      const { data } = await client.get("/api/scans", { params: { limit: 300 } });
      setScans(Array.isArray(data) ? data : []);
    } catch (err) {
      console.error("Falha ao carregar scans:", err);
    }
  };

  const load = async () => {
    setLoading(true);
    setError("");
    try {
      const params = {
        status_filter: statusFilter,
        sort: sortMode,
        limit: page.limit,
        offset: page.offset,
      };
      if (severitiesFilter.length > 0 && severitiesFilter.length < 5) {
        params.severity = severitiesFilter.join(",");
      }
      if (targetQuery.trim()) params.target = targetQuery.trim();
      if (scanFilter) params.scan_id = scanFilter;
      if (vstatus) params.verification_status = vstatus;

      const { data } = await client.get("/api/findings/page", { params });
      const items = Array.isArray(data?.items) ? data.items : [];
      setRows(items);
      setPage((prev) => ({ ...prev, total: Number(data?.total || 0) }));
      // Totais reais de severidade (todos os resultados, não só a página atual)
      if (data?.severity_counts && typeof data.severity_counts === "object") {
        setSeverityCounts({
          critical: Number(data.severity_counts.critical || 0),
          high:     Number(data.severity_counts.high     || 0),
          medium:   Number(data.severity_counts.medium   || 0),
          low:      Number(data.severity_counts.low      || 0),
          info:     Number(data.severity_counts.info     || 0),
        });
      }
    } catch (err) {
      setError(err?.response?.data?.detail || "Falha ao carregar vulnerabilidades.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadTargets();
    loadScans();
  }, []);

  useEffect(() => {
    setPage((p) => ({ ...p, offset: 0 }));
  }, [severitiesFilter, statusFilter, targetQuery, scanFilter, sortMode, vstatus]);

  useEffect(() => {
    load();
  }, [severitiesFilter, statusFilter, page.offset, targetQuery, scanFilter, sortMode, vstatus]);

  const hasPrev = page.offset > 0;
  const hasNext = page.offset + page.limit < page.total;

  // counts = totais reais vindos do backend (todos os resultados do filtro atual, não só a página)
  const counts = severityCounts;

  const toggleSeverity = (sev) => {
    setSeveritiesFilter((prev) => (prev.includes(sev) ? prev.filter((s) => s !== sev) : [...prev, sev]));
  };

  return (
    <main className="dpage">
      {/* KPI strip — severity breakdown of the current page */}
      <section className="grid-4" style={{ marginBottom: 22, gridTemplateColumns: "repeat(5, 1fr)" }}>
        {SEVERITIES.map((sev) => (
          <div key={sev} className="kpi">
            <div className="k">{sev}</div>
            <div
              className="v"
              style={{
                color:
                  sev === "critical" ? "var(--sev-critical-text)"
                  : sev === "high" ? "var(--sev-high-text)"
                  : sev === "medium" ? "var(--sev-medium-text)"
                  : sev === "low" ? "var(--sev-low-text)"
                  : "var(--sev-info-text)",
              }}
            >
              {counts[sev]}
            </div>
            <div className="hint">nesta página</div>
          </div>
        ))}
      </section>

      {error && <div className="err-box" style={{ marginBottom: 16 }}>{error}</div>}

      {/* Findings table */}
      <section className="t-wrap">
        <div className="t-head">
          <div>
            <h3>Vulnerabilidades</h3>
            <div className="sub">base real de findings coletados pelos scans · severidade, FAIR e AGE</div>
          </div>
          <div className="t-tools">
            <select value={targetQuery} onChange={(e) => setTargetQuery(e.target.value)}
              style={{ padding: "8px 12px", borderRadius: 8, border: "1px solid var(--line)", fontSize: 12.5, background: "var(--canvas)" }}>
              <option value="">Todos os targets</option>
              {targets.map((t) => <option key={t} value={t}>{t}</option>)}
            </select>
            <select value={scanFilter} onChange={(e) => setScanFilter(e.target.value)}
              style={{ padding: "8px 12px", borderRadius: 8, border: "1px solid var(--line)", fontSize: 12.5, background: "var(--canvas)", maxWidth: 220 }}>
              <option value="">Todos os scans</option>
              {scans.map((scan) => (
                <option key={scan.id} value={scan.id}>
                  #{scan.id} · {String(scan.target_query || "(sem alvo)").slice(0, 40)}
                </option>
              ))}
            </select>
            <select value={statusFilter} onChange={(e) => setStatusFilter(e.target.value)}
              style={{ padding: "8px 12px", borderRadius: 8, border: "1px solid var(--line)", fontSize: 12.5, background: "var(--canvas)" }}>
              <option value="open">Abertas</option>
              <option value="closed">Fechadas</option>
              <option value="false_positive">Falsos positivos</option>
              <option value="all">Todas</option>
            </select>
            <select value={sortMode} onChange={(e) => setSortMode(e.target.value)}
              style={{ padding: "8px 12px", borderRadius: 8, border: "1px solid var(--line)", fontSize: 12.5, background: "var(--canvas)" }}>
              <option value="severity">Ordenar por risco</option>
              <option value="date_desc">Mais recentes</option>
              <option value="date_asc">Mais antigas</option>
              <option value="scan_desc">Scan mais novo</option>
              <option value="scan_asc">Scan mais antigo</option>
              <option value="target">Alvo</option>
              <option value="tool">Ferramenta</option>
            </select>
          </div>
        </div>

        {/* Severity filter chips */}
        <div style={{ display: "flex", gap: 8, padding: "14px 22px", borderBottom: "1px solid var(--line)", flexWrap: "wrap" }}>
          {SEVERITIES.map((sev) => {
            const on = severitiesFilter.includes(sev);
            return (
              <button
                key={sev}
                onClick={() => toggleSeverity(sev)}
                className={`b ${SEV_CLASS[sev]}`}
                style={{ cursor: "pointer", opacity: on ? 1 : 0.4, textTransform: "none", padding: "5px 11px" }}
              >
                {sev} · {counts[sev]}
              </button>
            );
          })}
        </div>

        {/* ── Verification status filter ─────────────────────────────────── */}
        <div style={{ display: "flex", gap: 8, padding: "10px 22px", borderBottom: "1px solid var(--line)", flexWrap: "wrap", alignItems: "center" }}>
          <span style={{ fontSize: 11, color: "var(--ink-muted)", fontWeight: 600, letterSpacing: "0.05em", textTransform: "uppercase", marginRight: 4 }}>
            Verificação
          </span>
          {[null, "confirmed", "candidate", "hypothesis"].map((v) => {
            const cfg = v ? VSTATUS_CFG[v] : null;
            const label = cfg ? cfg.label : "Todas";
            const active = vstatus === v;
            return (
              <button
                key={v ?? "all"}
                onClick={() => setVstatus(v)}
                style={{
                  padding: "4px 10px", borderRadius: 20, fontSize: 11.5, fontWeight: active ? 700 : 500,
                  border: active ? `1.5px solid ${cfg?.color || "var(--brand-500)"}` : "1px solid var(--line)",
                  background: active ? (cfg?.bg || "var(--brand-50)") : "transparent",
                  color: active ? (cfg?.color || "var(--brand-700)") : "var(--ink-muted)",
                  cursor: "pointer",
                }}
              >
                {label}
              </button>
            );
          })}
        </div>

        {loading && (
          <div className="state"><div><div className="spin" /><p className="st-title">Carregando vulnerabilidades…</p></div></div>
        )}
        {!loading && rows.length === 0 && <div className="empty">Nenhuma vulnerabilidade para os filtros atuais.</div>}

        {!loading && rows.length > 0 && (
          <div style={{ overflowX: "auto" }}>
            <table className="t">
              <thead>
                <tr>
                  <th>ID</th>
                  <th>Scan</th>
                  <th>Vulnerabilidade</th>
                  <th>CVE</th>
                  <th>CVSS</th>
                  <th>Severidade</th>
                  <th>Verificação</th>
                  <th>Alvo</th>
                  <th>Ferramenta</th>
                  <th>Data</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((item) => {
                  const isExpanded = expandedId === item.id;
                  const repro = item.details?.reproduction || {};
                  const toolEvidence = Array.isArray(item.details?.tool_evidence) ? item.details.tool_evidence : [];
                  const location = locationForFinding(item);
                  const intel = isExpanded ? deriveIntelligence(item) : null;
                  return (
                    <Fragment key={item.id}>
                    <tr onClick={() => setExpandedId(isExpanded ? null : item.id)} style={{ cursor: "pointer" }}>
                      <td className="mono-id">{isExpanded ? "▼ " : "▶ "}{item.id}</td>
                      <td className="mono-sm" style={{ color: "var(--brand-700)" }}>#{item.scan_job_id || "—"}</td>
                      <td style={{ maxWidth: 260 }}>
                        <div style={{ fontWeight: 600, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                          {sanitizeText(item.title)}
                        </div>
                        {item.url && (
                          <div style={{ fontSize: 10.5, color: "var(--ink-muted)", marginTop: 2, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                            🔗 {item.url}
                          </div>
                        )}
                      </td>
                      <td className="mono-sm" style={{ minWidth: 160 }}>
                        {item.cve ? (
                          <>
                            <div style={{ color: "var(--sev-info-text)", fontWeight: 600 }}>{item.cve}</div>
                            {(item.cve_description || item.details?.cve_description || item.details?.description) && (
                              <div style={{ color: "var(--ink-muted)", fontSize: 11, marginTop: 2, maxWidth: 220, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                                {String(item.cve_description || item.details?.cve_description || item.details?.description || "").slice(0, 80)}
                              </div>
                            )}
                          </>
                        ) : "—"}
                      </td>
                      <td className="mono-sm" style={{ color: "var(--sev-medium-text)" }}>
                        {item.cvss != null ? Number(item.cvss).toFixed(1) : "—"}
                      </td>
                      <td>
                        <span className={`b ${SEV_CLASS[item.severity] || "b-low"}`}>{item.severity}</span>
                        {/* Business impact: show adjusted vs base score when different */}
                        {item.details?.adjusted_risk_score != null && item.details?.base_risk_score != null &&
                         item.details.adjusted_risk_score !== item.details.base_risk_score && (
                          <div style={{ fontSize: 10, color: "var(--ink-muted)", marginTop: 2 }}>
                            risco {item.details.base_risk_score}→<b style={{ color: "var(--sev-high-text)" }}>{item.details.adjusted_risk_score}</b>
                          </div>
                        )}
                      </td>
                      <td>
                        <VerificationBadge status={item.verification_status} />
                        {/* Stage-2 verification pending indicator */}
                        {item.details?.needs_verification && item.verification_status !== "confirmed" && (
                          <div style={{ fontSize: 9.5, color: "var(--ink-muted)", marginTop: 2 }}>verificação pendente</div>
                        )}
                      </td>
                      <td className="mono-sm" style={{ minWidth: 200, wordBreak: "break-all" }}>
                        <div style={{ fontWeight: 650 }}>
                          {location.primary}
                        </div>
                        {location.secondary && (
                          <div className="muted">
                            scan: {location.secondary}
                          </div>
                        )}
                      </td>
                      <td className="mono-sm" style={{ color: "var(--brand-700)" }}>{item.tool || item.details?.tool || "—"}</td>
                      <td className="mono-sm muted" style={{ whiteSpace: "nowrap" }}>
                        {item.created_at ? new Date(item.created_at).toLocaleDateString("pt-BR") : "—"}
                      </td>
                    </tr>
                    {isExpanded && intel && (
                      <tr>
                        <td colSpan={10} style={{ background: "var(--canvas)", padding: "20px 24px" }}>
                          <div style={{ display: "flex", flexDirection: "column", gap: 18, fontSize: 13 }}>

                            {/* ── Uso do aprendizado HackerOne (P3b) ────────── */}
                            {item.details?.learning_source && (
                              <div style={{ background: "linear-gradient(135deg,#0f172a,#1e1b4b)", borderRadius: 8, padding: "10px 14px", color: "#e2e8f0" }}>
                                <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
                                  <span style={{ fontSize: 12, fontWeight: 700, color: "#a5b4fc" }}>🧠 Aprendizado HackerOne aplicado</span>
                                  {Array.isArray(item.details.learning_source.tech_stack) && item.details.learning_source.tech_stack.length > 0 && (
                                    <span style={{ fontSize: 10.5, color: "#c7d2fe" }}>
                                      stack: {item.details.learning_source.tech_stack.slice(0, 4).join(", ")}
                                    </span>
                                  )}
                                </div>
                                <div style={{ fontSize: 11, color: "#cbd5e1", marginTop: 4, lineHeight: 1.5 }}>
                                  {item.details.learning_source.rationale || "Técnica priorizada com base em reports HackerOne reais para o stack detectado."}
                                </div>
                              </div>
                            )}

                            {/* ── Evidence gate + Business impact ────────────── */}
                            {(item.verification_status || item.details?.impact_reason || item.url) && (
                              <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
                                {item.verification_status && (
                                  <div style={{ background: VSTATUS_CFG[item.verification_status]?.bg || "var(--canvas-soft)", borderRadius: 8, padding: "8px 14px", minWidth: 160 }}>
                                    <div style={{ fontSize: 10.5, fontWeight: 700, color: "var(--ink-muted)", textTransform: "uppercase", marginBottom: 4 }}>Status de Verificação</div>
                                    <VerificationBadge status={item.verification_status} />
                                    {item.details?.verified_by && (
                                      <div style={{ fontSize: 10.5, color: "var(--ink-muted)", marginTop: 4 }}>por: {item.details.verified_by}</div>
                                    )}
                                    {item.details?.verification_note && item.verification_status !== "confirmed" && (
                                      <div style={{ fontSize: 10.5, color: "var(--ink-muted)", marginTop: 4, maxWidth: 260, lineHeight: 1.4 }}>{item.details.verification_note}</div>
                                    )}
                                    {item.details?.oob_callback && (
                                      <div style={{ fontSize: 10.5, color: "var(--sev-low-text)", marginTop: 4 }}>
                                        🔗 OOB callback: {item.details.oob_callback.protocol} de {item.details.oob_callback.remote_address}
                                      </div>
                                    )}
                                  </div>
                                )}
                                {item.url && (
                                  <div style={{ background: "var(--canvas-soft)", borderRadius: 8, padding: "8px 14px", flex: 1, minWidth: 200 }}>
                                    <div style={{ fontSize: 10.5, fontWeight: 700, color: "var(--ink-muted)", textTransform: "uppercase", marginBottom: 4 }}>Endpoint Afetado</div>
                                    <div style={{ fontFamily: "var(--font-mono)", fontSize: 12, wordBreak: "break-all", color: "var(--brand-700)" }}>{item.url}</div>
                                    {item.details?.impact_reason && item.details?.impact_reason !== "padrão" && (
                                      <div style={{ fontSize: 10.5, color: "var(--ink-muted)", marginTop: 4 }}>impacto: {item.details.impact_reason}</div>
                                    )}
                                    {item.details?.score_adjustment && (
                                      <div style={{ fontSize: 10.5, color: "var(--sev-high-text)", marginTop: 2 }}>score: {item.details.score_adjustment}</div>
                                    )}
                                  </div>
                                )}
                              </div>
                            )}

                            {/* ── How it was discovered ─────────────────────── */}
                            <div style={{ borderLeft: "3px solid var(--brand-500)", paddingLeft: 12 }}>
                              <div style={{ fontWeight: 700, marginBottom: 6, color: "var(--brand-700)", fontSize: 12, textTransform: "uppercase", letterSpacing: "0.06em" }}>Como foi descoberto</div>
                              <div style={{ lineHeight: 1.6, color: "var(--ink-soft)" }}>{intel.discoveryMethod || repro.discovery_method || "—"}</div>
                            </div>

                            {/* ── Real problem ──────────────────────────────── */}
                            {intel.realProblem && (
                              <div style={{ borderLeft: "3px solid var(--sev-high-text)", paddingLeft: 12 }}>
                                <div style={{ fontWeight: 700, marginBottom: 6, color: "var(--sev-high-text)", fontSize: 12, textTransform: "uppercase", letterSpacing: "0.06em" }}>O problema real</div>
                                <div style={{ lineHeight: 1.6, color: "var(--ink-soft)" }}>{intel.realProblem}</div>
                              </div>
                            )}

                            {/* ── Environment impact ────────────────────────── */}
                            {intel.envImpact && (
                              <div style={{ borderLeft: "3px solid var(--sev-critical-text)", paddingLeft: 12 }}>
                                <div style={{ fontWeight: 700, marginBottom: 6, color: "var(--sev-critical-text)", fontSize: 12, textTransform: "uppercase", letterSpacing: "0.06em" }}>Impacto no ambiente</div>
                                <div style={{ lineHeight: 1.6, color: "var(--ink-soft)" }}>{intel.envImpact}</div>
                              </div>
                            )}

                            {/* ── Standards & frameworks ────────────────────── */}
                            {(intel.mitre.length > 0 || intel.owasp.length > 0 || intel.iso.length > 0 || intel.cis.length > 0 || intel.pci.length > 0) && (
                              <div>
                                <div style={{ fontWeight: 700, marginBottom: 8, color: "var(--ink-soft)", fontSize: 12, textTransform: "uppercase", letterSpacing: "0.06em" }}>Índices de referência</div>
                                <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                                  {intel.mitre.length > 0 && (
                                    <div style={{ display: "flex", gap: 6, alignItems: "flex-start", flexWrap: "wrap" }}>
                                      <span style={{ fontSize: 11, fontWeight: 700, color: "var(--ink-muted)", minWidth: 52, paddingTop: 3 }}>MITRE</span>
                                      <div style={{ display: "flex", gap: 5, flexWrap: "wrap" }}>
                                        {intel.mitre.map((m) => (
                                          <span key={m.id || m} className="b b-info" style={{ textTransform: "none", fontSize: 11 }}>
                                            {m.id ? `${m.id} · ${m.name}` : m}
                                          </span>
                                        ))}
                                      </div>
                                    </div>
                                  )}
                                  {intel.owasp.length > 0 && (
                                    <div style={{ display: "flex", gap: 6, alignItems: "flex-start", flexWrap: "wrap" }}>
                                      <span style={{ fontSize: 11, fontWeight: 700, color: "var(--ink-muted)", minWidth: 52, paddingTop: 3 }}>OWASP</span>
                                      <div style={{ display: "flex", gap: 5, flexWrap: "wrap" }}>
                                        {intel.owasp.map((o) => (
                                          <span key={o} className="b b-medium" style={{ textTransform: "none", fontSize: 11 }}>{o}</span>
                                        ))}
                                      </div>
                                    </div>
                                  )}
                                  {intel.iso.length > 0 && (
                                    <div style={{ display: "flex", gap: 6, alignItems: "flex-start", flexWrap: "wrap" }}>
                                      <span style={{ fontSize: 11, fontWeight: 700, color: "var(--ink-muted)", minWidth: 52, paddingTop: 3 }}>ISO 27001</span>
                                      <div style={{ display: "flex", gap: 5, flexWrap: "wrap" }}>
                                        {intel.iso.map((s) => (
                                          <span key={s} className="b b-neutral" style={{ textTransform: "none", fontSize: 11 }}>{s}</span>
                                        ))}
                                      </div>
                                    </div>
                                  )}
                                  {intel.cis.length > 0 && (
                                    <div style={{ display: "flex", gap: 6, alignItems: "flex-start", flexWrap: "wrap" }}>
                                      <span style={{ fontSize: 11, fontWeight: 700, color: "var(--ink-muted)", minWidth: 52, paddingTop: 3 }}>CIS</span>
                                      <div style={{ display: "flex", gap: 5, flexWrap: "wrap" }}>
                                        {intel.cis.map((s) => (
                                          <span key={s} className="b b-neutral" style={{ textTransform: "none", fontSize: 11 }}>{s}</span>
                                        ))}
                                      </div>
                                    </div>
                                  )}
                                  {intel.pci.length > 0 && (
                                    <div style={{ display: "flex", gap: 6, alignItems: "flex-start", flexWrap: "wrap" }}>
                                      <span style={{ fontSize: 11, fontWeight: 700, color: "var(--ink-muted)", minWidth: 52, paddingTop: 3 }}>PCI DSS</span>
                                      <div style={{ display: "flex", gap: 5, flexWrap: "wrap" }}>
                                        {intel.pci.map((s) => (
                                          <span key={s} className="b b-neutral" style={{ textTransform: "none", fontSize: 11 }}>{s}</span>
                                        ))}
                                      </div>
                                    </div>
                                  )}
                                </div>
                              </div>
                            )}

                            {/* ── Commands ──────────────────────────────────── */}
                            {Array.isArray(repro.commands) && repro.commands.length > 0 && (
                              <div>
                                <div style={{ fontWeight: 700, marginBottom: 4, color: "var(--brand-700)", fontSize: 12, textTransform: "uppercase", letterSpacing: "0.06em" }}>Comandos executados</div>
                                {repro.commands.map((c, i) => (
                                  <pre key={i} style={{ background: "var(--ink)", color: "#9fe8b0", padding: "8px 10px", borderRadius: 6, overflowX: "auto", margin: "3px 0", fontSize: 12 }}>
                                    $ {sanitizeText(c.command)}
                                  </pre>
                                ))}
                              </div>
                            )}

                            {/* ── Payloads ──────────────────────────────────── */}
                            {Array.isArray(repro.payloads) && repro.payloads.length > 0 && (
                              <div>
                                <div style={{ fontWeight: 700, marginBottom: 4, color: "var(--sev-high-text)", fontSize: 12, textTransform: "uppercase", letterSpacing: "0.06em" }}>Payloads para replicação</div>
                                {repro.payloads.map((p, i) => (
                                  <pre key={i} style={{ background: "var(--ink)", color: "#ffd479", padding: "6px 10px", borderRadius: 6, overflowX: "auto", margin: "3px 0", fontSize: 12 }}>
                                    {sanitizeText(p)}
                                  </pre>
                                ))}
                              </div>
                            )}

                            {/* ── Proof ─────────────────────────────────────── */}
                            {Array.isArray(repro.proof) && repro.proof.length > 0 && (
                              <div>
                                <div style={{ fontWeight: 700, marginBottom: 4, color: "var(--brand-700)", fontSize: 12, textTransform: "uppercase", letterSpacing: "0.06em" }}>Evidência (saída real das ferramentas)</div>
                                {repro.proof.map((pr, i) => (
                                  <div key={i} style={{ marginBottom: 6 }}>
                                    <div className="mono-sm muted">{sanitizeText(pr.tool)}: {sanitizeText(pr.summary)}</div>
                                    <pre style={{ background: "var(--ink)", color: "#c8d4e0", padding: "8px 10px", borderRadius: 6, overflowX: "auto", maxHeight: 220, margin: "3px 0", fontSize: 11 }}>
                                      {sanitizeText(pr.output)}
                                    </pre>
                                  </div>
                                ))}
                              </div>
                            )}

                            {/* ── Reproduction steps ────────────────────────── */}
                            {Array.isArray(repro.steps) && repro.steps.length > 0 && (
                              <div>
                                <div style={{ fontWeight: 700, marginBottom: 4, color: "var(--brand-700)", fontSize: 12, textTransform: "uppercase", letterSpacing: "0.06em" }}>Passos para reproduzir</div>
                                <ol style={{ margin: 0, paddingLeft: 20 }}>
                                  {repro.steps.map((s, i) => <li key={i} className="mono-sm" style={{ marginBottom: 3 }}>{sanitizeText(s).replace(/^\d+\.\s*/, "")}</li>)}
                                </ol>
                              </div>
                            )}

                            {/* ── Recommendation ────────────────────────────── */}
                            {item.recommendation && (
                              <div style={{ borderLeft: "3px solid var(--sev-low-text)", paddingLeft: 12 }}>
                                <div style={{ fontWeight: 700, marginBottom: 6, color: "var(--sev-low-text)", fontSize: 12, textTransform: "uppercase", letterSpacing: "0.06em" }}>Recomendação</div>
                                <div style={{ lineHeight: 1.6 }} className="mono-sm">{sanitizeText(item.recommendation)}</div>
                              </div>
                            )}

                            {/* ── Tool evidence fallback ────────────────────── */}
                            {(!repro.commands || repro.commands.length === 0) && toolEvidence.length > 0 && (
                              <div>
                                <div style={{ fontWeight: 700, marginBottom: 4, fontSize: 12, textTransform: "uppercase", letterSpacing: "0.06em" }}>Evidência por ferramenta</div>
                                {toolEvidence.map((te, i) => (
                                  <div key={i} className="mono-sm" style={{ marginBottom: 3 }}>
                                    <strong>{sanitizeText(te.tool)}</strong>: {sanitizeText(te.finding_summary || "")}
                                  </div>
                                ))}
                              </div>
                            )}

                            {repro.verifiable === false && (
                              <div className="mono-sm muted">Esta fase executou cobertura mas não produziu evidência verificável.</div>
                            )}
                          </div>
                        </td>
                      </tr>
                    )}
                    </Fragment>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}

        <div className="pag">
          <div>Mostrando <b>{rows.length}</b> de <b>{page.total}</b> findings</div>
          <div className="nav">
            <button disabled={!hasPrev} onClick={() => setPage((p) => ({ ...p, offset: Math.max(0, p.offset - p.limit) }))}>‹</button>
            <button disabled={!hasNext} onClick={() => setPage((p) => ({ ...p, offset: p.offset + p.limit }))}>›</button>
          </div>
        </div>
      </section>
    </main>
  );
}
