"""
attack_graph.py — Construção automática de grafo de ataque e kill chains.

Dado o conjunto de findings de um scan, constrói:
  1. Um grafo direcionado onde nós são assets/capabilities e edges são
     relações de exploração (finding A habilita finding B)
  2. Paths de menor resistência: internet → dado sensível
  3. Kill chains no formato MITRE ATT&CK
  4. Score de risco composto: não apenas severidade individual,
     mas o valor do CAMINHO até o ativo crítico

Modelo de grafo:
  - Nó INTERNET (source)
  - Nós de CAPABILITY gerados por cada finding (ex: "rce_via_path_traversal")
  - Nós de ASSET crítico (ex: "banco_de_dados", "container_runtime", "admin_ui")
  - Nó DATA_EXFIL (sink)

Edges:
  - INTERNET → capability (quando o finding é diretamente explorável sem pre-requisito)
  - capability_A → capability_B (quando A habilita B — ex: info_disclosure → rce)
  - capability → ASSET (quando a capability compromete o ativo)
  - ASSET → DATA_EXFIL (quando o ativo contém dados sensíveis)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# Mapeamento finding → capability gerada
# ─────────────────────────────────────────────────────────────────────────────

# Cada regra: (padrão no título/tipo, capability gerada, pre_requires, unlocks)
# pre_requires: capabilities que precisam existir no mesmo target para esta edge ser válida
# unlocks: capabilities adicionais que esta finding torna possível

FINDING_TO_CAPABILITY: list[dict] = [
    # ── Recon / Info Disclosure ──────────────────────────────────────────────
    {
        "match": ["x-powered-by", "server header", "server leaks", "technology fingerprint",
                  "version disclosure", "information disclosure"],
        "capability": "tech_fingerprint",
        "pre_requires": [],
        "unlocks": ["targeted_cve_exploit"],
        "attack_stage": "reconnaissance",
        "description": "Versão de tecnologia exposta → atacante sabe qual CVE usar",
    },
    {
        "match": ["path traversal", "lfi", "local file inclusion", "directory traversal"],
        "capability": "file_read",
        "pre_requires": [],
        "unlocks": ["credential_harvest", "config_leak"],
        "attack_stage": "initial_access",
        "description": "Leitura de arquivos locais → credenciais, configurações, chaves",
    },
    {
        "match": ["rce", "remote code execution", "command injection", "code execution",
                  "os command", "spring4shell", "shellshock", "log4shell", "drupalgeddon"],
        "capability": "rce",
        "pre_requires": [],
        "unlocks": ["lateral_movement", "persistence", "data_exfil", "container_escape"],
        "attack_stage": "execution",
        "description": "Execução remota de código — comprometimento total do servidor",
    },
    {
        "match": ["sql injection", "sqli", "nosql injection"],
        "capability": "sqli",
        "pre_requires": [],
        "unlocks": ["data_exfil", "auth_bypass", "os_shell"],
        "attack_stage": "credential_access",
        "description": "SQL Injection → dump de banco, bypass de auth, possível shell",
    },
    {
        "match": ["ssrf", "server-side request forgery"],
        "capability": "ssrf",
        "pre_requires": [],
        "unlocks": ["cloud_metadata_access", "internal_port_scan", "credential_harvest"],
        "attack_stage": "discovery",
        "description": "SSRF → acesso a metadata de cloud (AWS/GCP), serviços internos",
    },
    {
        "match": ["xxe", "xml external entity"],
        "capability": "xxe",
        "pre_requires": [],
        "unlocks": ["file_read", "ssrf"],
        "attack_stage": "initial_access",
        "description": "XXE → leitura de arquivos + SSRF interno",
    },
    {
        "match": ["deserialization", "java deserialization", "php unserialize"],
        "capability": "deserialization_rce",
        "pre_requires": [],
        "unlocks": ["rce"],
        "attack_stage": "execution",
        "description": "Deserialização insegura → RCE em linguagens como Java/PHP",
    },
    {
        "match": ["default credentials", "default password", "admin:admin",
                  "credential exposure", "hardcoded password"],
        "capability": "default_creds",
        "pre_requires": [],
        "unlocks": ["admin_panel_access", "rce"],
        "attack_stage": "credential_access",
        "description": "Credenciais padrão → acesso imediato a painel administrativo",
    },
    {
        "match": ["jwt", "token bypass", "authentication bypass", "auth bypass",
                  "saml bypass", "oauth bypass"],
        "capability": "auth_bypass",
        "pre_requires": [],
        "unlocks": ["data_exfil", "privilege_escalation"],
        "attack_stage": "credential_access",
        "description": "Bypass de autenticação → acesso a recursos protegidos",
    },
    {
        "match": ["idor", "insecure direct object", "broken access control", "bola"],
        "capability": "idor",
        "pre_requires": [],
        "unlocks": ["data_exfil", "account_takeover"],
        "attack_stage": "credential_access",
        "description": "IDOR → acesso a dados de outros usuários/contas",
    },
    {
        "match": [".env", "env file", "config.json", "settings.json", "secret exposed",
                  "api key exposed", "aws key", "credentials file"],
        "capability": "credential_harvest",
        "pre_requires": [],
        "unlocks": ["cloud_takeover", "lateral_movement", "data_exfil"],
        "attack_stage": "credential_access",
        "description": "Credenciais expostas → acesso a cloud, banco, serviços internos",
    },
    {
        "match": ["subdomain takeover", "dangling cname", "cname takeover"],
        "capability": "subdomain_takeover",
        "pre_requires": [],
        "unlocks": ["phishing", "session_hijack"],
        "attack_stage": "initial_access",
        "description": "Takeover de subdomínio → interceptar cookies, phishing credível",
    },
    {
        "match": ["open redirect"],
        "capability": "open_redirect",
        "pre_requires": [],
        "unlocks": ["phishing", "oauth_token_steal"],
        "attack_stage": "initial_access",
        "description": "Open redirect → phishing + roubo de token OAuth",
    },
    {
        "match": ["xss", "cross-site scripting", "stored xss", "reflected xss", "dom xss"],
        "capability": "xss",
        "pre_requires": [],
        "unlocks": ["session_hijack", "account_takeover", "credential_phish"],
        "attack_stage": "credential_access",
        "description": "XSS → roubo de sessão, account takeover, keylogging",
    },
    {
        "match": ["csrf", "cross-site request forgery"],
        "capability": "csrf",
        "pre_requires": ["xss"],
        "unlocks": ["account_takeover", "unauthorized_action"],
        "attack_stage": "credential_access",
        "description": "CSRF (potencializado por XSS) → ações não autorizadas como usuário",
    },
    {
        "match": ["portainer", "docker api", "container management", "infra-exposta",
                  "docker exposed"],
        "capability": "container_runtime_access",
        "pre_requires": [],
        "unlocks": ["rce", "lateral_movement", "secret_steal", "host_escape"],
        "attack_stage": "execution",
        "description": "API Docker/Portainer exposta → criar container, executar comandos, acesso ao host",
    },
    {
        "match": ["grafana path traversal", "grafana", "cve-2021-43798"],
        "capability": "file_read",
        "pre_requires": [],
        "unlocks": ["credential_harvest"],
        "attack_stage": "initial_access",
        "description": "Grafana path traversal → ler grafana.ini com credenciais de banco",
    },
    {
        "match": ["actuator", "spring actuator", "env endpoint"],
        "capability": "config_leak",
        "pre_requires": [],
        "unlocks": ["credential_harvest"],
        "attack_stage": "reconnaissance",
        "description": "Spring Actuator exposto → /env retorna todas as variáveis de ambiente",
    },
    {
        "match": ["csp", "content security policy", "missing anti-clickjacking",
                  "x-frame-options", "sri", "sub resource integrity"],
        "capability": "client_side_attack_vector",
        "pre_requires": [],
        "unlocks": ["xss", "clickjacking", "supply_chain_inject"],
        "attack_stage": "initial_access",
        "description": "Política de segurança fraca → habilita XSS, clickjacking, injeção de supply chain",
    },
    {
        "match": ["session", "cookie", "phpsessid", "no httponly", "samesite"],
        "capability": "session_fixation",
        "pre_requires": [],
        "unlocks": ["session_hijack"],
        "attack_stage": "credential_access",
        "description": "Cookie mal configurado → roubo de sessão via XSS ou rede",
    },
    {
        "match": ["smb", "445", "samba", "ntlm", "pass-the-hash"],
        "capability": "smb_access",
        "pre_requires": [],
        "unlocks": ["lateral_movement", "credential_harvest", "ransomware_spread"],
        "attack_stage": "lateral_movement",
        "description": "SMB exposto → lateral movement, ransomware, roubo de hashes NTLM",
    },
    {
        "match": ["dev-exposto", "dev environment", "staging", "homolog"],
        "capability": "dev_env_access",
        "pre_requires": [],
        "unlocks": ["credential_harvest", "source_code_access", "debug_backdoor"],
        "attack_stage": "reconnaissance",
        "description": "Ambiente de desenvolvimento exposto → secrets, código-fonte, backdoors de debug",
    },
    {
        "match": ["lgpd", "pii exposed", "data exposure", "personal data"],
        "capability": "pii_access",
        "pre_requires": [],
        "unlocks": ["data_exfil"],
        "attack_stage": "collection",
        "description": "Dados pessoais acessíveis → exfiltração direta, violação LGPD",
    },
    {
        "match": ["waf bypass", "correlação crítica", "firewall bypass"],
        "capability": "waf_bypass",
        "pre_requires": [],
        "unlocks": ["direct_origin_access"],
        "attack_stage": "defense_evasion",
        "description": "IP de origem do WAF descoberto → acesso direto contornando proteção",
    },
]

# ─────────────────────────────────────────────────────────────────────────────
# Assets críticos — o que um atacante quer chegar
# ─────────────────────────────────────────────────────────────────────────────

ASSET_KEYWORDS: dict[str, dict] = {
    "container_runtime": {
        "keywords": ["portainer", "docker", "kubernetes", "rancher", "k8s"],
        "value": 10,
        "description": "Runtime de containers — acesso total à infra",
        "data_sensitivity": "critical",
    },
    "database": {
        "keywords": ["postgres", "mysql", "mongodb", "redis", "database", "db-", "-db."],
        "value": 9,
        "description": "Banco de dados — dados de clientes, transações",
        "data_sensitivity": "critical",
    },
    "financial_api": {
        "keywords": ["bank", "payment", "invoice", "billing", "finance", "pix", "boleto"],
        "value": 10,
        "description": "API financeira — transações, contas, saldo",
        "data_sensitivity": "critical",
    },
    "identity_service": {
        "keywords": ["auth", "sso", "oauth", "login", "keycloak", "identity"],
        "value": 9,
        "description": "Serviço de identidade — comprometimento de todas as contas",
        "data_sensitivity": "critical",
    },
    "monitoring_infra": {
        "keywords": ["grafana", "zabbix", "kibana", "prometheus", "datadog"],
        "value": 7,
        "description": "Infra de monitoramento — credenciais e topologia interna",
        "data_sensitivity": "high",
    },
    "ci_cd": {
        "keywords": ["jenkins", "gitlab", "github", "bitbucket", "pipeline", "deploy"],
        "value": 9,
        "description": "CI/CD — injeção de código malicioso em produção",
        "data_sensitivity": "critical",
    },
    "crm_erp": {
        "keywords": ["crm", "erp", "salesforce", "hubspot", "customer"],
        "value": 8,
        "description": "CRM/ERP — dados de clientes, contratos, PII",
        "data_sensitivity": "high",
    },
    "analytics_bi": {
        "keywords": ["bi-", "dashboard", "analytics", "metabase", "tableau"],
        "value": 7,
        "description": "BI/Analytics — relatórios com dados sensíveis de negócio",
        "data_sensitivity": "high",
    },
    "dev_environment": {
        "keywords": ["dev-", "-dev.", "staging", "homolog", "hml", "test"],
        "value": 6,
        "description": "Ambiente dev — secrets, credenciais, código-fonte",
        "data_sensitivity": "medium",
    },
    "mail_server": {
        "keywords": ["mail", "smtp", "imap", "webmail", "exchange"],
        "value": 8,
        "description": "Servidor de email — comunicações internas, phishing interno",
        "data_sensitivity": "high",
    },
}

# ─────────────────────────────────────────────────────────────────────────────
# MITRE ATT&CK mapping
# ─────────────────────────────────────────────────────────────────────────────

CAPABILITY_TO_ATTACK: dict[str, list[dict]] = {
    "tech_fingerprint": [{"id": "T1592", "name": "Gather Victim Host Information"}],
    "file_read": [{"id": "T1083", "name": "File and Directory Discovery"},
                  {"id": "T1552.001", "name": "Credentials in Files"}],
    "rce": [{"id": "T1190", "name": "Exploit Public-Facing Application"},
            {"id": "T1059", "name": "Command and Scripting Interpreter"}],
    "sqli": [{"id": "T1190", "name": "Exploit Public-Facing Application"},
             {"id": "T1005", "name": "Data from Local System"}],
    "ssrf": [{"id": "T1090", "name": "Proxy"},
             {"id": "T1552.005", "name": "Cloud Instance Metadata API"}],
    "credential_harvest": [{"id": "T1552", "name": "Unsecured Credentials"},
                           {"id": "T1078", "name": "Valid Accounts"}],
    "auth_bypass": [{"id": "T1078", "name": "Valid Accounts"},
                    {"id": "T1556", "name": "Modify Authentication Process"}],
    "idor": [{"id": "T1087", "name": "Account Discovery"},
             {"id": "T1005", "name": "Data from Local System"}],
    "xss": [{"id": "T1185", "name": "Browser Session Hijacking"},
            {"id": "T1539", "name": "Steal Web Session Cookie"}],
    "container_runtime_access": [{"id": "T1611", "name": "Escape to Host"},
                                  {"id": "T1609", "name": "Container Administration Command"}],
    "config_leak": [{"id": "T1592.002", "name": "Gather Victim Host Information: Software"},
                    {"id": "T1552.001", "name": "Credentials in Files"}],
    "smb_access": [{"id": "T1021.002", "name": "Remote Services: SMB/Windows Admin Shares"},
                   {"id": "T1550.002", "name": "Pass the Hash"}],
    "waf_bypass": [{"id": "T1562.006", "name": "Indicator Removal: Network Traffic Manipulation"},
                   {"id": "T1190", "name": "Exploit Public-Facing Application"}],
    "lateral_movement": [{"id": "T1021", "name": "Remote Services"}],
    "data_exfil": [{"id": "T1041", "name": "Exfiltration Over C2 Channel"},
                   {"id": "T1048", "name": "Exfiltration Over Alternative Protocol"}],
}


# ─────────────────────────────────────────────────────────────────────────────
# Core graph builder
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class AttackNode:
    node_id: str
    node_type: str  # "internet", "capability", "asset", "data_sink"
    label: str
    severity: str = "medium"
    finding_ids: list[int] = field(default_factory=list)
    attack_techniques: list[dict] = field(default_factory=list)
    description: str = ""
    domain: str = ""


@dataclass
class AttackEdge:
    source: str
    target: str
    edge_type: str  # "exploits", "enables", "accesses", "contains"
    weight: float = 1.0  # lower = easier to traverse
    finding_id: int | None = None
    description: str = ""


@dataclass
class KillChain:
    chain_id: str
    name: str
    path: list[str]           # node_ids in order
    path_labels: list[str]    # human-readable labels
    total_weight: float       # sum of edge weights (lower = more dangerous)
    risk_score: int           # 1-10
    severity: str             # critical/high/medium
    entry_point: str
    target_asset: str
    attack_techniques: list[dict]
    findings_involved: list[int]
    narrative: str            # human-readable description of the attack
    mitigations: list[str]


def _matches(text: str, patterns: list[str]) -> bool:
    t = text.lower()
    return any(p in t for p in patterns)


def _severity_weight(severity: str) -> float:
    """Peso da edge: menor peso = mais fácil de explorar."""
    return {"critical": 0.2, "high": 0.4, "medium": 0.7, "low": 0.9, "info": 1.0}.get(
        str(severity).lower(), 0.7
    )


def _classify_finding(finding: Any) -> list[dict]:
    """Retorna capabilities geradas por um finding."""
    title = str(finding.title or "").lower()
    description = str((finding.details or {}).get("description") or "").lower()
    full_text = f"{title} {description}"

    capabilities = []
    for rule in FINDING_TO_CAPABILITY:
        if _matches(full_text, rule["match"]):
            capabilities.append({
                "capability": rule["capability"],
                "pre_requires": rule["pre_requires"],
                "unlocks": rule["unlocks"],
                "attack_stage": rule["attack_stage"],
                "description": rule["description"],
                "rule": rule,
            })
    return capabilities


def _classify_asset(domain: str) -> str | None:
    """Retorna tipo de asset crítico baseado no domínio."""
    d = domain.lower()
    for asset_type, cfg in ASSET_KEYWORDS.items():
        if any(kw in d for kw in cfg["keywords"]):
            return asset_type
    return None


def build_attack_graph(db: Any, scan_id: int) -> dict[str, Any]:
    """
    Constrói o grafo de ataque para um scan.
    Retorna: nodes, edges, kill_chains, risk_summary
    """
    from app.models.models import Finding

    findings = (
        db.query(Finding)
        .filter(
            Finding.scan_job_id == scan_id,
            Finding.is_false_positive.is_(False),
        )
        .all()
    )

    nodes: dict[str, AttackNode] = {
        "INTERNET": AttackNode("INTERNET", "internet", "Internet (Attacker)", "info"),
        "DATA_EXFIL": AttackNode("DATA_EXFIL", "data_sink", "Exfiltração de Dados", "critical"),
    }
    edges: list[AttackEdge] = []
    capability_to_findings: dict[str, list[int]] = {}
    domain_capabilities: dict[str, set[str]] = {}  # domain → capabilities

    # Step 1: extract capabilities from findings
    for f in findings:
        domain = str(f.domain or "")
        caps = _classify_finding(f)
        for cap_info in caps:
            cap = cap_info["capability"]
            cap_node_id = f"CAP_{cap}_{domain}".replace(".", "_").replace("-", "_")

            if cap_node_id not in nodes:
                attack_techniques = CAPABILITY_TO_ATTACK.get(cap, [])
                nodes[cap_node_id] = AttackNode(
                    node_id=cap_node_id,
                    node_type="capability",
                    label=cap.replace("_", " ").title(),
                    severity=str(f.severity or "medium"),
                    finding_ids=[f.id],
                    attack_techniques=attack_techniques,
                    description=cap_info["description"],
                    domain=domain,
                )
            else:
                nodes[cap_node_id].finding_ids.append(f.id)

            capability_to_findings.setdefault(cap_node_id, []).append(f.id)
            domain_capabilities.setdefault(domain, set()).add(cap)

            # Edge: INTERNET → capability (direct access)
            weight = _severity_weight(str(f.severity or "medium"))
            edge = AttackEdge(
                source="INTERNET",
                target=cap_node_id,
                edge_type="exploits",
                weight=weight,
                finding_id=f.id,
                description=f"Exploração via {f.title or cap}",
            )
            # Avoid duplicates
            if not any(e.source == edge.source and e.target == edge.target for e in edges):
                edges.append(edge)

    # Step 2: capability → capability edges (when A unlocks B on same domain)
    for domain, caps in domain_capabilities.items():
        for cap in list(caps):
            rule = next(
                (r for r in FINDING_TO_CAPABILITY if r["capability"] == cap), None
            )
            if not rule:
                continue
            for unlocked in rule.get("unlocks", []):
                if unlocked in caps:
                    # This capability is already found → chain exists
                    src_id = f"CAP_{cap}_{domain}".replace(".", "_").replace("-", "_")
                    tgt_id = f"CAP_{unlocked}_{domain}".replace(".", "_").replace("-", "_")
                    if src_id in nodes and tgt_id in nodes:
                        if not any(e.source == src_id and e.target == tgt_id for e in edges):
                            edges.append(AttackEdge(
                                source=src_id,
                                target=tgt_id,
                                edge_type="enables",
                                weight=0.3,
                                description=f"{cap} → habilita {unlocked}",
                            ))

    # Step 3: assets
    all_domains = set(str(f.domain or "") for f in findings)
    for domain in all_domains:
        if not domain:
            continue
        asset_type = _classify_asset(domain)
        if asset_type:
            asset_cfg = ASSET_KEYWORDS[asset_type]
            asset_node_id = f"ASSET_{asset_type}_{domain}".replace(".", "_").replace("-", "_")
            nodes[asset_node_id] = AttackNode(
                node_id=asset_node_id,
                node_type="asset",
                label=f"{asset_type.replace('_',' ').title()} ({domain})",
                severity="critical" if asset_cfg["data_sensitivity"] == "critical" else "high",
                description=asset_cfg["description"],
                domain=domain,
            )
            # Edge: asset → data_exfil
            edges.append(AttackEdge(
                source=asset_node_id,
                target="DATA_EXFIL",
                edge_type="contains",
                weight=0.1,
                description=f"Ativo {asset_type} contém dados sensíveis",
            ))
            # Edge: capabilities on same domain → asset
            for cap in domain_capabilities.get(domain, set()):
                cap_node_id = f"CAP_{cap}_{domain}".replace(".", "_").replace("-", "_")
                if cap_node_id in nodes:
                    if not any(e.source == cap_node_id and e.target == asset_node_id for e in edges):
                        edges.append(AttackEdge(
                            source=cap_node_id,
                            target=asset_node_id,
                            edge_type="accesses",
                            weight=0.2,
                            description=f"{cap} comprometeu {asset_type}",
                        ))

    # Step 4: find kill chains (paths INTERNET → DATA_EXFIL)
    kill_chains = _find_kill_chains(nodes, edges, findings, max_chains=10)

    # Step 5: summary
    critical_chains = [kc for kc in kill_chains if kc.severity == "critical"]
    high_chains = [kc for kc in kill_chains if kc.severity == "high"]

    return {
        "node_count": len(nodes),
        "edge_count": len(edges),
        "kill_chain_count": len(kill_chains),
        "critical_kill_chains": len(critical_chains),
        "kill_chains": [_serialize_kill_chain(kc) for kc in kill_chains],
        "nodes": [_serialize_node(n) for n in nodes.values()],
        "edges": [_serialize_edge(e) for e in edges],
        "risk_summary": _compute_risk_summary(kill_chains, findings),
    }


def _find_kill_chains(
    nodes: dict[str, AttackNode],
    edges: list[AttackEdge],
    findings: list[Any],
    max_chains: int = 10,
) -> list[KillChain]:
    """Encontra caminhos de INTERNET → DATA_EXFIL usando BFS com pesos."""
    from collections import defaultdict
    import heapq

    # Build adjacency list
    adj: dict[str, list[tuple[float, str, AttackEdge]]] = defaultdict(list)
    for e in edges:
        adj[e.source].append((e.weight, e.target, e))

    kill_chains = []
    seen_paths: set[tuple[str, ...]] = set()

    # Dijkstra-like BFS for all paths (limited)
    # heap: (total_weight, path_nodes, edges_used)
    heap = [(0.0, ["INTERNET"], [])]

    while heap and len(kill_chains) < max_chains:
        weight, path, used_edges = heapq.heappop(heap)

        current = path[-1]
        if current == "DATA_EXFIL" and len(path) >= 3:
            path_tuple = tuple(path)
            if path_tuple not in seen_paths:
                seen_paths.add(path_tuple)
                kc = _build_kill_chain(path, used_edges, weight, nodes, findings)
                if kc:
                    kill_chains.append(kc)
            continue

        if len(path) > 8:  # max depth
            continue

        for edge_weight, neighbor, edge in adj.get(current, []):
            if neighbor not in path:  # no cycles
                heapq.heappush(heap, (
                    weight + edge_weight,
                    path + [neighbor],
                    used_edges + [edge],
                ))

    # Sort by risk (ascending weight = most dangerous first)
    kill_chains.sort(key=lambda kc: kc.total_weight)
    return kill_chains


def _build_kill_chain(
    path: list[str],
    used_edges: list[AttackEdge],
    total_weight: float,
    nodes: dict[str, AttackNode],
    findings: list[Any],
) -> KillChain | None:
    """Constrói um KillChain object a partir de um path."""
    if len(path) < 3:
        return None

    path_labels = [nodes[n].label for n in path if n in nodes]
    finding_ids = []
    attack_techniques = []
    seen_techs: set[str] = set()

    for node_id in path:
        node = nodes.get(node_id)
        if node:
            finding_ids.extend(node.finding_ids)
            for t in node.attack_techniques:
                if t["id"] not in seen_techs:
                    attack_techniques.append(t)
                    seen_techs.add(t["id"])

    # Find the asset node in path
    asset_node = next(
        (nodes[n] for n in path if nodes.get(n) and nodes[n].node_type == "asset"),
        None,
    )

    # Compute risk score: 10 = critical chain, lower weight = higher risk
    risk_score = max(1, min(10, int(10 - total_weight * 5)))
    if total_weight < 1.0:
        severity = "critical"
    elif total_weight < 2.0:
        severity = "high"
    else:
        severity = "medium"

    # Build narrative
    cap_nodes = [nodes[n] for n in path if nodes.get(n) and nodes[n].node_type == "capability"]
    if cap_nodes:
        steps = " → ".join(c.description.split("→")[0].strip() for c in cap_nodes if c.description)
        narrative = (
            f"Um atacante pode: {steps}. "
            f"Isso resulta em acesso ao ativo '{asset_node.label if asset_node else 'sistema'}' "
            f"e potencial exfiltração de dados. "
            f"Dificuldade relativa: {total_weight:.1f} (menor = mais fácil)."
        )
    else:
        narrative = "Cadeia de ataque identificada."

    # Mitigations based on path
    mitigations = _suggest_mitigations(cap_nodes)

    entry_node = nodes.get(path[1]) if len(path) > 1 else None

    return KillChain(
        chain_id=f"KC_{hash(tuple(path)) % 10000:04d}",
        name=f"{'→'.join(n.split('_')[1] if '_' in n else n for n in path[1:-1][:3])}",
        path=path,
        path_labels=path_labels,
        total_weight=total_weight,
        risk_score=risk_score,
        severity=severity,
        entry_point=entry_node.domain if entry_node else "",
        target_asset=asset_node.label if asset_node else "Dados Sensíveis",
        attack_techniques=attack_techniques,
        findings_involved=list(set(finding_ids)),
        narrative=narrative,
        mitigations=mitigations,
    )


def _suggest_mitigations(cap_nodes: list[AttackNode]) -> list[str]:
    mitigations = []
    seen = set()
    mitigation_map = {
        "rce": "Aplicar patches de segurança e validar entrada de dados.",
        "file_read": "Restringir permissões de arquivo e sanitizar caminhos.",
        "credential_harvest": "Rotacionar credenciais e usar secrets manager.",
        "container_runtime_access": "Proteger API Docker com autenticação e rede privada.",
        "auth_bypass": "Revisar lógica de autenticação e usar MFA.",
        "sqli": "Usar prepared statements e validar todas as entradas SQL.",
        "xss": "Implementar CSP estrita e sanitizar HTML output.",
        "ssrf": "Validar e filtrar URLs de entrada; bloquear acesso a IPs internos.",
        "config_leak": "Remover endpoints de debug e proteger arquivos de configuração.",
        "smb_access": "Bloquear porta 445 em firewalls externos.",
        "waf_bypass": "Mover origem para uma rede diferente ou usar IP rotation.",
    }
    for node in cap_nodes:
        cap = node.label.lower().replace(" ", "_")
        for key, mitigation in mitigation_map.items():
            if key in cap and key not in seen:
                mitigations.append(mitigation)
                seen.add(key)
    return mitigations


def _serialize_node(n: AttackNode) -> dict:
    return {
        "id": n.node_id, "type": n.node_type, "label": n.label,
        "severity": n.severity, "finding_ids": n.finding_ids,
        "attack_techniques": n.attack_techniques, "description": n.description,
        "domain": n.domain,
    }


def _serialize_edge(e: AttackEdge) -> dict:
    return {
        "source": e.source, "target": e.target, "type": e.edge_type,
        "weight": e.weight, "finding_id": e.finding_id, "description": e.description,
    }


def _serialize_kill_chain(kc: KillChain) -> dict:
    return {
        "chain_id": kc.chain_id, "name": kc.name, "path": kc.path,
        "path_labels": kc.path_labels, "total_weight": round(kc.total_weight, 2),
        "risk_score": kc.risk_score, "severity": kc.severity,
        "entry_point": kc.entry_point, "target_asset": kc.target_asset,
        "attack_techniques": kc.attack_techniques,
        "findings_involved": kc.findings_involved,
        "narrative": kc.narrative, "mitigations": kc.mitigations,
    }


def _compute_risk_summary(kill_chains: list[KillChain], findings: list[Any]) -> dict:
    return {
        "total_kill_chains": len(kill_chains),
        "critical_paths": sum(1 for kc in kill_chains if kc.severity == "critical"),
        "high_paths": sum(1 for kc in kill_chains if kc.severity == "high"),
        "shortest_path_weight": round(min((kc.total_weight for kc in kill_chains), default=10), 2),
        "most_dangerous_entry": kill_chains[0].entry_point if kill_chains else None,
        "most_dangerous_asset": kill_chains[0].target_asset if kill_chains else None,
        "top_attack_techniques": _top_techniques(kill_chains),
    }


def _top_techniques(kill_chains: list[KillChain]) -> list[dict]:
    count: dict[str, dict] = {}
    for kc in kill_chains:
        for t in kc.attack_techniques:
            tid = t["id"]
            if tid not in count:
                count[tid] = {**t, "frequency": 0}
            count[tid]["frequency"] += 1
    return sorted(count.values(), key=lambda x: -x["frequency"])[:10]
