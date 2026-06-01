"""Mapeamento a frameworks (MITRE ATT&CK) por CLASSE de vulnerabilidade.

Pentest automatizado fala a língua padrão: cada classe de vuln mapeia para uma
técnica/tática MITRE ATT&CK. Isso permite narrar o ataque em termos auditáveis
(Reconnaissance → ... → Impact) e comparar com qualquer framework de defesa.

Fonte única no BACKEND (antes o mapeamento vivia hardcoded por-ferramenta no
frontend). Chaveado pela família canônica de app.services.vuln_family.
"""

from __future__ import annotations

# Ordem das táticas ATT&CK Enterprise (para narrar a progressão do ataque).
TACTIC_ORDER: list[tuple[str, str]] = [
    ("TA0043", "Reconnaissance"),
    ("TA0042", "Resource Development"),
    ("TA0001", "Initial Access"),
    ("TA0002", "Execution"),
    ("TA0003", "Persistence"),
    ("TA0004", "Privilege Escalation"),
    ("TA0005", "Defense Evasion"),
    ("TA0006", "Credential Access"),
    ("TA0007", "Discovery"),
    ("TA0008", "Lateral Movement"),
    ("TA0009", "Collection"),
    ("TA0011", "Command and Control"),
    ("TA0010", "Exfiltration"),
    ("TA0040", "Impact"),
]
_TACTIC_NAME = dict(TACTIC_ORDER)
_TACTIC_RANK = {tid: i for i, (tid, _) in enumerate(TACTIC_ORDER)}

# família → {technique, technique_name, tactic, d3fend (contramedida)}
FAMILY_ATTACK: dict[str, dict] = {
    "xss": {"technique": "T1059.007", "technique_name": "Command and Scripting Interpreter: JavaScript",
            "tactic": "TA0002", "d3fend": "D3-OTP Output Encoding"},
    "sqli": {"technique": "T1190", "technique_name": "Exploit Public-Facing Application",
             "tactic": "TA0001", "d3fend": "D3-QPV Query Parameter Validation"},
    "rce": {"technique": "T1190", "technique_name": "Exploit Public-Facing Application",
            "tactic": "TA0001", "d3fend": "D3-PSEP Process Segment Execution Prevention"},
    "command_injection": {"technique": "T1059", "technique_name": "Command and Scripting Interpreter",
                          "tactic": "TA0002", "d3fend": "D3-IV Input Validation"},
    "ssrf": {"technique": "T1190", "technique_name": "Exploit Public-Facing Application",
             "tactic": "TA0001", "d3fend": "D3-OTF Outbound Traffic Filtering"},
    "idor": {"technique": "T1190", "technique_name": "Exploit Public-Facing Application (Object Authz)",
             "tactic": "TA0001", "d3fend": "D3-UAC User Account Control"},
    "broken_access_control": {"technique": "T1078", "technique_name": "Valid Accounts (Access Control Bypass)",
                              "tactic": "TA0001", "d3fend": "D3-UAC User Account Control"},
    "auth_bypass": {"technique": "T1078", "technique_name": "Valid Accounts",
                    "tactic": "TA0001", "d3fend": "D3-MFA Multi-factor Authentication"},
    "jwt_oauth": {"technique": "T1550.001", "technique_name": "Use Alternate Auth Material: Application Access Token",
                  "tactic": "TA0005", "d3fend": "D3-CTS Credential Transmission Scoping"},
    "csrf": {"technique": "T1185", "technique_name": "Browser Session Hijacking",
             "tactic": "TA0009", "d3fend": "D3-OTP Origin Token Pattern"},
    "open_redirect": {"technique": "T1566.002", "technique_name": "Phishing: Spearphishing Link",
                      "tactic": "TA0001", "d3fend": "D3-URA URL Reputation Analysis"},
    "lfri": {"technique": "T1083", "technique_name": "File and Directory Discovery",
             "tactic": "TA0007", "d3fend": "D3-FAPA File Access Pattern Analysis"},
    "path_traversal": {"technique": "T1083", "technique_name": "File and Directory Discovery",
                       "tactic": "TA0007", "d3fend": "D3-FAPA File Access Pattern Analysis"},
    "xxe": {"technique": "T1190", "technique_name": "Exploit Public-Facing Application (XXE)",
            "tactic": "TA0001", "d3fend": "D3-IV Input Validation"},
    "file_upload": {"technique": "T1505.003", "technique_name": "Server Software Component: Web Shell",
                    "tactic": "TA0003", "d3fend": "D3-FCR File Content Rules"},
    "deserialization": {"technique": "T1190", "technique_name": "Exploit Public-Facing Application (Deserialization)",
                        "tactic": "TA0001", "d3fend": "D3-IV Input Validation"},
    "subdomain_takeover": {"technique": "T1584.001", "technique_name": "Compromise Infrastructure: Domains",
                           "tactic": "TA0042", "d3fend": "D3-DNSDL DNS Denylisting"},
    "cors": {"technique": "T1190", "technique_name": "Exploit Public-Facing Application (CORS)",
             "tactic": "TA0001", "d3fend": "D3-OTP Origin Token Pattern"},
    "header_injection": {"technique": "T1190", "technique_name": "Exploit Public-Facing Application (CRLF)",
                         "tactic": "TA0001", "d3fend": "D3-IV Input Validation"},
    "race_condition": {"technique": "T1190", "technique_name": "Exploit Public-Facing Application (TOCTOU)",
                       "tactic": "TA0001", "d3fend": "D3-RAPA Resource Access Pattern Analysis"},
    "graphql_api": {"technique": "T1190", "technique_name": "Exploit Public-Facing Application (GraphQL)",
                    "tactic": "TA0001", "d3fend": "D3-IV Input Validation"},
    "business_logic": {"technique": "T1190", "technique_name": "Exploit Public-Facing Application (Logic Flaw)",
                       "tactic": "TA0001", "d3fend": "D3-RAPA Resource Access Pattern Analysis"},
    "info_exposure": {"technique": "T1213", "technique_name": "Data from Information Repositories",
                      "tactic": "TA0009", "d3fend": "D3-DENCR Disk Encryption"},
    "secrets": {"technique": "T1552.001", "technique_name": "Unsecured Credentials: Credentials In Files",
                "tactic": "TA0006", "d3fend": "D3-CR Credential Rotation"},
    "security_headers": {"technique": "T1190", "technique_name": "Exploit Public-Facing Application (Misconfig)",
                         "tactic": "TA0001", "d3fend": "D3-HCSPP HTTP Security Policy Pattern"},
    "misconfiguration": {"technique": "T1190", "technique_name": "Exploit Public-Facing Application (Misconfig)",
                         "tactic": "TA0001", "d3fend": "D3-SCP Secure Configuration"},
    "tls_ssl": {"technique": "T1557", "technique_name": "Adversary-in-the-Middle",
                "tactic": "TA0006", "d3fend": "D3-CTS Credential Transmission Scoping"},
    "vulnerable_dependency": {"technique": "T1190", "technique_name": "Exploit Public-Facing Application (CVE)",
                              "tactic": "TA0001", "d3fend": "D3-SU Software Update"},
    "dos": {"technique": "T1499", "technique_name": "Endpoint Denial of Service",
            "tactic": "TA0040", "d3fend": "D3-RAPA Resource Access Pattern Analysis"},
    "nosql_injection": {"technique": "T1190", "technique_name": "Exploit Public-Facing Application (NoSQLi)",
                        "tactic": "TA0001", "d3fend": "D3-IV Input Validation"},
    "websocket": {"technique": "T1190", "technique_name": "Exploit Public-Facing Application (WebSocket)",
                  "tactic": "TA0001", "d3fend": "D3-IV Input Validation"},
}


# ── MITRE ATLAS + NIST AI RMF (ameaças de IA/LLM) ────────────────────────────
# Mapeia as estratégias do llm_risk_service para técnicas ATLAS v5.4 + AI RMF.
ATLAS_FOR_STRATEGY: dict[str, dict] = {
    "prompt-injection": {"atlas": "AML.T0051", "atlas_name": "LLM Prompt Injection",
                         "nist_ai_rmf": "MEASURE-2.7", "genai_risk": "Prompt Injection"},
    "jailbreak": {"atlas": "AML.T0054", "atlas_name": "LLM Jailbreak",
                  "nist_ai_rmf": "MEASURE-2.6", "genai_risk": "Obscene/harmful content"},
    "jailbreak:composite": {"atlas": "AML.T0054", "atlas_name": "LLM Jailbreak (composite)",
                            "nist_ai_rmf": "MEASURE-2.6", "genai_risk": "Obscene/harmful content"},
    "exfiltration": {"atlas": "AML.T0057", "atlas_name": "LLM Data Leakage",
                     "nist_ai_rmf": "MANAGE-2.2", "genai_risk": "Data Privacy / Info Disclosure"},
}


def atlas_for_llm(strategy: str | None) -> dict | None:
    """Mapeamento ATLAS/AI RMF de uma estratégia de teste de LLM."""
    s = str(strategy or "").strip().lower()
    return ATLAS_FOR_STRATEGY.get(s) or ATLAS_FOR_STRATEGY.get(s.split(":")[0])


# ── NIST CSF 2.0 por família (compliance: "uma vuln, um checkbox") ────────────
FAMILY_CSF: dict[str, str] = {
    "xss": "PR.PS-06", "sqli": "PR.PS-06", "rce": "PR.PS-06", "command_injection": "PR.PS-06",
    "ssrf": "PR.PS-06", "xxe": "PR.PS-06", "ssti": "PR.PS-06", "deserialization": "PR.PS-06",
    "csrf": "PR.PS-06", "cors": "PR.PS-06", "header_injection": "PR.PS-06", "graphql_api": "PR.PS-06",
    "race_condition": "PR.PS-06", "business_logic": "PR.PS-06", "open_redirect": "PR.PS-06",
    "file_upload": "PR.PS-06", "path_traversal": "PR.PS-06", "lfri": "PR.PS-06",
    "nosql_injection": "PR.PS-06", "websocket": "PR.PS-06",
    "idor": "PR.AA-05", "broken_access_control": "PR.AA-05", "auth_bypass": "PR.AA-05",
    "jwt_oauth": "PR.AA-05",
    "secrets": "PR.DS-01", "info_exposure": "PR.DS-01",
    "tls_ssl": "PR.DS-02",
    "security_headers": "PR.PS-01", "misconfiguration": "PR.PS-01",
    "vulnerable_dependency": "ID.RA-01", "subdomain_takeover": "ID.AM-02",
    "dos": "PR.IR-04",
}
_CSF_NAME: dict[str, str] = {
    "PR.PS-06": "Protect · Secure Software Development",
    "PR.PS-01": "Protect · Configuration Management",
    "PR.AA-05": "Protect · Access Permissions & Least Privilege",
    "PR.DS-01": "Protect · Data-at-Rest Protection",
    "PR.DS-02": "Protect · Data-in-Transit Protection",
    "ID.RA-01": "Identify · Vulnerabilities Identified",
    "ID.AM-02": "Identify · Asset Inventory",
    "PR.IR-04": "Protect · Resource Capacity (Availability)",
}


def csf_for_family(family_id: str | None) -> dict | None:
    sub = FAMILY_CSF.get(str(family_id or ""))
    if not sub:
        return None
    return {"subcategory": sub, "name": _CSF_NAME.get(sub, sub), "function": sub.split(".")[0]}


# ── Export de camada MITRE ATT&CK Navigator ──────────────────────────────────
def build_navigator_layer(scan_name: str, family_ids: list[str]) -> dict:
    """Gera uma layer oficial do ATT&CK Navigator a partir das técnicas observadas."""
    from collections import Counter
    techs = Counter()
    for fam in family_ids:
        m = FAMILY_ATTACK.get(str(fam or ""))
        if m:
            techs[m["technique"]] += 1
    max_c = max(techs.values(), default=1)
    techniques = [
        {"techniqueID": tid, "score": cnt, "color": "",
         "comment": f"{cnt} achado(s)", "enabled": True}
        for tid, cnt in techs.items()
    ]
    return {
        "name": f"EASM Pentest — {scan_name}",
        "versions": {"attack": "16", "navigator": "5.1.0", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": "Técnicas MITRE ATT&CK observadas no pentest automatizado (EASM).",
        "gradient": {"colors": ["#ffe0e0", "#ff6b6b", "#c0392b"], "minValue": 0, "maxValue": max_c},
        "techniques": techniques,
    }


def attack_for_family(family_id: str | None) -> dict | None:
    """Retorna o mapeamento ATT&CK de uma família, com nomes de tática resolvidos."""
    m = FAMILY_ATTACK.get(str(family_id or ""))
    if not m:
        return None
    csf = csf_for_family(family_id)
    return {
        "technique": m["technique"],
        "technique_name": m["technique_name"],
        "tactic": m["tactic"],
        "tactic_name": _TACTIC_NAME.get(m["tactic"], m["tactic"]),
        "d3fend": m.get("d3fend"),
        "nist_csf": csf["subcategory"] if csf else None,
        "nist_csf_name": csf["name"] if csf else None,
    }


def attack_label(family_id: str | None) -> str:
    """Rótulo curto para a UI: 'T1190 · Initial Access'."""
    m = attack_for_family(family_id)
    if not m:
        return ""
    return f"{m['technique']} · {m['tactic_name']}"


def tactic_progression(family_ids: list[str]) -> list[dict]:
    """Dado o conjunto de famílias observadas, devolve as táticas ATT&CK
    percorridas, em ordem de kill chain (para a narrativa do relatório)."""
    seen: dict[str, dict] = {}
    for fam in family_ids:
        m = FAMILY_ATTACK.get(str(fam or ""))
        if not m:
            continue
        tid = m["tactic"]
        slot = seen.setdefault(tid, {"tactic": tid, "tactic_name": _TACTIC_NAME.get(tid, tid),
                                     "families": set(), "techniques": set()})
        slot["families"].add(fam)
        slot["techniques"].add(m["technique"])
    out = []
    for tid in sorted(seen, key=lambda t: _TACTIC_RANK.get(t, 99)):
        s = seen[tid]
        out.append({
            "tactic": s["tactic"], "tactic_name": s["tactic_name"],
            "families": sorted(s["families"]), "techniques": sorted(s["techniques"]),
        })
    return out
