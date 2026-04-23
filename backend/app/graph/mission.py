from __future__ import annotations

from typing import Any


MISSION_ITEMS = [
    "1. Autonomous Supervisor Loop & Guardrails",
    "2. Strategic Planning & Delegation Contract",
    "3. Asset Discovery & Exposure Mapping",
    "4. Threat Intelligence Correlation",
    "5. Adversarial Hypothesis & Thinking Checkpoint",
    "6. Risk Assessment & Exploit Validation",
    "7. Evidence Adjudication & Reproduction Gate",
    "8. Governance & Rating (FAIR + AGE)",
    "9. Executive Narrative & Priorities",
]


SKILL_CATALOG: list[dict[str, Any]] = [
    {
        "id": "recon-subdomain-enum",
        "category": "reconnaissance",
        "description": "Enumeração de subdomínios e expansão de superfície com validação DNS.",
        "triggers": ["domain", "subdomain", "dns", "massdns", "sublist3r", "amass"],
        "playbook": ["massdns", "sublist3r", "amass"],
    },
    {
        "id": "service-fingerprint-http",
        "category": "technologies",
        "description": "Fingerprint de serviços HTTP/TLS e headers para contexto de exploração.",
        "triggers": ["http", "https", "header", "whatweb", "nikto", "tls", "ssl"],
        "playbook": ["curl-headers", "nikto"],
    },
    {
        "id": "vuln-web-injection",
        "category": "vulnerabilities",
        "description": "Validação progressiva de injeção e falhas web com evidência reproduzível.",
        "triggers": ["sqli", "xss", "ssrf", "injection", "burp", "wapiti"],
        "playbook": ["burp-cli", "nikto", "nmap-vulscan"],
    },
    {
        "id": "waf-aware-validation",
        "category": "protocols",
        "description": "Estratégia de validação aware de WAF/proxy para reduzir falsos positivos.",
        "triggers": ["waf", "cloudflare", "proxy", "modsecurity", "akamai"],
        "playbook": ["wafw00f", "curl-headers", "nmap-vulscan"],
    },
    {
        "id": "osint-exposure-correlation",
        "category": "reconnaissance",
        "description": "Correlação de exposição externa e inteligência de ameaças.",
        "triggers": ["shodan", "leak", "osint", "exposure", "internet"],
        "playbook": ["shodan-cli"],
    },
    {
        "id": "evidence-proof-pack",
        "category": "coordination",
        "description": "Gate de evidência: só promove severidade alta com prova mínima reproduzível.",
        "triggers": ["critical", "high", "proof", "repro", "validation"],
        "playbook": ["burp-cli", "nikto", "nmap-vulscan"],
    },
]


def build_autonomous_mission_contract(max_iterations: int) -> dict[str, Any]:
    return {
        "mode": "autonomous-supervisor",
        "max_iterations": int(max_iterations),
        "loop": ["think", "delegate", "test", "observe", "adapt", "validate"],
        "execution_control": {
            "approaching_limit_ratio": 0.85,
            "force_finalize_remaining": 2,
            "pause_on_stagnation": True,
            "stagnation_threshold": 3,
        },
        "evidence_gate": {
            "critical_high_require_verified": True,
            "required_proof_fields": ["validation_status", "repro_steps", "technical_evidence"],
            "default_status_without_proof": "hypothesis",
        },
    }


def _text_blob(target: str, findings: list[dict[str, Any]], target_type: str, discovered_ports: list[int]) -> str:
    chunks = [str(target or ""), str(target_type or "")]
    if discovered_ports:
        chunks.append("ports:" + ",".join(str(p) for p in discovered_ports[:12]))
    for finding in findings[:40]:
        details = finding.get("details") or {}
        chunks.extend(
            [
                str(finding.get("title") or ""),
                str(finding.get("severity") or ""),
                str(details.get("tool") or ""),
                str(details.get("evidence") or ""),
            ]
        )
    return " ".join(chunks).lower()


def select_mission_skills(
    target: str,
    findings: list[dict[str, Any]] | None = None,
    target_type: str = "dominio",
    discovered_ports: list[int] | None = None,
    max_skills: int = 5,
) -> list[dict[str, Any]]:
    findings = list(findings or [])
    discovered_ports = list(discovered_ports or [])
    blob = _text_blob(target, findings, target_type, discovered_ports)

    scored: list[tuple[int, dict[str, Any]]] = []
    for skill in SKILL_CATALOG:
        score = 0
        for trigger in skill.get("triggers") or []:
            if str(trigger).lower() in blob:
                score += 1
        if score > 0:
            scored.append((score, skill))

    # Garante diversidade mínima de base para cenários sem sinais fortes.
    if not scored:
        defaults = [
            "recon-subdomain-enum",
            "service-fingerprint-http",
            "osint-exposure-correlation",
            "vuln-web-injection",
            "evidence-proof-pack",
        ]
        by_id = {item["id"]: item for item in SKILL_CATALOG}
        return [by_id[item_id] for item_id in defaults[:max_skills] if item_id in by_id]

    scored.sort(key=lambda pair: pair[0], reverse=True)
    unique: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    for _, skill in scored:
        skill_id = str(skill.get("id") or "")
        if not skill_id or skill_id in seen_ids:
            continue
        seen_ids.add(skill_id)
        unique.append(skill)
        if len(unique) >= max(1, int(max_skills)):
            break
    return unique
