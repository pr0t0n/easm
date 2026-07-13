"""attack_narrative.py — L6: Attack narrative report generator.

After a scan completes (or on-demand), uses Ollama + confirmed findings to
generate a human-readable attack narrative:

  "An attacker targeting example.com would first discover 42 subdomains via
   passive DNS. The payment.example.com subdomain runs Apache Tomcat 8.5.x
   (CVE-2017-12617 confirmed via nuclei), allowing unauthenticated RCE via
   HTTP PUT. Combined with the leaked DB credentials from a public GitHub
   repository (.env file), an attacker could achieve full data exfiltration..."

The narrative:
  1. Groups findings into kill chain phases (Recon → Weaponization → Delivery → Exploitation → C2 → Exfil)
  2. Identifies the most critical attack path
  3. Generates executive summary + technical narrative
  4. Includes remediation priorities

Config:
  settings.ollama_url    — Ollama server URL
  settings.llm_model     — Model to use (default: llama3.2:3b)
"""

from __future__ import annotations

import json
import logging
from typing import Any

import requests

from app.core.config import settings
from app.services.untrusted_content import normalize_adversarial_text, wrap_untrusted

logger = logging.getLogger(__name__)

OLLAMA_DEFAULT_URL = "http://ollama:11434"
DEFAULT_MODEL = "llama3.2:3b"

NARRATIVE_SYSTEM_PROMPT = """You are a senior security analyst writing a penetration test report.
Write clearly and professionally. Focus on business impact.
Structure: Executive Summary → Attack Path → Technical Details → Remediation.
Use concrete examples from the findings provided.
Be specific about which CVEs, tools, and endpoints were confirmed.
Write in Portuguese (Brazil) since this is for a Brazilian security team."""

EXECUTIVE_PROMPT_TEMPLATE = """Generate a penetration test attack narrative report based on these confirmed findings:

SCAN TARGET: {target}
TOTAL FINDINGS: {total_findings} ({confirmed} confirmed, {candidate} candidate, {hypothesis} hypothesis)
CRITICAL: {critical_count} | HIGH: {high_count} | MEDIUM: {medium_count} | LOW: {low_count}

CONFIRMED FINDINGS (most critical first):
{findings_json}

TECHNOLOGY STACK:
{tech_stack_json}

KILL CHAIN PHASES COVERED: {phases}

Write a professional penetration test report narrative in Portuguese with:
1. Resumo Executivo (2-3 paragraphs, business impact focus)
2. Caminho de Ataque Principal (step-by-step how an attacker would proceed)
3. Descobertas Críticas (detailed analysis of confirmed critical/high findings)
4. Remediações Prioritárias (numbered list, most critical first)

Be specific, cite CVE numbers and tools where relevant."""


def _group_findings_by_kill_chain(findings: list[dict]) -> dict[str, list[dict]]:
    """Group findings by kill chain phase based on tool/type."""
    groups: dict[str, list[dict]] = {
        "reconnaissance": [],
        "weaponization": [],
        "delivery": [],
        "exploitation": [],
        "persistence": [],
        "exfiltration": [],
    }

    tool_to_phase = {
        # Recon
        "subfinder": "reconnaissance", "amass": "reconnaissance",
        "theharvester": "reconnaissance", "shodan-cli": "reconnaissance",
        "osint-hibp": "reconnaissance", "osint-github-dork": "reconnaissance",
        "osint-shodan-asn": "reconnaissance",
        # Weaponization
        "nmap": "weaponization", "nmap-vuln": "weaponization",
        "nmap-vulscan": "weaponization", "nuclei": "weaponization",
        "tech_correlator": "weaponization", "wpscan": "weaponization",
        # Delivery
        "ffuf": "delivery", "gobuster": "delivery",
        "feroxbuster": "delivery", "nikto": "delivery",
        "httpx": "delivery", "katana": "delivery",
        # Exploitation
        "sqlmap": "exploitation", "dalfox": "exploitation",
        "hydra": "exploitation", "multi-identity-tester": "exploitation",
        "nuclei-sqli": "exploitation", "nuclei-xss": "exploitation",
        "nuclei-rce": "exploitation", "nuclei-ssrf": "exploitation",
        # Exfiltration
        "gitleaks": "exfiltration", "trufflehog": "exfiltration",
        "git-dumper": "exfiltration", "h8mail": "exfiltration",
    }

    for f in findings:
        tool = str(f.get("tool") or "").lower()
        phase = tool_to_phase.get(tool, "exploitation")  # default to exploitation
        # CVE findings → weaponization
        if f.get("cve"):
            phase = "weaponization"
        groups[phase].append(f)

    return {k: v for k, v in groups.items() if v}


def _findings_to_prompt_json(findings: list[dict], max_count: int = 20) -> str:
    """Convert findings to compact JSON for prompt.

    `title`/`domain`/`url` can carry text the scanned target controls
    (e.g. a header value or path echoed back into a finding) — normalize
    them so obfuscated injection attempts don't survive into the prompt.
    """
    items = []
    for f in sorted(findings, key=lambda x: -int(x.get("risk_score") or 1))[:max_count]:
        items.append({
            "title": normalize_adversarial_text(str(f.get("title") or "")),
            "severity": f.get("severity"),
            "cve": f.get("cve"),
            "tool": f.get("tool"),
            "domain": normalize_adversarial_text(str(f.get("domain") or "")),
            "url": normalize_adversarial_text(str(f.get("url") or "")),
            "verification": f.get("verification_status", "candidate"),
            "risk_score": f.get("risk_score"),
        })
    return json.dumps(items, ensure_ascii=False, indent=2)


def generate_narrative_with_llm(
    target: str,
    findings: list[dict],
    tech_stack: list[dict],
    phases_done: list[str],
) -> str:
    """Generate attack narrative using Ollama. Returns narrative text."""
    ollama_url = str(getattr(settings, "ollama_url", "") or OLLAMA_DEFAULT_URL)
    model_name = str(getattr(settings, "llm_model", "") or DEFAULT_MODEL)

    # Count by severity and status
    confirmed = [f for f in findings if f.get("verification_status") == "confirmed"]
    candidate = [f for f in findings if f.get("verification_status") == "candidate"]
    hypothesis = [f for f in findings if f.get("verification_status") == "hypothesis"]

    sev_counts: dict[str, int] = {}
    for f in findings:
        sev = str(f.get("severity") or "info").lower()
        sev_counts[sev] = sev_counts.get(sev, 0) + 1

    # Use confirmed findings preferentially
    priority_findings = (confirmed + candidate)[:25]

    prompt = EXECUTIVE_PROMPT_TEMPLATE.format(
        target=target,
        total_findings=len(findings),
        confirmed=len(confirmed),
        candidate=len(candidate),
        hypothesis=len(hypothesis),
        critical_count=sev_counts.get("critical", 0),
        high_count=sev_counts.get("high", 0),
        medium_count=sev_counts.get("medium", 0),
        low_count=sev_counts.get("low", 0),
        findings_json=wrap_untrusted(_findings_to_prompt_json(priority_findings), label="findings_do_alvo"),
        tech_stack_json=wrap_untrusted(json.dumps(tech_stack[:10], ensure_ascii=False), label="tech_stack_do_alvo"),
        phases=json.dumps(phases_done),
    )

    try:
        resp = requests.post(
            f"{ollama_url}/api/generate",
            json={
                "model": model_name,
                "prompt": prompt,
                "system": NARRATIVE_SYSTEM_PROMPT,
                "stream": False,
                "options": {
                    "temperature": 0.3,
                    "top_p": 0.95,
                    "num_predict": 3000,
                },
            },
            timeout=300,  # Narrative generation can take 3-5 minutes
        )
        resp.raise_for_status()
        data = resp.json()
        return str(data.get("response") or "")
    except Exception as e:
        logger.debug("narrative LLM generation failed: %s", e)
        return ""


def generate_structural_narrative(
    target: str,
    findings: list[dict],
    tech_stack: list[dict],
    crown_jewels: list[dict] | None = None,
) -> str:
    """Generate a structured narrative without LLM (deterministic fallback).

    Visão executiva + risco + joias da coroa + importância de controles.
    Used when Ollama is unavailable or narrative generation fails.
    """
    crown_jewels = crown_jewels or []
    confirmed = [f for f in findings if f.get("verification_status") == "confirmed"]
    candidate = [f for f in findings if f.get("verification_status") == "candidate"]

    def _sev(f):
        return str(f.get("severity") or "").lower()
    sev_counts = {s: sum(1 for f in findings if _sev(f) == s) for s in ("critical", "high", "medium", "low", "info")}
    crit_high = sev_counts["critical"] + sev_counts["high"]

    # Postura de risco geral (executiva)
    if sev_counts["critical"] > 0:
        posture, posture_txt = "CRÍTICO", "exposição crítica — exploração ativa provável; ação imediata requerida"
    elif sev_counts["high"] > 0:
        posture, posture_txt = "ALTO", "vulnerabilidades de alto impacto presentes; remediação prioritária em 72h"
    elif sev_counts["medium"] > 0:
        posture, posture_txt = "MÉDIO", "fraquezas de configuração que reduzem a resiliência do perímetro"
    else:
        posture, posture_txt = "BAIXO", "superfície relativamente endurecida; manter monitoramento contínuo"

    kill_chain = _group_findings_by_kill_chain(findings)

    lines = [
        f"# Relatório de Ataque — {target}",
        "",
        "## Sumário Executivo",
        "",
        f"**Postura de risco: {posture}** — {posture_txt}.",
        "",
        f"A avaliação ofensiva de `{target}` produziu **{len(findings)} descobertas** "
        f"(**{len(confirmed)} confirmadas com prova de exploração**, {len(candidate)} candidatas a validação). "
        f"Distribuição por severidade: "
        f"🔴 {sev_counts['critical']} críticas · 🟠 {sev_counts['high']} altas · "
        f"🟡 {sev_counts['medium']} médias · 🔵 {sev_counts['low']} baixas.",
        "",
        f"Para o negócio: {crit_high} vulnerabilidade(s) de severidade crítica/alta representam "
        f"risco direto de comprometimento — acesso não autorizado, vazamento de dados ou "
        f"interrupção de serviço. O tempo de exposição (age) eleva a probabilidade de exploração "
        f"ativa; priorize a correção das críticas antes que sejam encadeadas com outras fraquezas.",
        "",
    ]

    # ── Joias da Coroa (Crown Jewels) — ativos de maior valor ─────────────────
    if crown_jewels:
        lines.append("## ⭐ Joias da Coroa (Ativos Críticos)")
        lines.append("")
        lines.append(
            f"Foram identificados **{len(crown_jewels)} ativos de alto valor** — sistemas cujo "
            f"comprometimento causa o maior impacto ao negócio (autenticação, pagamento, dados, "
            f"administração, infraestrutura). Estes concentram a prioridade de teste e de defesa:"
        )
        lines.append("")
        for cj in crown_jewels[:10]:
            t = cj.get("target") or cj.get("subdomain") or ""
            lbl = str(cj.get("label") or "ativo crítico").replace("_", " ")
            # findings nesse ativo
            cj_finds = [f for f in findings if t and (t in str(f.get("domain") or "") or t in str(f.get("url") or ""))]
            cj_hc = sum(1 for f in cj_finds if _sev(f) in ("critical", "high"))
            risk_note = f" — {cj_hc} achado(s) crítico/alto" if cj_hc else " — sem achados críticos confirmados (manter vigilância)"
            lines.append(f"- ⭐ **`{t}`** ({lbl}){risk_note}")
        lines.append("")
        lines.append(
            "> **Por que importa:** controles fortes nesses ativos (MFA, segmentação de rede, "
            "least-privilege, WAF, monitoramento de acesso) são desproporcionalmente importantes — "
            "uma única falha aqui compromete a confidencialidade/integridade de todo o ambiente."
        )
        lines.append("")

    # Critical findings
    critical = [f for f in confirmed if str(f.get("severity") or "").lower() in ("critical", "high")]
    if critical:
        lines.append("## Vulnerabilidades Confirmadas de Maior Impacto")
        lines.append("")
        lines.append(f"**{len(critical)} descobertas críticas/altas** comprovadas diretamente por ferramentas ativas:")
        for f in critical[:5]:
            cve_str = f" ({f['cve']})" if f.get("cve") else ""
            lines.append(f"- **{f['title']}**{cve_str} em `{f.get('domain', target)}`")
        lines.append("")

    # Kill chain summary
    lines.append("## Caminho de Ataque")
    lines.append("")

    phase_order = ["reconnaissance", "weaponization", "delivery", "exploitation", "exfiltration"]
    phase_labels = {
        "reconnaissance": "🔍 Reconhecimento",
        "weaponization": "⚔️ Weaponização",
        "delivery": "📦 Entrega",
        "exploitation": "💥 Exploração",
        "exfiltration": "📤 Exfiltração",
    }

    for phase in phase_order:
        phase_findings = kill_chain.get(phase, [])
        if phase_findings:
            lines.append(f"### {phase_labels.get(phase, phase.title())}")
            for f in phase_findings[:3]:
                v = "✅" if f.get("verification_status") == "confirmed" else "⚠️"
                lines.append(f"{v} {f['title']}")
            lines.append("")

    # Remediation
    lines.append("## Remediações Prioritárias")
    lines.append("")
    priority_findings = sorted(
        [f for f in findings if f.get("verification_status") == "confirmed"],
        key=lambda x: -int(x.get("risk_score") or 1),
    )[:10]

    for i, f in enumerate(priority_findings, 1):
        cve_str = f" — {f['cve']}" if f.get("cve") else ""
        lines.append(f"{i}. **{f['title']}**{cve_str}")
        if f.get("recommendation"):
            lines.append(f"   → {f['recommendation']}")
    lines.append("")

    # ── Importância dos Controles (visão de defesa) ───────────────────────────
    lines.append("## Importância dos Controles")
    lines.append("")
    # Deriva controles relevantes a partir das classes de achado presentes
    blob = " ".join(str(f.get("title") or "").lower() for f in findings)
    controls: list[str] = []
    if any(k in blob for k in ("sql", "xss", "inje", "ssti", "rce", "command")):
        controls.append("**Validação de entrada & WAF** — prepared statements, output encoding e WAF em frente aos ativos web cortam a maior classe de exploração (injeção).")
    if any(k in blob for k in ("header", "hsts", "csp", "clickjack", "x-frame", "cors")):
        controls.append("**Hardening de headers HTTP** — HSTS, CSP, X-Frame-Options reduzem clickjacking, downgrade e roubo de sessão a custo quase zero.")
    if any(k in blob for k in ("auth", "jwt", "credential", "default", "senha", "password")):
        controls.append("**Autenticação forte** — MFA, bloqueio de brute-force e gestão segura de JWT/sessão protegem os ativos de identidade (joias da coroa).")
    if any(k in blob for k in ("ssl", "tls", "cert", "cipher")):
        controls.append("**Criptografia em trânsito** — TLS 1.2+ com ciphers modernos impede interceptação MITM de dados sensíveis.")
    if any(k in blob for k in ("port", "exposed", "exposto", "service", "waf-bypass", "origin")):
        controls.append("**Segmentação de rede & exposição mínima** — fechar serviços internos e proteger a origem atrás do WAF reduz drasticamente a superfície de ataque.")
    if any(k in blob for k in ("cve", "outdated", "version", "desatualiz")):
        controls.append("**Gestão de patches** — manter componentes atualizados elimina CVEs conhecidos (A06:2021), a via mais explorada por atacantes oportunistas.")
    if not controls:
        controls.append("**Monitoramento contínuo** — manter logging/alerting de eventos de segurança e reavaliação periódica da superfície exposta.")
    for c in controls:
        lines.append(f"- {c}")
    lines.append("")
    if crown_jewels:
        lines.append(
            f"> A priorização de defesa deve seguir o valor do ativo: os **{len(crown_jewels)} "
            f"ativos críticos** acima recebem os controles mais rígidos primeiro."
        )

    return "\n".join(lines)


def run_attack_narrative(db, job) -> dict[str, Any]:
    """Generate and store the attack narrative for a completed scan.

    Stores the narrative in job.state_data["attack_narrative"].
    Returns {narrative_text, method, findings_used}.
    """
    from app.models.models import Finding, ScanWorkItem, ScanLog

    target = str(job.target_query or "").strip()
    state = dict(job.state_data or {})

    # Gather findings
    findings_rows = (
        db.query(Finding)
        .filter(Finding.scan_job_id == job.id)
        .order_by(Finding.risk_score.desc())
        .limit(100)
        .all()
    )

    if not findings_rows:
        return {"skipped": "no_findings"}

    findings_dicts = [
        {
            "title": f.title,
            "severity": f.severity,
            "cve": f.cve,
            "tool": f.tool,
            "domain": f.domain,
            "url": f.url,
            "verification_status": f.verification_status,
            "risk_score": f.risk_score,
            "recommendation": f.recommendation,
        }
        for f in findings_rows
    ]

    tech_stack = list(state.get("tech_stack") or job.tech_stack or [])

    phases_done = list({
        str(item.phase_id)
        for item in db.query(ScanWorkItem.phase_id)
        .filter(
            ScanWorkItem.scan_job_id == job.id,
            ScanWorkItem.status.in_(["completed", "done"]),
        )
        .all()
    })

    # Try LLM first, fall back to structural
    narrative = ""
    method = "structural"

    if getattr(settings, "ollama_url", None):
        try:
            narrative = generate_narrative_with_llm(target, findings_dicts, tech_stack, phases_done)
            if narrative.strip():
                method = "llm"
        except Exception as e:
            logger.debug("LLM narrative failed, using structural: %s", e)

    if not narrative.strip():
        _cj = list(state.get("crown_jewels") or [])
        narrative = generate_structural_narrative(target, findings_dicts, tech_stack, crown_jewels=_cj)

    # Store in state_data
    state["attack_narrative"] = narrative
    state["attack_narrative_method"] = method
    state["attack_narrative_generated_at"] = __import__("datetime").datetime.now().isoformat()
    job.state_data = state

    db.add(ScanLog(
        scan_job_id=job.id,
        source="attack-narrative",
        level="INFO",
        message=f"narrative_generated scan={job.id} method={method} findings={len(findings_dicts)} chars={len(narrative)}",
    ))
    db.commit()

    logger.info(
        "attack_narrative generated: scan=%d method=%s findings=%d chars=%d",
        job.id, method, len(findings_dicts), len(narrative),
    )

    return {
        "narrative": narrative,
        "method": method,
        "findings_used": len(findings_dicts),
        "chars": len(narrative),
    }
