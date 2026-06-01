"""Caminhos de ataque rumo ao OBJETIVO (Frentes #2 + #6).

O que separa scanner de pentest: não uma lista de vulns, mas um CAMINHO provado
em direção a um objetivo. Aqui o objetivo são as JOIAS DA COROA (ativos de maior
valor). Para cada uma, montamos a sequência de passos (findings) ordenada pelas
táticas MITRE ATT&CK — entrada → escalada → impacto — e marcamos se o objetivo é
alcançável (há achado confirmado de alto impacto no ativo).
"""

from __future__ import annotations

from sqlalchemy.orm import Session

from app.services.framework_mapping import FAMILY_ATTACK, _TACTIC_RANK, _TACTIC_NAME
from app.services.vuln_family import classify_family, family_label

_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _finding_family(f) -> str:
    d = dict(getattr(f, "details", None) or {})
    return classify_family(
        title=getattr(f, "title", ""), tool=getattr(f, "tool", ""),
        owasp=str(d.get("owasp_category") or ""), cve=getattr(f, "cve", None),
        learning_family=(d.get("learning_source") or {}).get("vuln_family"),
    )


def _asset_of(f) -> str:
    return str(getattr(f, "domain", "") or getattr(f, "url", "") or "").lower()


def build_attack_paths(db: Session, scan_id: int, job=None, max_paths: int = 12) -> dict:
    """Monta caminhos de ataque por crown jewel + a progressão macro de táticas."""
    from app.models.models import Finding, ScanJob

    if job is None:
        job = db.query(ScanJob).filter(ScanJob.id == scan_id).first()
    state = dict(getattr(job, "state_data", None) or {})
    crown = state.get("crown_jewels") or []

    findings = (
        db.query(Finding)
        .filter(Finding.scan_job_id == scan_id, Finding.severity.in_(["critical", "high", "medium", "low"]))
        .all()
    )

    # Indexa findings por ativo (host).
    by_asset: dict[str, list] = {}
    for f in findings:
        a = _asset_of(f)
        if a:
            by_asset.setdefault(a, []).append(f)

    def _steps_for(asset_findings: list) -> list[dict]:
        steps = []
        for f in asset_findings:
            fam = _finding_family(f)
            atk = FAMILY_ATTACK.get(fam)
            if not atk:
                continue
            steps.append({
                "tactic": atk["tactic"], "tactic_name": _TACTIC_NAME.get(atk["tactic"], atk["tactic"]),
                "tactic_rank": _TACTIC_RANK.get(atk["tactic"], 99),
                "technique": atk["technique"], "family": fam, "family_label": family_label(fam),
                "title": str(getattr(f, "title", ""))[:120],
                "severity": str(getattr(f, "severity", "") or ""),
                "confirmed": str(getattr(f, "verification_status", "") or "") == "confirmed",
            })
        # ordena pela tática (kill chain) e severidade; dedup por (tática,família)
        steps.sort(key=lambda s: (s["tactic_rank"], _SEV_RANK.get(s["severity"], 9)))
        seen, uniq = set(), []
        for s in steps:
            k = (s["tactic"], s["family"])
            if k in seen:
                continue
            seen.add(k)
            uniq.append(s)
        return uniq

    paths: list[dict] = []
    for cj in crown[:max_paths]:
        t = str(cj.get("target") or cj.get("subdomain") or "").lower()
        if not t:
            continue
        # findings no ativo ou em subdomínio do ativo
        af = []
        for a, fs in by_asset.items():
            if t and (t in a or a in t):
                af.extend(fs)
        if not af:
            continue
        steps = _steps_for(af)
        reached = any(s["confirmed"] and s["severity"] in ("critical", "high") for s in steps)
        paths.append({
            "objective": t,
            "label": str(cj.get("label") or "ativo crítico").replace("_", " "),
            "steps": steps,
            "step_count": len(steps),
            "objective_reachable": reached,
            "max_severity": min((_SEV_RANK.get(s["severity"], 9) for s in steps), default=9),
        })

    # caminhos com objetivo alcançável e mais passos primeiro
    paths.sort(key=lambda p: (not p["objective_reachable"], p["max_severity"], -p["step_count"]))

    return {
        "scan_id": scan_id,
        "objectives_total": len([c for c in crown if c.get("target") or c.get("subdomain")]),
        "paths_with_findings": len(paths),
        "objectives_reachable": sum(1 for p in paths if p["objective_reachable"]),
        "paths": paths,
    }
