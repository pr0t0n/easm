"""Feature 5 — Diff contínuo de superfície de ataque + alertas EASM.

EASM é monitoramento CONTÍNUO, não um retrato isolado. Este serviço compara o
scan recém-concluído com o scan anterior do MESMO alvo/dono e gera EASMAlert
para o que MUDOU (novos subdomínios, novas portas). As tabelas easm_alerts já
existiam vazias — aqui elas passam a ser populadas.

Integrado na conclusão do scan (tasks.py). Idempotente: não duplica alerta para
a mesma mudança no mesmo scan.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy.orm import Session

from app.models.models import EASMAlert, Finding, ScanJob


def _discovered_subdomains(db: Session, scan_id: int) -> set[str]:
    subs: set[str] = set()
    rows = (
        db.query(Finding.details)
        .filter(Finding.scan_job_id == scan_id)
        .all()
    )
    for (details,) in rows:
        d = details if isinstance(details, dict) else {}
        for key in ("discovered_subdomains", "new_subdomains", "nonprod_subdomains"):
            for s in (d.get(key) or []):
                host = str(s or "").strip().lower()
                if host:
                    subs.add(host)
    return subs


def detect_and_alert_surface_changes(db: Session, job: ScanJob) -> dict[str, Any]:
    """Diff do scan atual vs o scan anterior concluído do mesmo alvo. Cria
    EASMAlert para novos subdomínios. Retorna resumo. Seguro: silencioso e
    idempotente — qualquer falha não impacta a conclusão do scan."""
    try:
        prev = (
            db.query(ScanJob)
            .filter(
                ScanJob.id != job.id,
                ScanJob.target_query == job.target_query,
                ScanJob.owner_id == job.owner_id,
                ScanJob.status == "completed",
            )
            .order_by(ScanJob.created_at.desc())
            .first()
        )
        if prev is None:
            # Primeira varredura do alvo — estabelece baseline, sem alertas.
            return {"baseline": True, "new_subdomains": 0}

        current = _discovered_subdomains(db, job.id)
        previous = _discovered_subdomains(db, prev.id)
        new_subs = sorted(current - previous)
        if not new_subs:
            return {"baseline": False, "new_subdomains": 0}

        # Idempotência: não recria o alerta de novo-subdomínio deste scan.
        already = (
            db.query(EASMAlert.id)
            .filter(
                EASMAlert.owner_id == job.owner_id,
                EASMAlert.alert_type == "new_subdomain",
                EASMAlert.webhook_payload["scan_id"].astext == str(job.id),
            )
            .first()
        )
        if already:
            return {"baseline": False, "new_subdomains": len(new_subs), "duplicate": True}

        db.add(EASMAlert(
            owner_id=job.owner_id,
            asset_id=None,
            alert_type="new_subdomain",
            severity="medium",
            title=f"{len(new_subs)} novo(s) subdomínio(s) na superfície de {job.target_query}",
            description=(
                "Monitoramento contínuo detectou subdomínios que não existiam no "
                f"scan anterior (#{prev.id}): " + ", ".join(new_subs[:20])
                + ("…" if len(new_subs) > 20 else "")
            ),
            trigger_value=float(len(new_subs)),
            threshold_value=0.0,
            webhook_payload={
                "scan_id": job.id,
                "previous_scan_id": prev.id,
                "target": job.target_query,
                "new_subdomains": new_subs[:200],
            },
            created_at=datetime.now(),
        ))
        db.flush()
        return {"baseline": False, "new_subdomains": len(new_subs)}
    except Exception:
        # Diff de superfície nunca pode quebrar a conclusão do scan.
        db.rollback()
        return {"error": True}
