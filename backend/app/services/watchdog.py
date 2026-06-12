"""Watchdog — prevê e auto-recupera estados 'Up mas travado'.

O caso real: o kali_runner ficou 'Up (healthy)' por 20h, mas com a fila de jobs
em memória inchada parou de ACEITAR novos jobs → o scan empacou (milhares em
'queued', 0 em execução), sem nenhum container caído. O healthcheck raso (/healthz)
não pegou.

Este watchdog (rodado pelo celery-beat a cada minuto):
  1. PROBE FUNCIONAL do kali (não só ping): se travar, REINICIA o kali.
  2. DETECTA stall de dispatch do scan (queued>0 e 0 em execução) e re-enfileira
     itens presos em dispatched/submitted há muito tempo.
Sempre registra um alerta para a página de Saúde ver.
"""

from __future__ import annotations

import logging
import os
from datetime import datetime, timedelta

import httpx
from sqlalchemy import text

logger = logging.getLogger("watchdog")

_KALI_URL = os.getenv("KALI_RUNNER_URL", "http://kali_runner:8088").rstrip("/")
_KALI_CONTAINER = os.getenv("KALI_CONTAINER", "scriptkiddo_kali_runner")
_STUCK_MINUTES = int(os.getenv("WATCHDOG_STUCK_MINUTES", "12"))
# Tempo sem atualização antes de tratar um scan não-terminal como órfão em limbo.
# Cobre o caso real: restart do worker/backend perde a mensagem .delay() e o scan
# fica 'queued' para sempre, invisível à recuperação antiga (que só via 'running').
_LIMBO_SECONDS = int(os.getenv("WATCHDOG_LIMBO_SECONDS", "180"))


def _kali_functional_ok() -> bool:
    """Probe FUNCIONAL: o kali aceita listar jobs rápido? (pega o 'wedge')."""
    try:
        with httpx.Client(timeout=httpx.Timeout(connect=3.0, read=6.0, write=3.0, pool=3.0)) as c:
            r = c.get(f"{_KALI_URL}/jobs")
            return r.status_code < 500
    except Exception:
        # também tenta o /healthz como segunda chance
        try:
            with httpx.Client(timeout=5.0) as c:
                return c.get(f"{_KALI_URL}/healthz").status_code < 500
        except Exception:
            return False


def _restart_kali() -> bool:
    """Reinicia o kali_runner via Docker (requer socket rw). Limpa o estado inchado."""
    try:
        import docker
        client = docker.from_env()
        client.containers.get(_KALI_CONTAINER).restart(timeout=20)
        logger.warning("watchdog: kali_runner REINICIADO (estava travado)")
        return True
    except Exception as exc:
        logger.error("watchdog: falha ao reiniciar kali: %s", exc)
        return False


def run_watchdog(db) -> dict:
    """Verifica saúde funcional + stall de scan; auto-recupera. Idempotente."""
    report = {"kali_functional": True, "kali_restarted": False,
              "stalled_scans": [], "requeued": 0, "checked_at": datetime.utcnow().isoformat()}

    # Prova de vida do auto-curador: grava ANTES de qualquer trabalho, para que o
    # guardião do backend saiba que beat→worker_scope→watchdog está vivo.
    try:
        from app.services.platform_health import record_watchdog_heartbeat
        record_watchdog_heartbeat()
    except Exception:
        pass

    # ── Capacidade ADAPTATIVA (AIMD por saúde): sobe/desce o paralelismo ─────
    try:
        from app.services.adaptive_capacity import adjust as _adjust_cap
        report["adaptive"] = _adjust_cap(db)
    except Exception as _ac_err:
        logger.debug("adaptive_capacity failed: %s", _ac_err)

    # ── 1. kali funcional? senão, reinicia ──────────────────────────────────
    if not _kali_functional_ok():
        report["kali_functional"] = False
        report["kali_restarted"] = _restart_kali()

    # ── 2. stall de dispatch nos scans em execução ──────────────────────────
    rows = db.execute(text("""
        SELECT s.id,
          count(*) FILTER (WHERE w.status = 'queued') AS queued,
          count(*) FILTER (WHERE w.status IN ('running','dispatched')) AS active,
          count(*) FILTER (WHERE w.status='dispatched' AND w.updated_at < now() - interval '%d minutes') AS stuck_dispatched
        FROM scan_jobs s JOIN scan_work_items w ON w.scan_job_id = s.id
        WHERE s.status = 'running'
        GROUP BY s.id
    """ % _STUCK_MINUTES)).fetchall()

    revived = []
    for sid, queued, active, stuck in rows:
        # stall = há trabalho na fila mas NADA executando (dispatch parou)
        if int(queued or 0) > 0 and int(active or 0) == 0:
            # AUTO-RECUPERAÇÃO via entry point canônico: ele NÃO re-dispara se a
            # chain do scan ainda está viva (chain lock presente). Uma fase lenta
            # (kali) deixa scan_work_items sem 'active' por minutos sem que o driver
            # tenha morrido — re-disparar nesse caso criava chains PARALELAS (causa
            # raiz do scan #8 duplicado).
            try:
                from app.workers.tasks import ensure_scan_chain_running
                _res = ensure_scan_chain_running(int(sid), mode="unit")
                if _res.get("enqueued"):
                    report["stalled_scans"].append({"scan_id": int(sid), "queued": int(queued)})
                    logger.warning("watchdog: scan %s EMPACADO (queued=%s, active=0) → re-disparado", sid, queued)
                    revived.append(int(sid))
                else:
                    logger.info("watchdog: scan %s queued=%s active=0 mas chain VIVA (%s) → não re-disparando",
                                sid, queued, _res.get("reason"))
            except Exception as exc:
                logger.error("watchdog: falha ao re-disparar scan %s: %s", sid, exc)
        # re-enfileira itens presos em dispatched há muito tempo (kali perdeu o job)
        if int(stuck or 0) > 0:
            res = db.execute(text("""
                UPDATE scan_work_items SET status='queued', updated_at=now()
                WHERE scan_job_id=:sid AND status='dispatched'
                  AND updated_at < now() - interval '%d minutes'
            """ % _STUCK_MINUTES), {"sid": int(sid)})
            report["requeued"] += int(getattr(res, "rowcount", 0) or 0)
    report["revived_scans"] = revived

    if report["requeued"]:
        db.commit()

    # ── 3. scans em LIMBO: não-terminais porém SEM execução real ─────────────
    # (queued/running/retrying com updated_at antigo e SEM chain lock viva). É o
    # buraco que deixava #9/#10/#11 'queued' para sempre: a recuperação acima só
    # olha status='running'. Aqui pegamos QUALQUER status recuperável. O helper é
    # idempotente (no-op se o lock está vivo) e limita os re-disparos.
    limbo_revived = []
    try:
        # cutoff em UTC-naive (coluna updated_at é UTC-naive). Comparar com now()
        # do postgres (-03) desviava ~3h e só pegava scans muito antigos.
        _cutoff = datetime.utcnow() - timedelta(seconds=_LIMBO_SECONDS)
        limbo_rows = db.execute(text(
            "SELECT id FROM scan_jobs WHERE status IN ('queued','running','retrying') "
            "AND updated_at < :cutoff ORDER BY id"
        ), {"cutoff": _cutoff}).fetchall()
        if limbo_rows:
            from app.workers.tasks import recover_scan_if_orphaned, active_scan_task_ids
            active_ids, inspect_ok = active_scan_task_ids()
            for (sid,) in limbo_rows:
                if int(sid) in revived:
                    continue
                res = recover_scan_if_orphaned(int(sid), mode="unit", source="watchdog",
                                               active_ids=active_ids, inspect_ok=inspect_ok)
                if res.get("action") in ("redriven", "failed_budget"):
                    limbo_revived.append({"scan_id": int(sid), **res})
                    logger.warning("watchdog: scan %s em LIMBO → %s", sid, res.get("action"))
    except Exception as exc:
        logger.error("watchdog: pass de limbo falhou: %s", exc)
    report["limbo_recovered"] = limbo_revived

    # guarda o último resultado para a página de Saúde
    try:
        db.execute(text("""
            INSERT INTO scan_logs (scan_job_id, source, level, message, created_at)
            SELECT (SELECT id FROM scan_jobs ORDER BY id DESC LIMIT 1), 'watchdog',
                   CASE WHEN :alert THEN 'WARN' ELSE 'INFO' END, :msg, now()
            WHERE EXISTS (SELECT 1 FROM scan_jobs)
        """), {"alert": (not report["kali_functional"]) or bool(report["stalled_scans"]),
               "msg": f"watchdog kali_ok={report['kali_functional']} restarted={report['kali_restarted']} "
                      f"stalled={len(report['stalled_scans'])} requeued={report['requeued']}"})
        db.commit()
    except Exception:
        db.rollback()

    return report
