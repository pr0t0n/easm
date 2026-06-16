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
# Item 27 (definitivo) — recuperação baseada em PROGRESSO REAL (último scan_log),
# SEM depender do celery inspect (instável → deixava o scan travado até o TTL de
# 90min do lock). Sem nenhum scan_log por este tempo num scan não-terminal = órfão
# → libera o lock e re-dispara. Threshold > maior ferramenta legítima (ZAP active
# ~30min é gated/raro; o operador loga mcp/checkpoint constantemente quando vivo).
_ORPHAN_NO_PROGRESS_SECONDS = int(os.getenv("WATCHDOG_ORPHAN_NO_PROGRESS", "720"))  # 12min


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
              "stalled_scans": [], "requeued": 0, "checked_at": datetime.now().isoformat()}

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
        _cutoff = datetime.now() - timedelta(seconds=_LIMBO_SECONDS)
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

    # ── 3b. Item 27 (DEFINITIVO) — órfão por FALTA DE PROGRESSO real ─────────
    # Não depende de celery inspect (instável). Para cada scan não-terminal: se
    # NÃO há scan_log há > _ORPHAN_NO_PROGRESS_SECONDS, está morto (o operador
    # loga mcp/dispatch/checkpoint o tempo todo quando vivo) → ROUBA o lock
    # (force release) e re-dispara. É exatamente o que era feito na mão.
    progress_revived = []
    try:
        from app.workers.tasks import _force_release_chain_lock, ensure_scan_chain_running
        from app.models.models import ScanLog
        # Relógio ÚNICO (-03): created_at agora é gravado pelo app em -03 (naive,
        # via datetime.now() com TZ=America/Sao_Paulo) e now() do PG também é -03 →
        # comparar direto é consistente, idle real. Exclui os próprios logs do
        # watchdog (senão a recuperação reseta o sinal de vida).
        stuck = db.execute(text(
            """
            SELECT j.id,
                   EXTRACT(EPOCH FROM (now() - COALESCE(
                       (SELECT max(l.created_at) FROM scan_logs l
                         WHERE l.scan_job_id = j.id AND l.source <> 'watchdog'),
                       j.updated_at)))::int AS idle_s
            FROM scan_jobs j
            WHERE j.status IN ('queued','running','retrying')
            """
        )).fetchall()
        for sid, idle_s in stuck:
            idle = int(idle_s or 0)
            if idle >= _ORPHAN_NO_PROGRESS_SECONDS:
                _force_release_chain_lock(int(sid))
                _res = ensure_scan_chain_running(int(sid), mode="unit")
                progress_revived.append({"scan_id": int(sid), "idle_s": idle, "redispatch": _res})
                db.add(ScanLog(
                    scan_job_id=int(sid), source="watchdog", level="WARNING",
                    message=(f"orfao por SEM-PROGRESSO ({idle}s sem scan_log) → lock liberado "
                             f"e scan re-disparado (item 27, sem depender de celery inspect)"),
                ))
                logger.warning("watchdog: scan %s SEM PROGRESSO %ss → lock liberado + re-disparado", sid, idle)
        if progress_revived:
            db.commit()
    except Exception as exc:
        db.rollback()
        logger.error("watchdog: pass de progresso (item 27) falhou: %s", exc)
    report["progress_recovered"] = progress_revived

    # ── 3c. A3 — CADEIA MORTA por AUSÊNCIA DE LOCK (não depende de log) ───────
    # Bug real (scan #15): a cadeia principal (run_scan_job_unit, que avança as
    # fases) morreu, mas os pollers da fila paralela seguiram logando → os passes
    # baseados em "log recente" / "updated_at recente" não disparavam. Aqui o
    # sinal de vida é o PRÓPRIO chain lock (com B1 ele expira em ≤TTL quando o
    # worker morre). Para todo scan running SEM lock → recupera (o helper cruza
    # com celery inspect e tem orçamento de re-disparo, então é seguro mesmo na
    # janela curta entre phase-units).
    deadchain_revived = []
    try:
        from app.workers.tasks import recover_scan_if_orphaned, _chain_lock_alive, active_scan_task_ids
        running_ids = [int(r[0]) for r in db.execute(text(
            "SELECT id FROM scan_jobs WHERE status='running' ORDER BY id"
        )).fetchall()]
        no_lock = [sid for sid in running_ids if not _chain_lock_alive(sid)]
        if no_lock:
            active_ids, inspect_ok = active_scan_task_ids()
            # Só re-dispara o que é ORFÃO de verdade: sem lock E sem task ativa no
            # celery. Isso evita falso-positivo na janela curta entre phase-units
            # (sem lock, porém a próxima unit já está ativa) — que, repetido,
            # esgotaria o orçamento de re-disparo de um scan saudável. Se o inspect
            # não respondeu (inspect_ok=False) → conservador: não mexe.
            truly_orphan = [sid for sid in no_lock if inspect_ok and sid not in active_ids]
            for sid in truly_orphan:
                res = recover_scan_if_orphaned(sid, mode="unit", source="watchdog-deadchain",
                                               active_ids=active_ids, inspect_ok=inspect_ok)
                if res.get("action") in ("redriven", "failed_budget"):
                    deadchain_revived.append({"scan_id": sid, **res})
                    logger.warning("watchdog: scan %s CADEIA MORTA (running sem lock) → %s",
                                   sid, res.get("action"))
        if deadchain_revived:
            db.commit()
    except Exception as exc:
        db.rollback()
        logger.error("watchdog: pass de cadeia-morta (A3) falhou: %s", exc)
    report["deadchain_recovered"] = deadchain_revived

    # ── 3d. A1 — PROMOTOR de scans em espera (admissão) ──────────────────────
    # Sobe scans diferidos por limite de concorrência quando abre vaga (FIFO).
    # Agendado nunca preempta: só entra aqui quando há espaço de fato.
    try:
        from app.workers.tasks import promote_deferred_scans
        _prom = promote_deferred_scans()
        report["scans_promoted"] = _prom.get("promoted", [])
        if _prom.get("promoted"):
            logger.warning("watchdog: scans promovidos da fila de admissão: %s", _prom["promoted"])
    except Exception as exc:
        logger.error("watchdog: promotor de admissão (A1) falhou: %s", exc)
        report["scans_promoted"] = []

    # Item 20 — limpeza segura da fila: itens pendentes (queued/blocked/
    # submitted/retry) de scans JÁ TERMINAIS nunca rodarão e só incham a tabela
    # (scan #12 chegou a 6072 blocked). Remover é seguro — o scan acabou.
    try:
        purged = db.execute(text("""
            DELETE FROM scan_work_items
            WHERE status IN ('queued','blocked','submitted','retry')
              AND scan_job_id IN (
                  SELECT id FROM scan_jobs
                  WHERE lower(status) IN ('completed','failed','stopped','cancelled')
              )
        """))
        db.commit()
        report["queue_purged"] = int(getattr(purged, "rowcount", 0) or 0)
    except Exception as exc:
        db.rollback()
        logger.error("watchdog: limpeza de fila falhou: %s", exc)
        report["queue_purged"] = 0

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
