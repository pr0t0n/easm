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
# Item 27 — recuperação baseada no último scan_log, corroborada pela atividade
# do Kali Runner. O limiar precisa ser maior que o maior job normal do P01
# (amass_brute=900s); 720s fazia o watchdog roubar um lock ainda legítimo.
_ORPHAN_NO_PROGRESS_SECONDS = int(os.getenv("WATCHDOG_ORPHAN_NO_PROGRESS", "1200"))  # 20min
_IDLE_TX_REAPER_SECONDS = int(os.getenv("WATCHDOG_IDLE_TX_REAPER_SECONDS", "90"))


def _reap_idle_transactions(db) -> list[dict]:
    """Terminate app sessions that are idle inside a transaction too long.

    This is a last-resort guardrail. The primary fix is the PostgreSQL
    per-connection idle_in_transaction_session_timeout configured in
    app.db.session. The watchdog reaper covers old pooled connections and gives
    us durable telemetry when a code path violates the no-long-transaction
    contract.
    """
    rows = db.execute(text("""
        SELECT pid,
               now() - xact_start AS age,
               left(coalesce(query, ''), 500) AS query
          FROM pg_stat_activity
         WHERE datname = current_database()
           AND usename = current_user
           AND pid <> pg_backend_pid()
           AND state = 'idle in transaction'
           AND xact_start IS NOT NULL
           AND xact_start < now() - (:seconds || ' seconds')::interval
         ORDER BY xact_start
         LIMIT 25
    """), {"seconds": int(_IDLE_TX_REAPER_SECONDS)}).fetchall()
    killed: list[dict] = []
    for pid, age, query in rows:
        ok = bool(db.execute(text("SELECT pg_terminate_backend(:pid)"), {"pid": int(pid)}).scalar())
        killed.append({"pid": int(pid), "age": str(age), "terminated": ok, "query": str(query or "")[:500]})
    return killed


def _kali_scan_has_active_jobs(scan_id: int) -> bool | None:
    """Return runner proof-of-life for one scan without Celery inspect.

    ``None`` means the runner could not be inspected. Running/queued responses
    are intentionally requested separately: those rows have no captured stdout,
    so the response remains small even when the historical job store is large.
    """
    try:
        with httpx.Client(timeout=httpx.Timeout(connect=3.0, read=6.0, write=3.0, pool=3.0)) as client:
            for job_status in ("running", "queued"):
                response = client.get(
                    f"{_KALI_URL}/jobs",
                    params={"status": job_status, "limit": 1000},
                )
                response.raise_for_status()
                payload = response.json()
                for item in payload.get("items") or []:
                    if int(item.get("scan_id") or -1) == int(scan_id):
                        return True
        return False
    except Exception:
        return None


def _no_progress_recovery_blocker(
    scan_id: int,
    runner_active: bool | None,
    active_ids: set[int] | list[int] | tuple[int, ...],
    inspect_ok: bool | None,
) -> str | None:
    """Return why the no-progress watchdog must *not* redrive a scan yet.

    The no-progress pass exists to recover truly orphaned scans, but scan #22
    exposed a narrow race: a long P01 had just finished in Kali Runner and the
    Celery phase task was still consolidating/persisting results. Runner looked
    idle for a few seconds, so the watchdog force-released the chain lock and
    launched a duplicate P01.

    Redrive is only safe when we have positive proof that neither execution
    plane is active: no Kali job and Celery inspect succeeded with no active
    scan task.
    """
    if runner_active is True:
        return "kali_runner_active"
    if inspect_ok is not True:
        return "celery_inspect_unknown"
    try:
        normalized_active_ids = {int(sid) for sid in active_ids}
    except Exception:
        normalized_active_ids = set()
    if int(scan_id) in normalized_active_ids:
        return "celery_task_active"
    return None


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
              "stalled_scans": [], "requeued": 0, "checked_at": datetime.now().isoformat(),
              "idle_transactions_killed": []}

    # Prova de vida do auto-curador: grava ANTES de qualquer trabalho, para que o
    # guardião do backend saiba que beat→worker_scope→watchdog está vivo.
    try:
        from app.services.platform_health import record_watchdog_heartbeat
        record_watchdog_heartbeat()
    except Exception:
        pass

    # ── 0. DB lock guardrail: no idle transaction may survive long enough to
    # freeze scan progress. Commit before/after so the watchdog itself does not
    # become a lock holder.
    try:
        db.commit()
        killed_idle = _reap_idle_transactions(db)
        if killed_idle:
            report["idle_transactions_killed"] = killed_idle
            db.execute(text("""
                INSERT INTO scan_logs (scan_job_id, source, level, message, created_at)
                SELECT (SELECT id FROM scan_jobs ORDER BY id DESC LIMIT 1),
                       'watchdog',
                       'WARN',
                       :message,
                       now()
            """), {"message": f"idle_transaction_reaper killed={killed_idle}"[:4000]})
        db.commit()
    except Exception as _idle_reaper_err:
        db.rollback()
        logger.debug("idle_transaction_reaper failed: %s", _idle_reaper_err)

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

    # ── 1b. Poller rehydration from durable DB state ─────────────────────────
    # A submitted scan_work_item may outlive its volatile Celery poll message.
    # Recreate stale pollers before the stale-active repair below, otherwise a
    # terminal Kali job can be converted into retry/failed without first fetching
    # and preserving its result/evidence.
    try:
        from app.workers.tasks import _rehydrate_stale_work_item_pollers

        running_scan_ids = [
            int(row[0])
            for row in db.execute(text("SELECT id FROM scan_jobs WHERE status='running'")).fetchall()
        ]
        for _sid in running_scan_ids:
            _rehydrate_stale_work_item_pollers(
                db,
                _sid,
                stale_after_seconds=45,
                limit=200,
                source="watchdog",
            )
        db.commit()
    except Exception as _rehydrate_err:
        db.rollback()
        logger.debug("watchdog poller_rehydration failed: %s", _rehydrate_err)

    # ── 2. stall de dispatch nos scans em execução ──────────────────────────
    rows = db.execute(text("""
        SELECT s.id,
          count(*) FILTER (WHERE w.status = 'queued') AS queued,
          count(*) FILTER (WHERE w.status IN ('running','dispatched','submitted')) AS active,
          count(*) FILTER (
            WHERE w.status IN ('running','dispatched','submitted')
              AND w.lease_until IS NOT NULL
              AND w.lease_until <= now()
          ) AS expired_active,
          count(*) FILTER (
            WHERE w.status IN ('running','dispatched','submitted')
              AND w.lease_until IS NULL
              AND w.updated_at < now() - interval '%d minutes'
          ) AS orphan_without_lease
        FROM scan_jobs s JOIN scan_work_items w ON w.scan_job_id = s.id
        WHERE s.status = 'running'
        GROUP BY s.id
    """ % _STUCK_MINUTES)).fetchall()

    revived = []
    stale_repaired = []
    for sid, queued, active, expired, stuck in rows:
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
        # Repara itens ativos órfãos. Lease é o contrato de posse: se ainda está
        # no futuro, uma ferramenta longa pode estar saudável mesmo sem tocar
        # updated_at. Só mexemos quando o lease venceu ou quando nem existe lease
        # e o item está velho.
        if int(expired or 0) > 0 or int(stuck or 0) > 0:
            retry_res = db.execute(text("""
                UPDATE scan_work_items
                   SET status='retry',
                       lease_until=NULL,
                       updated_at=now(),
                       last_error='watchdog_stale_active_requeued'
                 WHERE scan_job_id=:sid
                   AND status IN ('running','dispatched','submitted')
                   AND attempts < max_attempts
                   AND (
                     lease_until <= now()
                     OR (lease_until IS NULL AND updated_at < now() - interval '%d minutes')
                   )
            """ % _STUCK_MINUTES), {"sid": int(sid)})
            fail_res = db.execute(text("""
                UPDATE scan_work_items
                   SET status='failed',
                       lease_until=NULL,
                       finished_at=now(),
                       updated_at=now(),
                       last_error='watchdog_stale_active_max_attempts'
                 WHERE scan_job_id=:sid
                   AND status IN ('running','dispatched','submitted')
                   AND attempts >= max_attempts
                   AND (
                     lease_until <= now()
                     OR (lease_until IS NULL AND updated_at < now() - interval '%d minutes')
                   )
            """ % _STUCK_MINUTES), {"sid": int(sid)})
            requeued = int(getattr(retry_res, "rowcount", 0) or 0)
            failed = int(getattr(fail_res, "rowcount", 0) or 0)
            if requeued or failed:
                report["requeued"] += requeued
                report["stale_failed"] = int(report.get("stale_failed", 0) or 0) + failed
                stale_repaired.append({"scan_id": int(sid), "requeued": requeued, "failed": failed})
    report["revived_scans"] = revived
    report["stale_repaired"] = stale_repaired

    # Commit unconditionally: this closes out section 2's transaction (open
    # since the SELECT at the top of this section) BEFORE the next sections
    # make their own blocking network calls (celery inspect, kali HTTP,
    # .delay()). Leaving it open across those calls is what let a single slow
    # broker/runner response turn into a multi-hour idle-in-transaction lock
    # on scan_jobs, freezing every write on the platform (2026-07-25 incident).
    db.commit()
    if report["requeued"] or stale_repaired:
        try:
            from app.workers.tasks import _schedule_scan_work_dispatch
            for item in stale_repaired:
                _schedule_scan_work_dispatch(int(item["scan_id"]))
        except Exception as exc:
            logger.error("watchdog: falha ao acordar dispatcher apos reparo stale: %s", exc)

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
        # End this read's transaction NOW, before active_scan_task_ids() (celery
        # inspect RPC) and recover_scan_if_orphaned() (more network + DB) run —
        # those calls have no bound tight enough to safely hold a lock open
        # across them. See commit note in section 2 above for the incident.
        db.commit()
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
        db.rollback()
        logger.error("watchdog: pass de limbo falhou: %s", exc)
    report["limbo_recovered"] = limbo_revived

    # ── 3b. Item 27 — órfão por FALTA DE PROGRESSO real ──────────────────────
    # Antes de roubar o lock exige ausência comprovada nos dois planos:
    #   (1) sem job ativo no Kali Runner;
    #   (2) celery inspect respondeu e não há task ativa do scan.
    # Isso fecha a janela vista no scan #22: o Runner terminou o último job P01,
    # mas a task Celery ainda estava consolidando/persistindo P01; re-disparar
    # nessa janela duplicava a fase.
    progress_revived = []
    progress_runner_active = []
    try:
        from app.workers.tasks import _force_release_chain_lock, ensure_scan_chain_running, active_scan_task_ids
        from app.models.models import ScanLog
        active_ids, inspect_ok = active_scan_task_ids()
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
        # Close this read's transaction before the loop's network calls
        # (kali HTTP, chain-lock release, celery .delay()) — see section 2 note.
        db.commit()
        for sid, idle_s in stuck:
            idle = int(idle_s or 0)
            if idle >= _ORPHAN_NO_PROGRESS_SECONDS:
                runner_active = _kali_scan_has_active_jobs(int(sid))
                blocker = _no_progress_recovery_blocker(int(sid), runner_active, active_ids, inspect_ok)
                if blocker:
                    progress_runner_active.append({"scan_id": int(sid), "idle_s": idle, "blocker": blocker})
                    logger.info(
                        "watchdog: scan %s sem scan_log ha %ss, mas %s; preservando lock",
                        sid,
                        idle,
                        blocker,
                    )
                    continue
                _force_release_chain_lock(int(sid))
                _res = ensure_scan_chain_running(int(sid), mode="unit")
                progress_revived.append({"scan_id": int(sid), "idle_s": idle, "redispatch": _res})
                db.add(ScanLog(
                    scan_job_id=int(sid), source="watchdog", level="WARNING",
                    message=(f"orfao por SEM-PROGRESSO ({idle}s sem scan_log) → lock liberado "
                             f"e scan re-disparado (item 27, sem runner/celery ativo)"),
                ))
                logger.warning("watchdog: scan %s SEM PROGRESSO %ss → lock liberado + re-disparado", sid, idle)
        if progress_revived:
            db.commit()
    except Exception as exc:
        db.rollback()
        logger.error("watchdog: pass de progresso (item 27) falhou: %s", exc)
    report["progress_recovered"] = progress_revived
    report["progress_runner_active"] = progress_runner_active

    # ── 3c. A3 — CADEIA MORTA por AUSÊNCIA DE LOCK (não depende de log) ───────
    # Bug real (scan #15): a cadeia principal (run_scan_job_unit, que avança as
    # fases) morreu, mas os pollers da fila paralela seguiram logando → os passes
    # baseados em "log recente" / "updated_at recente" não disparavam. Aqui o
    # sinal de vida é o PRÓPRIO chain lock (com B1 ele expira em ≤TTL quando o
    # worker morre). Para todo scan running SEM lock → recupera (o helper cruza
    # com celery inspect e tem orçamento de re-disparo, então é seguro mesmo na
    # janela curta entre phase-units). Também precisa cruzar com o Kali Runner:
    # scan #23 provou que P01 pode ficar sem lock/work_items enquanto uma
    # ferramenta longa ainda está viva; sem esse sinal, o deadchain duplicava P01.
    deadchain_revived = []
    deadchain_preserved = []
    try:
        from app.workers.tasks import recover_scan_if_orphaned, _chain_lock_alive, active_scan_task_ids
        running_ids = [int(r[0]) for r in db.execute(text(
            "SELECT id FROM scan_jobs WHERE status='running' ORDER BY id"
        )).fetchall()]
        # Close this read's transaction before _chain_lock_alive (Redis) and
        # active_scan_task_ids (celery inspect) run — see section 2 note.
        db.commit()
        no_lock = [sid for sid in running_ids if not _chain_lock_alive(sid)]
        if no_lock:
            active_ids, inspect_ok = active_scan_task_ids()
            # CADEIA MORTA de verdade exige TRÊS sinais (senão é falso-positivo):
            #  (1) sem chain lock;
            #  (2) sem task run_scan_job ATIVA no celery (inspect_ok=True);
            #  (3) FILA OCIOSA — nenhum work item tocado há > _ORPHAN_NO_PROGRESS;
            #  (4) KALI OCIOSO — nenhum job running/queued para o scan.
            # O (3) é o que faltava: em modo PARALELO a cadeia solta o lock e se
            # re-enfileira por countdown enquanto espera a fila drenar
            # (work_queue_wait) — estado legítimo. Se há itens sendo despachados/
            # polados (updated_at recente), o scan está VIVO mesmo sem lock.
            # Se há job no Kali, P01/P02 ainda está vivo mesmo sem work item.
            # Só re-dispara quando o lock sumiu, a fila parou de fato e o Kali
            # não tem execução ativa.
            _idle_cut = datetime.now() - timedelta(seconds=_ORPHAN_NO_PROGRESS_SECONDS)
            truly_orphan = []
            for sid in no_lock:
                if not inspect_ok or sid in active_ids:
                    continue
                runner_active = _kali_scan_has_active_jobs(sid)
                if runner_active is True:
                    deadchain_preserved.append({"scan_id": sid, "blocker": "kali_runner_active"})
                    logger.info(
                        "watchdog: scan %s running sem lock, mas Kali Runner tem job ativo; preservando deadchain",
                        sid,
                    )
                    continue
                if runner_active is None:
                    deadchain_preserved.append({"scan_id": sid, "blocker": "kali_runner_unknown"})
                    logger.info(
                        "watchdog: scan %s running sem lock, mas Kali Runner nao pode ser inspecionado; preservando deadchain",
                        sid,
                    )
                    continue
                last_item = db.execute(text(
                    "SELECT max(updated_at) FROM scan_work_items WHERE scan_job_id=:s"
                ), {"s": sid}).scalar()
                # fila vazia (last_item None) OU parada há muito → órfão real.
                if last_item is None or last_item < _idle_cut:
                    truly_orphan.append(sid)
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
    report["deadchain_preserved"] = deadchain_preserved

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
