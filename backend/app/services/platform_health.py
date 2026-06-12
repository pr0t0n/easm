"""Saúde da plataforma — visão Docker de todos os containers (Centro Operacional).

Lê o Docker socket (read-only) para reportar status/health de cada container do
projeto, com alerta quando algo está fora e o ÚLTIMO log/erro para validar —
exatamente o que faltou quando o worker_parallel caiu (OOM exit 137).

Falha graciosamente: se o socket não estiver disponível, cai num fallback por
heartbeats (worker_heartbeats) + ping de serviços, para nunca quebrar a página.
"""

from __future__ import annotations

import logging
import os
import re
from datetime import datetime, timedelta

logger = logging.getLogger("platform_guard")

# Prefixo dos containers do projeto (compose: container_name scriptkiddo_*).
_PROJECT_PREFIX = os.getenv("HEALTH_CONTAINER_PREFIX", "scriptkiddo_")
_LOG_TAIL = 40
_ERROR_RE = re.compile(r"(error|exception|traceback|killed|oom|fatal|panic|refused|cannot|failed)", re.I)

# ── Self-correction (guardião) ───────────────────────────────────────────────
# Heartbeat que o watchdog (run_watchdog, executado pelo beat→worker_scope a cada
# minuto) grava a cada tick. É a prova de vida do PRÓPRIO auto-curador: se ficar
# velho, o laço de auto-recuperação está quebrado (beat morto ou worker_scope sem
# consumir) e o backend — sempre de pé — revive a espinha do laço.
_WATCHDOG_HEARTBEAT_KEY = "platform:watchdog_heartbeat"
_WATCHDOG_STALE_SECONDS = int(os.getenv("WATCHDOG_STALE_SECONDS", "180"))      # 3 ticks perdidos
_SELF_HEAL_COOLDOWN = int(os.getenv("SELF_HEAL_COOLDOWN_SECONDS", "45"))       # anti-martelo entre polls
_RESTART_COOLDOWN = int(os.getenv("SELF_HEAL_RESTART_COOLDOWN", "300"))        # anti-tempestade de restart
_GUARD_LIMBO_SECONDS = int(os.getenv("WATCHDOG_LIMBO_SECONDS", "180"))

# Containers SEGUROS de reiniciar automaticamente (stateless / consumidores
# idempotentes). NUNCA reinicia postgres/redis (stateful), backend (é onde o
# guardião roda) nem frontend/ollama/zap (caros ou irrelevantes ao scan).
_AUTO_RESTART_NAMES = {"celery_beat", "mcp_server", "kali_runner"}


def _is_auto_restartable(short_name: str) -> bool:
    return short_name.startswith("worker_") or short_name in _AUTO_RESTART_NAMES


def _guard_redis():
    from app.services.scan_work_queue import _redis_client
    return _redis_client()


def record_watchdog_heartbeat() -> None:
    """Prova de vida do auto-curador — chamada a cada tick do watchdog."""
    try:
        _guard_redis().set(_WATCHDOG_HEARTBEAT_KEY, datetime.utcnow().isoformat())
    except Exception:
        pass


_GUARD_HEARTBEAT_KEY = "platform:guard_heartbeat"


def record_guard_heartbeat() -> None:
    """Prova de vida do guardião do backend (thread daemon)."""
    try:
        _guard_redis().set(_GUARD_HEARTBEAT_KEY, datetime.utcnow().isoformat())
    except Exception:
        pass


def _watchdog_heartbeat_age() -> float | None:
    """Idade (s) do último heartbeat do watchdog; None se ausente/ilegível."""
    try:
        raw = _guard_redis().get(_WATCHDOG_HEARTBEAT_KEY)
        if not raw:
            return None
        if isinstance(raw, bytes):
            raw = raw.decode()
        return (datetime.utcnow() - datetime.fromisoformat(raw)).total_seconds()
    except Exception:
        return None


def _restart_container(short_or_full: str, reason: str) -> dict:
    """Reinicia um container via Docker, com cooldown por-container no redis para
    evitar tempestade de restart. Falha graciosamente (reporta, não levanta)."""
    name = short_or_full if short_or_full.startswith(_PROJECT_PREFIX) else f"{_PROJECT_PREFIX}{short_or_full}"
    short = name.replace(_PROJECT_PREFIX, "")
    try:
        r = _guard_redis()
        if r.get(f"platform:self_heal:restart:{short}"):
            return {"container": short, "action": "skip_cooldown", "reason": reason}
        r.set(f"platform:self_heal:restart:{short}", datetime.utcnow().isoformat(), ex=_RESTART_COOLDOWN)
    except Exception:
        pass
    try:
        import docker
        docker.from_env().containers.get(name).restart(timeout=20)
        logger.warning("guard: container %s REINICIADO (%s)", short, reason)
        return {"container": short, "action": "restarted", "reason": reason}
    except Exception as exc:
        logger.error("guard: falha ao reiniciar %s: %s", short, exc)
        return {"container": short, "action": "restart_failed", "reason": reason, "error": str(exc)[:160]}


def run_platform_self_heal(db=None, *, source: str = "auto", force: bool = False,
                           docker_view: dict | None = None) -> dict:
    """Guardião independente (roda no backend, sempre de pé).

    Fecha o meta-SPOF "quem vigia o vigia": o watchdog se auto-cura, mas se o
    PRÓPRIO laço (beat/worker_scope) cair, ninguém o revive. Este guardião:
      1. Checa o heartbeat do watchdog; se velho → reinicia celery_beat + worker_scope.
      2. Reinicia containers stateless caídos (workers/mcp/kali), com cooldown.
      3. Re-dispara scans órfãos/limbo direto (independe do beat — só precisa de
         redis+DB+fila, que o backend tem).
    Idempotente e protegido por cooldown, então é barato chamar a cada poll."""
    report = {
        "checked_at": datetime.utcnow().isoformat(), "source": source,
        "corrections": [], "orphans_recovered": [], "watchdog": {}, "skipped": False,
    }

    if not force:
        # cooldown global: só age uma vez por janela, mesmo sob polling intenso.
        try:
            if not _guard_redis().set("platform:self_heal:cooldown", source, nx=True, ex=_SELF_HEAL_COOLDOWN):
                report["skipped"] = True
                return report
        except Exception:
            pass

    # 1. Vida do auto-curador ────────────────────────────────────────────────
    age = _watchdog_heartbeat_age()
    alive = age is not None and age <= _WATCHDOG_STALE_SECONDS
    report["watchdog"] = {"heartbeat_age_seconds": age, "stale_threshold": _WATCHDOG_STALE_SECONDS, "alive": alive}
    if not alive:
        for c in ("celery_beat", "worker_scope"):
            report["corrections"].append(_restart_container(c, reason=f"watchdog_stale(age={age})"))

    # 2. Containers stateless caídos ──────────────────────────────────────────
    view = docker_view if docker_view is not None else _docker_view()
    if view and view.get("source") == "docker":
        for c in view.get("containers", []):
            if not c.get("is_alert"):
                continue
            short = str(c.get("name") or "")
            status = str(c.get("status") or "")
            if _is_auto_restartable(short) and any(k in status for k in ("exited", "dead", "restarting")):
                report["corrections"].append(_restart_container(short, reason=f"container_{status}"))

    # 3. Scans órfãos/limbo (independe do beat) ────────────────────────────────
    if db is not None:
        try:
            from sqlalchemy import text as _t
            from app.workers.tasks import recover_scan_if_orphaned, active_scan_task_ids
            # cutoff em UTC-naive (a coluna updated_at é UTC-naive); evita o desvio
            # de fuso de comparar com now() do postgres (que está em -03).
            cutoff = datetime.utcnow() - timedelta(seconds=_GUARD_LIMBO_SECONDS)
            rows = db.execute(_t(
                "SELECT id FROM scan_jobs WHERE status IN ('queued','running','retrying') "
                "AND updated_at < :cutoff ORDER BY id"
            ), {"cutoff": cutoff}).fetchall()
            # inspeciona as tasks ativas UMA vez (caro) e reusa para todos os scans.
            active_ids, inspect_ok = active_scan_task_ids() if rows else (set(), True)
            for (sid,) in rows:
                res = recover_scan_if_orphaned(int(sid), mode="unit", source=f"guard:{source}",
                                               active_ids=active_ids, inspect_ok=inspect_ok)
                if res.get("action") in ("redriven", "failed_budget"):
                    report["orphans_recovered"].append({"scan_id": int(sid), **res})
        except Exception as exc:
            report["orphan_error"] = str(exc)[:160]

    if report["corrections"] or report["orphans_recovered"]:
        logger.warning("guard[%s]: %d restart(s), %d scan(s) recuperado(s)",
                       source, len(report["corrections"]), len(report["orphans_recovered"]))
    return report

# Papel de cada serviço (para agrupar/explicar na UI).
_ROLE = {
    "backend": "API", "mcp_server": "Gateway MCP", "kali_runner": "Arsenal (Kali)",
    "zap": "Scanner ZAP", "postgres": "Banco", "redis": "Fila/Broker", "ollama": "LLM/Embeddings",
    "frontend": "UI", "celery_beat": "Agendador",
}


def _classify(state: dict, health: str | None) -> tuple[str, bool]:
    """Retorna (status_label, is_alert)."""
    status = str(state.get("Status") or "").lower()
    oom = bool(state.get("OOMKilled"))
    exit_code = state.get("ExitCode")
    if status == "running":
        if health == "unhealthy":
            return "unhealthy", True
        if health in ("starting", None, "", "healthy", "none"):
            return ("healthy" if health == "healthy" else "up"), False
        return "up", False
    if status == "restarting":
        return "restarting", True
    if status in ("exited", "dead"):
        if oom:
            return "oom-killed", True
        return (f"exited({exit_code})" if exit_code not in (0, None) else "exited"), True
    if status in ("created", "paused"):
        return status, True
    return status or "unknown", True


def _docker_view() -> dict | None:
    try:
        import docker
    except Exception:
        return None
    try:
        client = docker.from_env()
        client.ping()
    except Exception:
        return None

    containers = []
    try:
        for c in client.containers.list(all=True):
            name = c.name
            if _PROJECT_PREFIX and not name.startswith(_PROJECT_PREFIX):
                continue
            attrs = c.attrs or {}
            state = attrs.get("State") or {}
            health = ((state.get("Health") or {}).get("Status"))
            label, is_alert = _classify(state, health)
            short = name.replace(_PROJECT_PREFIX, "")
            # últimos logs sempre; destaque de ERRO apenas para containers em
            # alerta (evita falso-positivo de linhas benignas tipo telemetria).
            last_log = ""
            last_error = ""
            try:
                raw = c.logs(tail=_LOG_TAIL, timestamps=False).decode("utf-8", "replace")
                lines = [ln for ln in raw.splitlines() if ln.strip()]
                last_log = "\n".join(lines[-12:])
                if is_alert:
                    err_lines = [ln for ln in lines if _ERROR_RE.search(ln)]
                    last_error = "\n".join(err_lines[-5:]) or "\n".join(lines[-5:])
            except Exception:
                pass
            containers.append({
                "name": short,
                "container": name,
                "role": _ROLE.get(short, ""),
                "status": label,
                "is_alert": is_alert,
                "health": health or "none",
                "exit_code": state.get("ExitCode"),
                "oom_killed": bool(state.get("OOMKilled")),
                "started_at": state.get("StartedAt"),
                "finished_at": state.get("FinishedAt"),
                "image": (attrs.get("Config") or {}).get("Image"),
                "restart_count": attrs.get("RestartCount"),
                "last_log": last_log,
                "last_error": last_error or None,
            })
    except Exception:
        return None

    containers.sort(key=lambda x: (not x["is_alert"], x["name"]))
    alerts = [c for c in containers if c["is_alert"]]
    return {
        "source": "docker",
        "total": len(containers),
        "up": sum(1 for c in containers if not c["is_alert"]),
        "down": len(alerts),
        "all_healthy": len(alerts) == 0,
        "alerts": [c["name"] for c in alerts],
        "containers": containers,
    }


def _fallback_view(db) -> dict:
    """Sem socket: heartbeats dos workers + ping de serviços."""
    from datetime import datetime, timedelta
    from sqlalchemy import text as _t

    containers: list[dict] = []

    # Workers via heartbeat (stale > 180s = down).
    try:
        rows = db.execute(_t(
            "SELECT worker_name, status, last_seen_at FROM worker_heartbeats ORDER BY worker_name"
        )).fetchall()
        now = datetime.utcnow()
        for wn, st, seen in rows:
            stale = True
            if seen:
                try:
                    stale = (now - seen) > timedelta(seconds=180)
                except Exception:
                    stale = True
            containers.append({
                "name": str(wn), "role": "Worker", "status": "down" if stale else "up",
                "is_alert": stale, "health": "none", "last_log": "", "last_error": None,
                "last_seen_at": str(seen) if seen else None,
            })
    except Exception:
        pass

    # Serviços externos por ping.
    for svc in _ping_services():
        containers.append(svc)

    alerts = [c for c in containers if c["is_alert"]]
    return {
        "source": "fallback", "total": len(containers),
        "up": sum(1 for c in containers if not c["is_alert"]),
        "down": len(alerts), "all_healthy": len(alerts) == 0,
        "alerts": [c["name"] for c in alerts], "containers": containers,
        "note": "Docker socket indisponível — visão por heartbeat + ping (sem logs de container).",
    }


def _ping_services() -> list[dict]:
    import httpx
    out = []
    checks = [
        ("kali_runner", os.getenv("KALI_RUNNER_URL", "http://kali_runner:8088") + "/health", "Arsenal (Kali)"),
        ("mcp_server", os.getenv("MCP_SERVER_URL", "http://mcp_server:3000") + "/health", "Gateway MCP"),
        ("zap", os.getenv("ZAP_URL", "http://zap:8090") + "/JSON/core/view/version/", "Scanner ZAP"),
        ("ollama", os.getenv("OLLAMA_BASE_URL", "http://ollama:11434") + "/api/tags", "LLM/Embeddings"),
    ]
    for name, url, role in checks:
        ok = False
        try:
            r = httpx.get(url, timeout=4)
            ok = r.status_code < 500
        except Exception:
            ok = False
        out.append({"name": name, "role": role, "status": "up" if ok else "down",
                    "is_alert": not ok, "health": "none", "last_log": "", "last_error": None})
    return out


def _adaptive_capacity_view() -> dict | None:
    """Nível adaptativo de concorrência atual (visibilidade do AIMD)."""
    try:
        from app.services.adaptive_capacity import get_level, get_capacity, MIN_L, MAX_L
        return {"level": get_level(), "min": MIN_L, "max": MAX_L, "capacity": get_capacity()}
    except Exception:
        return None


def get_environment_logs(kind: str = "workers", tail: int = 50) -> dict:
    """Últimas `tail` linhas de log dos containers, para a tela Admin · Logs.

    kind="workers" → todos os containers scriptkiddo_worker_* (execução dos scans).
    kind="comms"   → mcp_server (gateway interno de ferramentas) + kali_runner
                     (requisições externas aos alvos) + backend (API/requisições).
    Lê via Docker socket; falha graciosamente por container."""
    tail = max(1, min(int(tail or 50), 500))
    try:
        import docker
        client = docker.from_env()
        client.ping()
    except Exception as exc:
        return {"kind": kind, "tail": tail, "available": False,
                "error": f"Docker indisponivel: {str(exc)[:120]}", "sources": []}

    if kind == "comms":
        wanted = ["mcp_server", "kali_runner", "backend"]
        roles = {"mcp_server": "Gateway MCP (interno)", "kali_runner": "Arsenal Kali (externo)", "backend": "API / requisições"}
        names = [f"{_PROJECT_PREFIX}{w}" for w in wanted]
    else:
        kind = "workers"
        names = []
        try:
            for c in client.containers.list(all=True):
                if c.name.startswith(f"{_PROJECT_PREFIX}worker_") or c.name == f"{_PROJECT_PREFIX}celery_beat":
                    names.append(c.name)
        except Exception:
            pass
        names.sort()
        roles = {}

    sources = []
    for name in names:
        short = name.replace(_PROJECT_PREFIX, "")
        entry = {"name": short, "container": name, "role": roles.get(short, "Worker"), "lines": [], "error": None}
        try:
            ct = client.containers.get(name)
            raw = ct.logs(tail=tail, timestamps=True).decode("utf-8", "replace")
            entry["lines"] = [ln for ln in raw.splitlines() if ln.strip()][-tail:]
            entry["status"] = ct.status
        except Exception as exc:
            entry["error"] = str(exc)[:140]
        sources.append(entry)

    return {"kind": kind, "tail": tail, "available": True, "sources": sources}


def get_platform_health(db=None) -> dict:
    """Visão de saúde da plataforma + AUTO-CORREÇÃO.

    Prefere Docker; cai em fallback. A cada chamada também roda o guardião de
    auto-correção (cooldown-gated): como a UI de Saúde e o Centro Operacional
    fazem polling deste endpoint, a plataforma se vigia e se cura continuamente
    enquanto observada — em cima da thread de guarda do backend (sempre de pé)."""
    view = _docker_view()
    if view is None:
        view = _fallback_view(db)
    view["adaptive_capacity"] = _adaptive_capacity_view()
    try:
        view["self_heal"] = run_platform_self_heal(
            db, source="health_poll",
            docker_view=view if view.get("source") == "docker" else None,
        )
    except Exception as exc:
        view["self_heal"] = {"error": str(exc)[:160]}
    return view
