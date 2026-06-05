"""Saúde da plataforma — visão Docker de todos os containers (Centro Operacional).

Lê o Docker socket (read-only) para reportar status/health de cada container do
projeto, com alerta quando algo está fora e o ÚLTIMO log/erro para validar —
exatamente o que faltou quando o worker_parallel caiu (OOM exit 137).

Falha graciosamente: se o socket não estiver disponível, cai num fallback por
heartbeats (worker_heartbeats) + ping de serviços, para nunca quebrar a página.
"""

from __future__ import annotations

import os
import re

# Prefixo dos containers do projeto (compose: container_name scriptkiddo_*).
_PROJECT_PREFIX = os.getenv("HEALTH_CONTAINER_PREFIX", "scriptkiddo_")
_LOG_TAIL = 40
_ERROR_RE = re.compile(r"(error|exception|traceback|killed|oom|fatal|panic|refused|cannot|failed)", re.I)

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


def get_platform_health(db=None) -> dict:
    """Visão de saúde da plataforma. Prefere Docker; cai em fallback."""
    view = _docker_view()
    if view is None:
        view = _fallback_view(db)
    view["adaptive_capacity"] = _adaptive_capacity_view()
    return view
