"""Capacidade ADAPTATIVA de varredura (AIMD — congestion control).

Em vez de um cap FIXO de concorrência (que ou satura a rede do operador, ou
subutiliza), o nível de paralelismo sobe e desce conforme a SAÚDE do ambiente:
  - sinal primário: TAXA DE TIMEOUT recente dos tools (timeout alto = link
    saturado → RECUAR);
  - sinal secundário: pressão de memória do host.
Política AIMD (como TCP): aumento ADITIVO quando saudável, queda MULTIPLICATIVA
quando estressado. O nível vive no Redis; o dispatcher lê via capacity_limits().
"""

from __future__ import annotations

import os

from sqlalchemy import text

from app.core.config import settings

_KEY = "easm:adaptive:concurrency_level"
MIN_L = int(os.getenv("ADAPTIVE_MIN", "6"))
MAX_L = int(os.getenv("ADAPTIVE_MAX", "32"))   # teto lógico; caps por classe ainda limitam o envio real
START_L = int(os.getenv("ADAPTIVE_START", "16"))
STEP_UP = int(os.getenv("ADAPTIVE_STEP_UP", "3"))
# Backlog item 18: o timeout de tool contra alvo atrás de WAF (Cloudflare) é
# bloqueio REMOTO, não saturação local — não deve colapsar a concorrência (a CPU
# fica ociosa a ~0,3%). Por isso o threshold de timeout é mais tolerante e o
# recuo por timeout é SUAVE (aditivo); só a pressão de MEMÓRIA local causa recuo
# multiplicativo (saturação real da máquina).
_HIGH_TIMEOUT = float(os.getenv("ADAPTIVE_HIGH_TIMEOUT", "0.55"))  # >55% timeout → recuo suave
_LOW_TIMEOUT = float(os.getenv("ADAPTIVE_LOW_TIMEOUT", "0.10"))    # <10% → avança
_MIN_SAMPLES = 8
_HIGH_MEM = float(os.getenv("ADAPTIVE_HIGH_MEM", "88"))


def _redis():
    import redis
    return redis.from_url(settings.redis_url, decode_responses=True,
                          socket_timeout=2, socket_connect_timeout=2)


def get_level() -> int:
    try:
        v = _redis().get(_KEY)
        return int(v) if v else START_L
    except Exception:
        return START_L


def _set_level(level: int) -> None:
    try:
        _redis().set(_KEY, int(level))
    except Exception:
        pass


def get_capacity() -> dict[str, int]:
    """Caps por classe derivados do nível adaptativo atual (soma ≈ nível)."""
    L = max(MIN_L, min(MAX_L, get_level()))
    return {
        "light": min(max(2, round(L * 0.35)), max(2, int(settings.scan_work_queue_cap_light))),
        "medium": min(max(2, round(L * 0.55)), max(2, int(settings.scan_work_queue_cap_medium))),
        "heavy": min(max(1, round(L * 0.15)), max(1, int(settings.scan_work_queue_cap_heavy))),
        "oob": min(2, max(1, int(settings.scan_work_queue_cap_oob))),
    }


def _mem_percent() -> float | None:
    try:
        import psutil
        return float(psutil.virtual_memory().percent)
    except Exception:
        return None


def adjust(db) -> dict:
    """Mede a saúde e aplica AIMD. Chamado periodicamente (watchdog)."""
    row = db.execute(text(
        "SELECT count(*) FILTER (WHERE status IN ('timeout','failed')) AS bad, "
        "count(*) AS total FROM scan_work_items "
        "WHERE updated_at > now() - interval '3 minutes' "
        "AND status IN ('completed','done','skipped','failed','timeout')"
    )).first()
    bad, total = int(row[0] or 0), int(row[1] or 0)
    rate = (bad / total) if total >= _MIN_SAMPLES else None
    mem = _mem_percent()

    level = get_level()
    old = level
    if mem is not None and mem >= _HIGH_MEM:
        # Pressão de MEMÓRIA local (saturação real) → recuo multiplicativo.
        level = max(MIN_L, level // 2)
        action = "decrease_mem"
    elif rate is not None and rate > _HIGH_TIMEOUT:
        # Timeout alto = majoritariamente bloqueio REMOTO (WAF) → recuo SUAVE
        # (aditivo). Não colapsa a concorrência local com a CPU ociosa.
        level = max(MIN_L, level - STEP_UP)
        action = "decrease_timeout"
    elif rate is None or rate < _LOW_TIMEOUT:
        # Saudável (ou amostra insuficiente) → avança aditivamente até o teto.
        level = min(MAX_L, level + STEP_UP)
        action = "increase"
    else:
        action = "hold"

    if level != old:
        _set_level(level)

    return {
        "level": level, "previous": old, "action": action,
        "timeout_rate": round(rate, 3) if rate is not None else None,
        "samples": total, "mem_percent": mem,
        "min": MIN_L, "max": MAX_L, "capacity": get_capacity(),
    }
