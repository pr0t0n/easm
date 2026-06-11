"""EPSS (Exploit Prediction Scoring System) lookup — FIRST.org.

Enriquece findings com a probabilidade de exploração (EPSS) por CVE, usando a
API pública da FIRST.org (https://api.first.org/data/v1/epss). EPSS é atualizado
diariamente; mantemos um cache em memória com TTL para evitar refetch.

Fonte oficial: https://www.first.org/epss/  — dado REAL, não estimado.
"""
from __future__ import annotations

import time

import httpx

_EPSS_URL = "https://api.first.org/data/v1/epss"
_CACHE_TTL_SECONDS = 6 * 60 * 60  # EPSS muda 1x/dia; 6h é folgado
_BATCH_SIZE = 100  # a API aceita lista separada por vírgula
_TIMEOUT = 15.0

# cve (str maiúsculo) -> {"epss": float, "percentile": float, "fetched_at": float}
_cache: dict[str, dict] = {}


def _normalize(cve: str) -> str:
    return str(cve or "").strip().upper()


def _fresh(entry: dict) -> bool:
    return (time.time() - entry.get("fetched_at", 0)) < _CACHE_TTL_SECONDS


def get_epss_scores(cves: list[str]) -> dict[str, dict]:
    """Retorna {cve: {"epss": float, "percentile": float}} para os CVEs dados.

    CVEs sem score na FIRST.org (ou falha de rede) simplesmente não aparecem no
    dicionário de retorno — o chamador trata ausência como "—" (sem inventar).
    """
    wanted = {_normalize(c) for c in cves if _normalize(c).startswith("CVE-")}
    if not wanted:
        return {}

    result: dict[str, dict] = {}
    missing: list[str] = []
    for cve in wanted:
        entry = _cache.get(cve)
        if entry and _fresh(entry):
            if entry.get("epss") is not None:
                result[cve] = {"epss": entry["epss"], "percentile": entry["percentile"]}
        else:
            missing.append(cve)

    for i in range(0, len(missing), _BATCH_SIZE):
        batch = missing[i : i + _BATCH_SIZE]
        fetched = _fetch_batch(batch)
        now = time.time()
        for cve in batch:
            row = fetched.get(cve)
            if row is not None:
                _cache[cve] = {"epss": row["epss"], "percentile": row["percentile"], "fetched_at": now}
                result[cve] = {"epss": row["epss"], "percentile": row["percentile"]}
            else:
                # marca como buscado-sem-resultado para não martelar a API
                _cache[cve] = {"epss": None, "percentile": None, "fetched_at": now}

    return result


def _fetch_batch(cves: list[str]) -> dict[str, dict]:
    """Consulta a API EPSS para um lote de CVEs. Retorna {} em falha (sem exceção)."""
    if not cves:
        return {}
    try:
        resp = httpx.get(
            _EPSS_URL,
            params={"cve": ",".join(cves)},
            timeout=_TIMEOUT,
            headers={"User-Agent": "scriptkiddo-easm"},
        )
        resp.raise_for_status()
        payload = resp.json()
    except (httpx.HTTPError, ValueError):
        return {}

    out: dict[str, dict] = {}
    for row in payload.get("data") or []:
        cve = _normalize(row.get("cve"))
        try:
            epss = float(row.get("epss"))
            percentile = float(row.get("percentile"))
        except (TypeError, ValueError):
            continue
        out[cve] = {"epss": epss, "percentile": percentile}
    return out
