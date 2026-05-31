"""Geração de embeddings via fastembed (ONNX, CPU, sem torch).

Modelo ``BAAI/bge-small-en-v1.5`` (384 dimensões) — rápido em CPU (~250
embeds/s mesmo em CPU modesta), ao contrário do caminho via Ollama (que
recarregava o modelo a ~30s por chamada nesta máquina). Falha graciosamente:
se o modelo não puder ser carregado, retorna ``None`` e o chamador cai em
heurística.
"""

from __future__ import annotations

import os
import threading

EMBED_MODEL = os.getenv("EMBED_MODEL", "BAAI/bge-small-en-v1.5")
EMBED_DIM = int(os.getenv("EMBED_DIM", "384"))

_model = None
_model_lock = threading.Lock()
_load_failed = False


def _get_model():
    """Carrega o modelo fastembed sob demanda (singleton thread-safe)."""
    global _model, _load_failed
    if _model is not None:
        return _model
    if _load_failed:
        return None
    with _model_lock:
        if _model is not None:
            return _model
        if _load_failed:
            return None
        try:
            from fastembed import TextEmbedding

            cache_dir = os.getenv("FASTEMBED_CACHE", "/app/.fastembed_cache")
            try:
                os.makedirs(cache_dir, exist_ok=True)
            except Exception:
                cache_dir = None
            # threads=1: o onnxruntime, por padrão, cria arenas de memória/threads
            # dimensionadas pelos núcleos da CPU — nos workers (pool=threads) isso
            # inflava a memória e causava OOM. 1 thread mantém o footprint enxuto.
            _model = TextEmbedding(model_name=EMBED_MODEL, cache_dir=cache_dir, threads=1)
            return _model
        except Exception:
            _load_failed = True
            return None


def embed_text(text: str) -> list[float] | None:
    """Embeda um texto. Retorna o vetor (384-dim) ou None se indisponível."""
    text = (text or "").strip()
    if not text:
        return None
    m = _get_model()
    if m is None:
        return None
    try:
        vecs = list(m.embed([text[:8000]]))
        return [float(x) for x in vecs[0]]
    except Exception:
        return None


def embed_texts(texts: list[str]) -> list[list[float] | None]:
    """Embeda um lote. Mantém alinhamento posicional; itens vazios viram None."""
    cleaned = [(t or "").strip()[:8000] for t in texts]
    non_empty = [t for t in cleaned if t]
    if not non_empty:
        return [None] * len(texts)
    m = _get_model()
    if m is None:
        return [None] * len(texts)
    try:
        produced = [[float(x) for x in v] for v in m.embed(non_empty)]
    except Exception:
        return [None] * len(texts)
    it = iter(produced)
    out: list[list[float] | None] = []
    for t in cleaned:
        out.append(next(it) if t else None)
    return out


def vector_literal(vec: list[float]) -> str:
    """Serializa um vetor no formato literal pgvector: '[0.1,0.2,...]'."""
    return "[" + ",".join(f"{x:.6f}" for x in vec) + "]"


def is_available() -> bool:
    """Checa se o modelo de embedding está disponível."""
    return embed_text("ping") is not None
