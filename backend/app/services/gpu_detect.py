"""P5 — Detecção automática de capacidade de aceleração (GPU vs CPU).

A plataforma deve descobrir SOZINHA, no ambiente em que está rodando, se há
GPU utilizável — e adaptar/reportar — em vez de depender de configuração
manual. Este módulo é READ-ONLY e à prova de falha: qualquer sonda que erre
cai para "cpu". Nada aqui muda comportamento; quem consome decide.

Sondas:
  - nvidia-smi  → GPU NVIDIA acessível ao processo (Linux + container toolkit).
  - onnxruntime.get_available_providers() → provider preferido p/ fastembed.
  - Ollama /api/ps → o LLM carregou em VRAM (size_vram > 0) = está em GPU.

Nota honesta: no Docker do Mac a GPU nunca é acessível ao container — aqui a
detecção corretamente reporta "cpu". GPU real só em Linux + NVIDIA.
"""
from __future__ import annotations

import logging
import os
import shutil
import subprocess
from typing import Any

logger = logging.getLogger(__name__)

# Ordem de preferência de execution provider do onnxruntime (fastembed).
_PROVIDER_PREFERENCE = ("CUDAExecutionProvider", "CoreMLExecutionProvider", "CPUExecutionProvider")


def _preferred_provider(available: list[str]) -> str:
    """Escolhe o melhor provider ONNX disponível (CUDA > CoreML > CPU).

    Lógica pura (testável sem onnxruntime instalado).
    """
    avail = set(available or [])
    for p in _PROVIDER_PREFERENCE:
        if p in avail:
            return p
    return "CPUExecutionProvider"


def detect_onnx_providers() -> dict[str, Any]:
    """Providers ONNX disponíveis + o preferido. Fallback seguro p/ CPU."""
    try:
        import onnxruntime  # type: ignore

        available = list(onnxruntime.get_available_providers())
    except Exception as exc:  # noqa: BLE001
        logger.debug("onnxruntime indisponível: %s", exc)
        available = ["CPUExecutionProvider"]
    return {"available": available, "preferred": _preferred_provider(available)}


def probe_nvidia() -> list[dict[str, Any]]:
    """Lista GPUs NVIDIA via nvidia-smi. [] se não houver / comando ausente."""
    if not shutil.which("nvidia-smi"):
        return []
    try:
        out = subprocess.run(
            ["nvidia-smi", "--query-gpu=name,memory.total", "--format=csv,noheader,nounits"],
            capture_output=True, text=True, timeout=5, check=False,
        )
        if out.returncode != 0:
            return []
        gpus: list[dict[str, Any]] = []
        for line in out.stdout.strip().splitlines():
            parts = [p.strip() for p in line.split(",")]
            if len(parts) >= 2:
                gpus.append({"name": parts[0], "memory_total_mb": _safe_int(parts[1])})
        return gpus
    except Exception as exc:  # noqa: BLE001
        logger.debug("nvidia-smi falhou: %s", exc)
        return []


def probe_ollama_accelerator(base_url: str | None = None, *, timeout: float = 3.0) -> dict[str, Any]:
    """Pergunta ao Ollama (/api/ps) se algum modelo está em VRAM (GPU)."""
    url = (base_url or os.getenv("OLLAMA_BASE_URL", "http://ollama:11434")).rstrip("/")
    try:
        import httpx  # type: ignore

        r = httpx.get(f"{url}/api/ps", timeout=timeout)
        r.raise_for_status()
        models = (r.json() or {}).get("models") or []
        vram = sum(int(m.get("size_vram") or 0) for m in models)
        return {"reachable": True, "on_gpu": vram > 0, "vram_bytes": vram, "models_loaded": len(models)}
    except Exception as exc:  # noqa: BLE001
        logger.debug("probe Ollama /api/ps falhou: %s", exc)
        return {"reachable": False, "on_gpu": False, "vram_bytes": 0, "models_loaded": 0}


def capability_summary(ollama_base_url: str | None = None) -> dict[str, Any]:
    """Resumo unificado consumível por /config/ai-status e pela adaptação de
    fastembed/Ollama. Determina o acelerador 'efetivo' do ponto de vista da app.
    """
    nvidia = probe_nvidia()
    onnx = detect_onnx_providers()
    ollama = probe_ollama_accelerator(ollama_base_url)

    if ollama.get("on_gpu"):
        accelerator = "gpu-ollama"          # Ollama confirmou modelo em VRAM
    elif nvidia:
        accelerator = "gpu-available"       # placa existe, mas LLM ainda em CPU
    else:
        accelerator = "cpu"                 # sem GPU acessível (ex.: Docker no Mac)

    return {
        "accelerator": accelerator,
        "gpu_usable": bool(nvidia) or bool(ollama.get("on_gpu")),
        "nvidia_gpus": nvidia,
        "onnx_preferred_provider": onnx["preferred"],
        "onnx_available_providers": onnx["available"],
        "ollama": ollama,
    }


def _safe_int(value: str) -> int:
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return 0
