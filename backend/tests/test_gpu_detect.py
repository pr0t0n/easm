"""P5 — Testes da detecção de capacidade GPU (lógica pura + fallback seguro).

O caminho GPU real só dá pra validar em Linux+NVIDIA; aqui travamos a lógica
de decisão e a garantia de que TUDO cai para CPU sem estourar quando não há
GPU/onnxruntime/Ollama (ex.: Docker no Mac, CI).
"""
from __future__ import annotations

from app.services import gpu_detect as g


def test_preferred_provider_prefers_cuda():
    assert g._preferred_provider(
        ["CPUExecutionProvider", "CUDAExecutionProvider"]
    ) == "CUDAExecutionProvider"


def test_preferred_provider_coreml_over_cpu():
    assert g._preferred_provider(
        ["CoreMLExecutionProvider", "CPUExecutionProvider"]
    ) == "CoreMLExecutionProvider"


def test_preferred_provider_defaults_to_cpu_when_empty():
    assert g._preferred_provider([]) == "CPUExecutionProvider"
    assert g._preferred_provider(["SomethingExotic"]) == "CPUExecutionProvider"


def test_probe_ollama_unreachable_is_safe(monkeypatch):
    # base_url inválida → não estoura, reporta CPU/unreachable.
    res = g.probe_ollama_accelerator("http://127.0.0.1:0", timeout=0.01)
    assert res["reachable"] is False
    assert res["on_gpu"] is False
    assert res["vram_bytes"] == 0


def test_capability_summary_falls_back_to_cpu(monkeypatch):
    # Sem NVIDIA e Ollama inalcançável → acelerador 'cpu', gpu_usable False.
    monkeypatch.setattr(g, "probe_nvidia", lambda: [])
    monkeypatch.setattr(
        g, "probe_ollama_accelerator",
        lambda *a, **k: {"reachable": False, "on_gpu": False, "vram_bytes": 0, "models_loaded": 0},
    )
    summary = g.capability_summary()
    assert summary["accelerator"] == "cpu"
    assert summary["gpu_usable"] is False
    assert summary["onnx_preferred_provider"] in g._PROVIDER_PREFERENCE


def test_capability_summary_reports_gpu_when_ollama_on_vram(monkeypatch):
    monkeypatch.setattr(g, "probe_nvidia", lambda: [{"name": "NVIDIA A10", "memory_total_mb": 24000}])
    monkeypatch.setattr(
        g, "probe_ollama_accelerator",
        lambda *a, **k: {"reachable": True, "on_gpu": True, "vram_bytes": 5_000_000, "models_loaded": 1},
    )
    summary = g.capability_summary()
    assert summary["accelerator"] == "gpu-ollama"
    assert summary["gpu_usable"] is True
    assert summary["nvidia_gpus"]


def test_safe_int():
    assert g._safe_int("24000") == 24000
    assert g._safe_int("24000.0") == 24000
    assert g._safe_int("n/a") == 0
