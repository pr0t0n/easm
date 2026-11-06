"""Testes do contrato jev-local — sem Ollama (backend semântico é simulado)."""
from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from app import _rule_answer, app


@pytest.fixture()
def client() -> TestClient:
    return TestClient(app)


# ─────────────────────────────────────────────────────────────
# Health / introspecção
# ─────────────────────────────────────────────────────────────

def test_health_degrades_without_ollama(client, monkeypatch):
    import app as app_module

    original_get = app_module.httpx.Client.get

    def _boom(self, url, *args, **kwargs):
        if "ollama" in str(url):
            raise ConnectionError("refused")
        return original_get(self, url, *args, **kwargs)

    monkeypatch.setattr(app_module.httpx.Client, "get", _boom, raising=False)
    resp = client.get("/health")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "degraded"
    assert body["ollama_ok"] is False


def test_question_kinds_documented(client):
    resp = client.get("/v1/questions")
    assert resp.status_code == 200
    kinds = resp.json()["kinds"]
    assert set(kinds) == {"noul", "choice", "score"}


# ─────────────────────────────────────────────────────────────
# Validação do contrato (422, nunca silencioso)
# ─────────────────────────────────────────────────────────────

def test_choice_requires_two_options(client):
    resp = client.post("/v1/systemone", json={
        "state": "x",
        "questions": [{"id": "q1", "kind": "choice", "question": "which?", "options": ["only"]}],
    })
    assert resp.status_code == 422


def test_duplicate_question_ids_rejected(client):
    payload = {"state": "x", "questions": [
        {"id": "q1", "kind": "noul", "question": "a?"},
        {"id": "q1", "kind": "noul", "question": "b?"},
    ]}
    assert client.post("/v1/systemone", json=payload).status_code == 422


def test_unknown_kind_rejected(client):
    resp = client.post("/v1/systemone", json={
        "state": "x",
        "questions": [{"id": "q1", "kind": "likert", "question": "a?"}],
    })
    assert resp.status_code == 422


# ─────────────────────────────────────────────────────────────
# Caminho feliz com backend semântico simulado
# ─────────────────────────────────────────────────────────────

def _fake_ollama(answers: dict[str, str]):
    def _generate(prompt: str, model: str) -> str:
        for key, raw in answers.items():
            if key in prompt:
                return raw
        return "{}"
    return _generate


def test_noul_happy_path(client, monkeypatch):
    monkeypatch.setattr("app._ollama_generate", _fake_ollama({
        "is this an API endpoint": '{"value": true, "probability": 0.91}',
    }))
    resp = client.post("/v1/systemone", json={
        "state": {"endpoint": "/api/v1/users"},
        "questions": [{"id": "is_api", "kind": "noul", "question": "is this an API endpoint?"}],
    })
    assert resp.status_code == 200
    answer = resp.json()["answers"][0]
    assert answer["kind"] == "noul"
    assert answer["value"] is True
    assert answer["probability"] == pytest.approx(0.91)
    assert answer["source"] == "jev"
    assert answer["fallback_reason"] is None


def test_choice_happy_path_with_distribution(client, monkeypatch):
    monkeypatch.setattr("app._ollama_generate", _fake_ollama({
        "family of this report": json.dumps({
            "value": "vuln-injection",
            "probabilities": {"vuln-injection": 0.8, "recon-web-crawl": 0.2},
        }),
    }))
    resp = client.post("/v1/systemone", json={
        "state": "SQL error in login parameter",
        "questions": [{
            "id": "family", "kind": "choice", "question": "family of this report?",
            "options": ["vuln-injection", "recon-web-crawl"],
        }],
    })
    answer = resp.json()["answers"][0]
    assert answer["value"] == "vuln-injection"
    assert answer["probabilities"]["vuln-injection"] == pytest.approx(0.8)
    assert answer["source"] == "jev"


def test_score_happy_path(client, monkeypatch):
    monkeypatch.setattr("app._ollama_generate", _fake_ollama({
        "quality of this report": '{"value": 4, "probability": 0.7}',
    }))
    resp = client.post("/v1/systemone", json={
        "state": "detailed write-up with reproduction steps",
        "questions": [{"id": "quality", "kind": "score", "question": "quality of this report?", "scale_max": 5}],
    })
    answer = resp.json()["answers"][0]
    assert answer["value"] == 4
    assert answer["source"] == "jev"


# ─────────────────────────────────────────────────────────────
# Fail-closed: resposta fora do contrato cai no rule, nunca 5xx
# ─────────────────────────────────────────────────────────────

def test_choice_value_outside_enum_falls_back_to_rule(client, monkeypatch):
    monkeypatch.setattr("app._ollama_generate", _fake_ollama({
        "family of this report": '{"value": "DROP TABLE", "probabilities": {}}',
    }))
    resp = client.post("/v1/systemone", json={
        "state": "x",
        "questions": [{
            "id": "family", "kind": "choice", "question": "family of this report?",
            "options": ["vuln-injection", "recon-web-crawl"],
        }],
    })
    assert resp.status_code == 200
    answer = resp.json()["answers"][0]
    assert answer["source"] == "rule"
    assert answer["fallback_reason"]
    assert answer["value"] in {"vuln-injection", "recon-web-crawl"}


def test_score_out_of_scale_falls_back(client, monkeypatch):
    monkeypatch.setattr("app._ollama_generate", _fake_ollama({
        "quality": '{"value": 99, "probability": 0.9}',
    }))
    resp = client.post("/v1/systemone", json={
        "state": "x",
        "questions": [{"id": "quality", "kind": "score", "question": "quality?", "scale_max": 5}],
    })
    answer = resp.json()["answers"][0]
    assert answer["source"] == "rule"
    assert 1 <= answer["value"] <= 5


def test_ollama_down_all_questions_answer_via_rule(client, monkeypatch):
    def _raise(prompt: str, model: str) -> str:
        raise ConnectionError("ollama unreachable")
    monkeypatch.setattr("app._ollama_generate", _raise)

    resp = client.post("/v1/systemone", json={
        "state": {"tech": ["wordpress"]},
        "questions": [
            {"id": "q_noul", "kind": "noul", "question": "is wordpress present?"},
            {"id": "q_choice", "kind": "choice", "question": "primary tech?",
             "options": ["wordpress", "aspnet"]},
            {"id": "q_score", "kind": "score", "question": "exposure level?", "scale_max": 5},
        ],
    })
    assert resp.status_code == 200
    answers = {a["id"]: a for a in resp.json()["answers"]}
    for aid in ("q_noul", "q_choice", "q_score"):
        assert answers[aid]["source"] == "rule"
        assert answers[aid]["fallback_reason"]
    # noul nunca assume verdadeiro no fallback
    assert answers["q_noul"]["value"] is False


def test_deterministic_seed_in_payload(monkeypatch):
    captured = {}

    import app as app_module

    original_post = app_module.httpx.Client.post

    def _spy(self, url, **kwargs):
        # O TestClient herda de httpx.Client: só intercepta a chamada ao
        # Ollama; as chamadas ao próprio app passam pelo transport original.
        if "/api/generate" not in str(url):
            return original_post(self, url, **kwargs)
        captured["payload"] = kwargs.get("json")
        captured["url"] = url

        class _R:
            status_code = 200

            def raise_for_status(self):
                pass

            def json(self):
                return {"response": '{"value": true, "probability": 0.8}'}

        return _R()

    monkeypatch.setattr(app_module.httpx.Client, "post", _spy, raising=False)
    client = TestClient(app_module.app)
    resp = client.post("/v1/systemone", json={
        "state": "x",
        "questions": [{"id": "q1", "kind": "noul", "question": "anything?"}],
    })
    assert resp.status_code == 200
    options = captured["payload"]["options"]
    assert options["temperature"] == 0
    assert options["top_p"] == 1
    assert options["seed"] == 424242


def test_rule_answer_choice_picks_term_overlap():
    from app import Question

    q = Question(
        id="q", kind="choice", question="family?",
        options=["vuln-sqli-injection", "recon-subdomain-enum"],
    )
    answer = _rule_answer(q, "error in your sql syntax near login", "test")
    assert answer.value == "vuln-sqli-injection"
    assert answer.source == "rule"
