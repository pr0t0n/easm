"""Triage automático dos learnings H1 pendentes (Fase 3 do LANGGRAPH_BRAIN_PLAN).

O crawler semeia ~10k registros `pending_review`; revisão humana serial não
escala. Este script usa Ollama local para classificar em lotes, deduplicar
contra os aceitos e aceitar automaticamente acima de um limiar conservador —
com auditoria total. Zona cinzenta fica pendente para revisão humana.

Decisões de segurança:
  - Só auto-aceita confidence >= threshold E risk != high E sem duplicata.
  - Toda decisão grava raw_llm_response (síntese) + review_notes (trilha).
  - Resumável: linhas já triadas (raw_extraction->>'triage') são puladas.
  - Lote de prompt com N rows por chamada — 3B em CPU não escala 1:1.

Uso (dentro do container backend):
  python3 scripts/triage_h1_learnings.py --limit 300 --batch 10
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import time
from pathlib import Path
from typing import Any

sys.path.insert(0, "/app")
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import httpx
from sqlalchemy import text

from app.db.session import SessionLocal

OLLAMA_URL = "http://ollama:11434/api/generate"
DEFAULT_MODEL = "llama3.2:3b"

PROMPT_TEMPLATE = """Classifique os reports de bug bounty abaixo. Para CADA item responda APENAS um objeto JSON por linha, sem texto extra, no formato:
{{"i": <indice>, "family": "<familia owasp>", "phases": ["Pxx", ...], "skills": ["<skill_id>", ...], "tools": ["<ferramenta>"], "confidence": <0.1>, "risk": "low|medium|high"}}

Famílias comuns: sqli, xss, ssrf, idor, auth_bypass, info_disclosure, csrf, cors_misconfiguration, jwt_oauth, command_injection, path_traversal, ssti, deserialization, xxE, clickjacking, subdomain_takeover, race_condition, business_logic, api_security, crypto, outra.
Skills válidas (exemplos): skill.vuln.ssrf, skill.vuln.sqli, skill.vuln.xss, skill.vuln.idor, skill.vuln.jwt_oauth, skill.recon.subdomain_enumeration, skill.reporting.evidence_quality. Se incerto, use "outra".

{items}
"""


def _compact(value: Any, limit: int = 280) -> str:
    text_value = re.sub(r"\s+", " ", str(value or "")).strip()
    return text_value[:limit]


def _extract_json_objects(raw: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for line in raw.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
        except Exception:
            match = re.search(r"\{.*\}", line)
            if not match:
                continue
            try:
                obj = json.loads(match.group(0))
            except Exception:
                continue
        if isinstance(obj, dict) and "i" in obj:
            out.append(obj)
    return out


def _title_tokens(title: str) -> set[str]:
    # Boilerplate dos seeds H1 ("h1 github skill phase px #NNN") inflava o
    # Jaccard e marcava tudo como duplicata — remove antes de comparar.
    stop = {"h1", "github", "skill", "report", "reports", "phase", "px"}
    return {
        t for t in re.split(r"[^a-z0-9]+", str(title or "").lower())
        if len(t) > 3 and t not in stop and not t.isdigit()
    }


def _jaccard(a: set[str], b: set[str]) -> float:
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


def _call_ollama(client: httpx.Client, model: str, prompt: str, timeout: int = 180) -> str:
    last_exc: Exception | None = None
    for attempt in range(3):
        try:
            response = client.post(
                OLLAMA_URL,
                json={
                    "model": model,
                    "prompt": prompt,
                    "stream": False,
                    # Mantém o modelo carregado entre chamadas do lote; sem
                    # isso cada request recarrega e a janela de OOM no host
                    # 8GB (durante scans) derruba o llama-server.
                    "keep_alive": "10m",
                },
                timeout=timeout,
            )
            response.raise_for_status()
            return str(response.json().get("response") or "")
        except Exception as exc:  # 500 (llama-server killed) → backoff e retry
            last_exc = exc
            time.sleep(15 * (attempt + 1))
    raise last_exc or RuntimeError("ollama_unavailable")


def _pending_rows(db, limit: int) -> list[dict[str, Any]]:
    rows = db.execute(
        text(
            """
            SELECT id, title, vulnerability_type, summary, steps_to_reproduce,
                   learned_mission, affected_phases, recommended_tools,
                   raw_extraction, source_kind
            FROM vulnerability_learnings
            WHERE status = 'pending_review'
              AND (raw_extraction->>'triage' IS NULL)
            ORDER BY id
            LIMIT :limit
            """
        ),
        {"limit": limit},
    ).fetchall()
    return [
        {
            "id": row[0], "title": row[1], "vulnerability_type": row[2],
            "summary": row[3], "steps": row[4], "mission": row[5],
            "phases": row[6], "tools": row[7], "raw_extraction": row[8] or {},
            "source_kind": row[9],
        }
        for row in rows
    ]


def _accepted_title_tokens(db) -> list[tuple[int, set[str]]]:
    rows = db.execute(
        text("SELECT id, title FROM vulnerability_learnings WHERE status = 'accepted'")
    ).fetchall()
    return [(int(r[0]), _title_tokens(str(r[1] or ""))) for r in rows]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--limit", type=int, default=300)
    parser.add_argument("--batch", type=int, default=10)
    parser.add_argument("--threshold", type=float, default=0.85)
    parser.add_argument("--model", default=DEFAULT_MODEL)
    parser.add_argument("--dedup-cutoff", type=float, default=0.8)
    args = parser.parse_args()

    db = SessionLocal()
    client = httpx.Client()
    stats = {"classified": 0, "accepted": 0, "kept_pending": 0, "duplicates": 0, "errors": 0}

    try:
        accepted_tokens = _accepted_title_tokens(db)
        rows = _pending_rows(db, args.limit)
        # Libera a transação antes das chamadas longas ao Ollama: o postgres
        # tem idle_in_transaction_session_timeout=120s (compose) e mata a
        # conexão se o LLM demorar mais que isso entre queries.
        db.commit()
        print(f"[triage] {len(rows)} pendentes | {len(accepted_tokens)} aceitos na base | model={args.model}")

        for offset in range(0, len(rows), args.batch):
            batch = rows[offset : offset + args.batch]
            items = "\n\n".join(
                f"### Item {idx}\nTitulo: {_compact(r['title'], 200)}\n"
                f"Tipo: {_compact(r['vulnerability_type'], 80)}\n"
                f"Resumo: {_compact(r['summary'], 240)}\n"
                f"Passos: {_compact(r['steps'], 240)}"
                for idx, r in enumerate(batch)
            )
            try:
                raw = _call_ollama(client, args.model, PROMPT_TEMPLATE.format(items=items))
            except Exception as exc:
                print(f"[triage] batch {offset} erro ollama: {exc}")
                stats["errors"] += len(batch)
                continue
            decisions = {int(d.get("i", -1)): d for d in _extract_json_objects(raw) if isinstance(d.get("i"), int)}

            for idx, row in enumerate(batch):
                decision = decisions.get(idx)
                raw_extraction = dict(row["raw_extraction"] or {})
                if decision is None:
                    raw_extraction["triage"] = {"error": "no_decision", "ts": time.time()}
                    _update(db, row["id"], raw_extraction=raw_extraction)
                    stats["kept_pending"] += 1
                    continue

                stats["classified"] += 1
                confidence = float(decision.get("confidence") or 0.0)
                risk = str(decision.get("risk") or "high").lower()
                title_tokens = _title_tokens(row["title"])
                best_dup = max(
                    (_jaccard(title_tokens, tokens) for _, tokens in accepted_tokens),
                    default=0.0,
                )
                triage_record = {
                    "ts": time.time(),
                    "model": args.model,
                    "family": str(decision.get("family") or "outra"),
                    "phases": [str(p) for p in (decision.get("phases") or []) if str(p).startswith("P")][:4],
                    "skills": [str(s) for s in (decision.get("skills") or [])][:4],
                    "tools": [str(t) for t in (decision.get("tools") or [])][:6],
                    "confidence": confidence,
                    "risk": risk,
                    "dup_similarity": round(best_dup, 3),
                }
                raw_extraction["triage"] = triage_record
                raw_extraction["confidence"] = confidence
                raw_extraction["risk_score_hint"] = {"high": 0.8, "medium": 0.5, "low": 0.2}.get(risk, 0.5)

                if best_dup >= args.dedup_cutoff:
                    triage_record["decision"] = "duplicate"
                    _update(db, row["id"], raw_extraction=raw_extraction, review_note="triage: duplicata")
                    stats["duplicates"] += 1
                elif confidence >= args.threshold and risk != "high":
                    triage_record["decision"] = "auto_accepted"
                    _update(
                        db, row["id"],
                        raw_extraction=raw_extraction,
                        status="accepted",
                        accepted_at=time.strftime("%Y-%m-%dT%H:%M:%S"),
                        raw_llm_response=json.dumps(decision, ensure_ascii=False)[:4000],
                        review_note=f"triage auto-aceite conf={confidence:.2f} risk={risk} family={triage_record['family']}",
                    )
                    stats["accepted"] += 1
                else:
                    triage_record["decision"] = "kept_pending"
                    _update(db, row["id"], raw_extraction=raw_extraction, review_note="triage: zona cinzenta")
                    stats["kept_pending"] += 1

            done = min(offset + args.batch, len(rows))
            print(f"[triage] {done}/{len(rows)} | {stats}")

        print(f"[triage] FINAL {stats}")
        return 0
    finally:
        db.close()
        client.close()


def _update(db, row_id: int, *, raw_extraction: dict[str, Any], review_note: str = "",
            status: str | None = None, accepted_at: str | None = None,
            raw_llm_response: str | None = None) -> None:
    sets = ["raw_extraction = :re", "review_notes = COALESCE(review_notes,'') || :note"]
    params: dict[str, Any] = {"re": json.dumps(raw_extraction, ensure_ascii=False), "note": f"\n[{time.strftime('%Y-%m-%d %H:%M')}] {review_note}", "id": row_id}
    if status:
        sets.append("status = :status")
        params["status"] = status
    if accepted_at:
        sets.append("accepted_at = :accepted_at")
        params["accepted_at"] = accepted_at
    if raw_llm_response:
        sets.append("raw_llm_response = :sintese")
        params["sintese"] = raw_llm_response
    db.execute(text(f"UPDATE vulnerability_learnings SET {', '.join(sets)} WHERE id = :id"), params)
    db.commit()


if __name__ == "__main__":
    sys.exit(main())
