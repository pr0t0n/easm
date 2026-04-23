#!/usr/bin/env python3
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import json
import sys


@dataclass
class CheckResult:
    name: str
    ok: bool
    detail: str


def contains_all(path: Path, required: list[str]) -> CheckResult:
    if not path.exists():
        return CheckResult(str(path), False, "arquivo ausente")
    text = path.read_text(encoding="utf-8", errors="replace")
    missing = [token for token in required if token not in text]
    if missing:
        return CheckResult(str(path), False, f"tokens ausentes: {', '.join(missing)}")
    return CheckResult(str(path), True, "ok")


def main() -> int:
    root = Path(__file__).resolve().parents[1]

    checks: list[CheckResult] = [
        contains_all(
            root / "backend/app/graph/workflow.py",
            [
                "supervisor_node",
                "completed_capabilities",
                "objective_met",
                "evidence_adjudication",
            ],
        ),
        contains_all(
            root / "backend/app/services/cyber_autoagent_alignment.py",
            [
                "CYBER_AUTOAGENT_PROMPT_PRINCIPLES",
                "evaluate_execution_quality",
                "build_supervisor_prompt_contract",
            ],
        ),
        contains_all(
            root / "backend/app/workers/tasks.py",
            [
                "agent_validation",
                "VALIDACAO CYBER AUTOAGENT",
            ],
        ),
        contains_all(
            root / "backend/app/core/config.py",
            [
                "llm_primary_provider",
                "llm_primary_model",
                "llm_evaluation_model",
                "enable_auto_evaluation",
            ],
        ),
        contains_all(
            root / ".env.example",
            [
                "LLM_PRIMARY_PROVIDER",
                "LLM_PRIMARY_MODEL",
                "LLM_EVALUATION_MODEL",
                "ENABLE_AUTO_EVALUATION",
            ],
        ),
        contains_all(
            root / ".gitignore",
            ["backend/celerybeat-schedule"],
        ),
    ]

    payload = {
        "total": len(checks),
        "passed": sum(1 for c in checks if c.ok),
        "failed": sum(1 for c in checks if not c.ok),
        "checks": [
            {"name": c.name, "ok": c.ok, "detail": c.detail}
            for c in checks
        ],
    }
    print(json.dumps(payload, ensure_ascii=True, indent=2))
    return 0 if payload["failed"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
