"""Limpeza de findings falso-positivos/lixo já gravados (backlog itens 1,2,13,16).

Aplica aos dados ANTIGOS a mesma lógica do código novo:
  - título é banner ASCII de ferramenta (figlet/box-drawing) → REMOVE
  - registro de COBERTURA ("0 findings"/"no vulnerabilities detected"/
    "no parseable output"/"Sem achados") → REMOVE (não é vuln)
  - achado de injeção/exploit cuja "evidência" é só "[INFO] testing" do sqlmap
    ou "does not appear to be injectable" (sem confirmação real) → REMOVE
Preserva: CVEs, headers, recon, dev/staging, business_logic confirmado, etc.

Uso: python -m scripts.cleanup_fp_findings [--apply] [--scans 12,13]
Sem --apply = DRY RUN (só conta e mostra amostra).
"""
import re
import sys

from app.db.session import SessionLocal
from app.models.models import Finding, Vulnerability
from app.services.offensive_operator_runner import (
    _is_banner_line, _sanitize_evidence, _has_real_evidence,
)

_COVERAGE_RE = re.compile(
    r"(0 finding|no vulnerabilities detected|no parseable output|ran \(no parseable|"
    r"sem achados|cobertura executada)",
    re.IGNORECASE,
)
# Marcadores de confirmação REAL de injeção (sqlmap)
_INJ_CONFIRM = ("is vulnerable", "back-end dbms", "sqlmap identified the following injection")
_INJ_FP = ("[info]", "does not appear to be injectable", "does not seem to be injectable",
           "all tested parameters do not")


def _title_payload(title: str) -> str:
    # parte após "Fase: " (ex.: "Injection Testing: <conteúdo>")
    return title.split(": ", 1)[1] if ": " in title else title


def _is_fp_injection(f: Finding) -> bool:
    t = (f.title or "")
    if not re.match(r"^(Injection Testing|Exploit Validation)\b", t, re.IGNORECASE):
        return False
    blob = ""
    det = f.details if isinstance(f.details, dict) else {}
    for ev in (det.get("tool_evidence") or []):
        if isinstance(ev, dict):
            blob += " ".join(str(x) for x in (ev.get("injection_evidence") or []))
            blob += " " + str(ev.get("finding_summary") or "")
    blob += " " + _title_payload(t)
    low = blob.lower()
    if any(m in low for m in _INJ_CONFIRM):
        return False   # tem confirmação real → mantém
    # injeção sem confirmação real (só [INFO] testing / not injectable) → FP
    return True


def classify(f: Finding) -> str | None:
    payload = _title_payload(f.title or "")
    if _is_banner_line(payload):
        return "banner"
    if _COVERAGE_RE.search(f.title or ""):
        return "coverage"
    if _is_fp_injection(f):
        return "fp_injection"
    # Findings do OPERADOR: re-sanitiza a evidência (remove path de erro do
    # gobuster, banner, etc.) e, se sobrar SEM evidência real, é registro de
    # cobertura que não devia existir → remove. Pega títulos como "- Nikto
    # v2.6.0" e qualquer wrapper de fase sem achado real. Restrito ao operador
    # para não tocar findings do work-queue (headers/recon legítimos).
    det = f.details if isinstance(f.details, dict) else {}
    if str(det.get("scan_mode") or det.get("source_worker") or "") == "offensive_operator" or det.get("phase_id"):
        evs = [_sanitize_evidence(dict(e)) for e in (det.get("tool_evidence") or []) if isinstance(e, dict)]
        if det.get("tool_evidence") is not None:
            has_real, _ = _has_real_evidence(evs)
            if not has_real and str(det.get("finding_class") or "") != "business_logic_confirmed":
                return "no_real_evidence"
    return None


def main():
    apply = "--apply" in sys.argv
    scans = [12, 13]
    for a in sys.argv:
        if a.startswith("--scans"):
            scans = [int(x) for x in a.split("=", 1)[1].split(",")]
    db = SessionLocal()
    try:
        rows = db.query(Finding).filter(Finding.scan_job_id.in_(scans)).all()
        buckets: dict[str, list] = {}
        for f in rows:
            c = classify(f)
            if c:
                buckets.setdefault(c, []).append(f)
        total_del = sum(len(v) for v in buckets.values())
        print(f"Findings analisados: {len(rows)} | a remover: {total_del}")
        for c, fs in sorted(buckets.items()):
            print(f"\n[{c}] {len(fs)}:")
            for f in fs[:5]:
                print(f"   #{f.id} [{f.severity}] {(f.title or '')[:75]}")
            if len(fs) > 5:
                print(f"   … +{len(fs)-5}")
        if not apply:
            print("\nDRY RUN — nada removido. Rode com --apply para executar.")
            return
        del_ids = [f.id for fs in buckets.values() for f in fs]
        if del_ids:
            vdel = db.query(Vulnerability).filter(Vulnerability.finding_id.in_(del_ids)).delete(synchronize_session=False)
            fdel = db.query(Finding).filter(Finding.id.in_(del_ids)).delete(synchronize_session=False)
            db.commit()
            print(f"\nAPLICADO: {fdel} findings removidos, {vdel} vulnerabilities vinculadas removidas.")
    finally:
        db.close()


if __name__ == "__main__":
    main()
