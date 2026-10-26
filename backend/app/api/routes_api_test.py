"""API Security module — standalone OWASP API Top 10 testing.

A first-class module alongside SCAN and BAS. It takes a base URL plus an API
spec (OpenAPI/Swagger, Postman collection, HAR or GraphQL) and runs ONLY the
API security phase (P16): the OWASP API Top 10 skills (BOLA, BFLA, broken
authentication, injection, mass assignment, SSRF, etc.) plus parameter fuzzing
and spec-driven DAST.

Implementation note: this reuses the existing scan engine instead of
duplicating it. An API test is a ScanJob with mode="api" and scan_level="api"
(a profile restricted to phase P16 — see scan_profiles.API_PHASES). Spec
ingestion, endpoint inventory, the api-skill-top20 runner, finding persistence
and the report endpoints are all shared with SCAN; nothing in SCAN is changed.
"""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, require_admin
from app.db.session import get_db
from app.models.models import ScanJob, User
from app.schemas.scan import ScanCreate, ScanResponse

# Reuse the SCAN implementation wholesale — do not reimplement creation,
# listing, lifecycle or reporting.
from app.api.routes_scans import (
    _TERMINAL_SCAN_STATUSES,
    _authorized_scan_query,
    _effective_mission_progress,
    _open_finding_counts_by_scan,
    create_scan,
    finalize_scan,
    scan_report,
    stop_scan,
)

router = APIRouter(prefix="/api/apitest", tags=["api-test"])


class ApiTestCreate(BaseModel):
    # Base URL / host of the API under test (authorized scope root).
    target_url: str
    # Spec source: a URL to fetch, OR an inline spec body (Swagger/OpenAPI/
    # Postman collection / HAR / GraphQL introspection), OR both.
    spec_url: str | None = None
    spec_payload: dict[str, Any] | None = None
    spec_type: str = "openapi"  # openapi | swagger | postman | har | graphql
    # Safe by default: no mutating (POST/PUT/DELETE) active DAST unless the
    # operator explicitly authorizes it for this target.
    allow_mutations: bool = False
    active_level: str = "safe"
    # Optional authenticated testing (bearer/headers/cookies/userlist).
    auth_config: dict[str, Any] | None = None
    # Header variables applied to EVERY request (ex.: x-api-key, x-organization-id,
    # x-project-id, Authorization). Essencial para passar o gate de auth.
    headers: dict[str, str] | None = None
    # Body/path variables used to fill fields and path vars by name (ex.:
    # {"requestId": "<uuid válido>", "cpf": "12345678900"}). Necessário p/ testes
    # como optIn, que exigem um REQUEST_ID válido de transação.
    variables: dict[str, Any] | None = None
    # Optional deep corpus mode. The library contains 10,000 deterministic
    # synthetic candidates; this budget controls how many are selected per
    # variable, so creating a test never implies 10,000 network requests.
    fuzz_profile: str = "safe"
    fuzz_library_size: int = Field(default=10_000, ge=1_000, le=10_000)
    fuzz_library_budget: int = Field(default=0, ge=0, le=64)
    access_group_id: int | None = None
    access_group_name: str | None = None
    authorization_code: str | None = None
    scope_authorization_attested: bool = False


def _api_scan_payload(payload: ApiTestCreate) -> ScanCreate:
    if not (payload.spec_url or payload.spec_payload):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Informe spec_url ou spec_payload (Swagger/OpenAPI/Postman/HAR).",
        )
    api_scan_config = {
        "enabled": True,
        "spec_url": payload.spec_url or "",
        "spec_payload": payload.spec_payload,
        "spec_type": payload.spec_type,
        "allow_mutations": bool(payload.allow_mutations),
        "active_level": payload.active_level,
        # Variáveis do teste: headers aplicados a toda request e variáveis de
        # path/body preenchidas por nome (requestId, cpf, ...).
        "test_headers": {str(k): str(v) for k, v in (payload.headers or {}).items()},
        "test_variables": dict(payload.variables or {}),
        "fuzz_profile": payload.fuzz_profile,
        "fuzz_library_size": payload.fuzz_library_size,
        "fuzz_library_budget": payload.fuzz_library_budget,
    }
    return ScanCreate(
        target_query=payload.target_url,
        mode="api",
        scan_level="api",
        execution_plan="external_only",
        access_group_id=payload.access_group_id,
        access_group_name=payload.access_group_name,
        authorization_code=payload.authorization_code,
        scope_authorization_attested=payload.scope_authorization_attested,
        auth_config=payload.auth_config,
        api_scan_config=api_scan_config,
    )


def _scan_to_response(db: Session, s: ScanJob) -> ScanResponse:
    sev = _open_finding_counts_by_scan(db, [s.id]).get(s.id, {})
    terminal = str(s.status or "").lower() in _TERMINAL_SCAN_STATUSES
    state = dict(s.state_data or {})
    card_state: dict[str, Any] = {}
    for key in ("api_scan_config", "api_scan_observability", "broken_glass"):
        if key in state:
            card_state[key] = state.get(key)
    return ScanResponse(
        id=s.id,
        target_query=s.target_query,
        mode=s.mode,
        access_group_id=s.access_group_id,
        status=s.status,
        compliance_status=s.compliance_status,
        current_step=s.current_step,
        mission_progress=_effective_mission_progress(s),
        retry_attempt=s.retry_attempt,
        retry_max=s.retry_max,
        next_retry_at=s.next_retry_at,
        last_error=s.last_error,
        created_at=s.created_at,
        updated_at=s.updated_at,
        started_at=s.created_at,
        finished_at=s.updated_at if terminal else None,
        open_critical=int(sev.get("critical", 0)),
        open_high=int(sev.get("high", 0)),
        open_medium=int(sev.get("medium", 0)),
        open_low=int(sev.get("low", 0)),
        open_info=int(sev.get("info", 0)),
        state_data=card_state,
    )


@router.post("", response_model=ScanResponse)
@router.post("/", response_model=ScanResponse)
def create_api_test(
    payload: ApiTestCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
) -> ScanResponse:
    """Create and dispatch an API security test from a spec. Reuses create_scan
    (auth gate, spec ingestion, P16 OWASP API Top 10 seeding/dispatch)."""
    return create_scan(_api_scan_payload(payload), db=db, current_user=current_user)


@router.get("", response_model=list[ScanResponse])
@router.get("/", response_model=list[ScanResponse])
def list_api_tests(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> list[ScanResponse]:
    rows = (
        _authorized_scan_query(db, current_user)
        .filter(ScanJob.mode == "api")
        .order_by(ScanJob.created_at.desc())
        .all()
    )
    return [_scan_to_response(db, s) for s in rows]


@router.get("/catalog")
def api_test_catalog(current_user: User = Depends(get_current_user)):
    """The OWASP API Top 20 test catalog (which tests exist), with the Broken
    Access Control family (BOLA/BFLA/BOPLA/mass-assignment) flagged."""
    from app.services.api_endpoint_report import BAC_SKILL_IDS
    from app.services.api_skill_top20_runner import load_api_top20_skills

    skills = []
    for s in load_api_top20_skills().get("skills", []):
        sid = str(s.get("id") or "")
        skills.append({
            "id": sid,
            "name": s.get("name") or sid,
            "owasp": s.get("owasp") or s.get("category") or "",
            "priority": int(s.get("priority") or 999),
            "is_bac": sid in BAC_SKILL_IDS,
        })
    return {"skills": skills, "total": len(skills), "bac_total": sum(1 for s in skills if s["is_bac"])}


@router.get("/fuzz-library/catalog")
def api_fuzz_library_catalog(
    current_user: User = Depends(get_current_user),
):
    """Describe the built-in 10k OpenAPI variable corpus without returning all
    payloads. Values are synthetic and intended for controlled, authorized API
    testing only."""
    from app.services.api_fuzz_corpus import corpus_catalog

    return corpus_catalog()


@router.get("/fuzz-library/sample")
def api_fuzz_library_sample(
    limit: int = Query(default=100, ge=1, le=500),
    category: str | None = Query(default=None),
    current_user: User = Depends(get_current_user),
):
    """Return a bounded, inspectable slice of the synthetic corpus for UI and
    rule-authoring. The endpoint intentionally caps responses at 500 entries."""
    from app.services.api_fuzz_corpus import build_openapi_variable_corpus

    rows = list(build_openapi_variable_corpus())
    if category:
        wanted = category.strip().lower()
        rows = [row for row in rows if str(row.get("category") or "").lower() == wanted]
    return {
        "version": "openapi-variable-corpus-v1",
        "total_available": len(rows),
        "limit": limit,
        "category": category,
        "items": rows[:limit],
    }


def _get_api_job(db: Session, current_user: User, test_id: int) -> ScanJob:
    job = _authorized_scan_query(db, current_user).filter(ScanJob.id == test_id).first()
    if not job or str(job.mode or "") != "api":
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Teste de API nao encontrado")
    return job


@router.get("/{test_id}", response_model=ScanResponse)
def get_api_test(
    test_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ScanResponse:
    return _scan_to_response(db, _get_api_job(db, current_user, test_id))


@router.post("/{test_id}/stop")
def stop_api_test(
    test_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    _get_api_job(db, current_user, test_id)
    return stop_scan(test_id, db=db, current_user=current_user)


@router.post("/{test_id}/finalize")
def finalize_api_test(
    test_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    _get_api_job(db, current_user, test_id)
    return finalize_scan(test_id, db=db, current_user=current_user)


def _esc(v: Any) -> str:
    import html
    return html.escape(str(v if v is not None else ""))


def _attackpath_html(rep: dict[str, Any], kind: str) -> str:
    """Fluxo da operação + Attack Path, renderizado ABAIXO da tabela OWASP.
    Mostra como um atacante encadeia endpoints reutilizando variáveis
    (requestId/projectId/...) até um achado — o pedido do usuário."""
    flow = rep.get("flow", {}) or {}
    stats = flow.get("stats", {}) or {}
    paths = rep.get("attack_paths", []) or []
    variables = rep.get("variables", []) or []
    by_stage = stats.get("by_stage", {}) or {}
    stage_line = " · ".join(f"{v} {k}" for k, v in by_stage.items()) or "—"
    ext = flow.get("external_variables", []) or []
    dyn = "sim (executado via Caido)" if rep.get("summary", {}).get("flow_dynamic") else "não (modelo estático do contrato)"
    out = [
        "<h2>Fluxo da operação</h2>",
        f'<p class="flowmeta">Nós: <b>{_esc(stats.get("nodes_total", 0))}</b> · '
        f'Dependências (produtor→consumidor): <b>{_esc(stats.get("edges_total", 0))}</b> · '
        f'Estágios: {_esc(stage_line)} · Execução dinâmica: {_esc(dyn)}'
        + (f' · Variáveis sem produtor (seed necessário): {_esc(", ".join(ext[:8]))}' if ext else "")
        + "</p>",
    ]
    if not paths:
        out.append('<p class="flowmeta">Nenhum attack-path derivado do fluxo.</p>')
        return "\n".join(out)
    out.append("<h2>Attack Path</h2>")
    for p in paths[:8]:
        badge = "CONFIRMADO" if p.get("confirmed") else "potencial"
        sev = _esc(p.get("severity"))
        owasp = ", ".join(p.get("owasp") or [])
        out.append(f'<div class="apc apc-{"conf" if p.get("confirmed") else "pot"}">')
        out.append(f'<div class="aph"><span class="apb apb-{sev}">{_esc(badge)}</span> '
                   f'<b>{_esc(p.get("name"))}</b> <span class="apo">{_esc(owasp)}</span></div>')
        out.append("<ol class='apsteps'>")
        for st in p.get("steps", []):
            tags = []
            if st.get("produces"):
                tags.append(f'→ produz {_esc(", ".join(st["produces"]))}')
            if st.get("consumes"):
                tags.append(f'← reusa {_esc(", ".join(st["consumes"]))}')
            tagline = f' <span class="aptag">{" | ".join(tags)}</span>' if tags else ""
            mark = ' <span class="apfind">◆ ACHADO</span>' if st.get("finding") else ""
            owa = f' <span class="apo">[{_esc(st.get("owasp"))}/{_esc(st.get("severity"))}]</span>' if st.get("owasp") else ""
            out.append(f'<li><code>{_esc(st.get("method"))} {_esc(st.get("path"))}</code>{owa}{mark}'
                       f'<div class="apr">{_esc(st.get("result"))}{tagline}</div></li>')
        out.append("</ol></div>")
    if kind == "technical" and variables:
        out.append("<h2>Variáveis observadas (lineage)</h2>")
        out.append('<table><thead><tr><th>Variável</th><th>Origem</th><th>Campo</th><th>Reutilizada em</th></tr></thead><tbody>')
        for v in variables[:40]:
            reused = ", ".join(v.get("reused_in", []) or [])
            out.append(f'<tr><td><code>{_esc(v.get("name"))}</code></td><td>{_esc(v.get("source_endpoint"))}</td>'
                       f'<td>{_esc(v.get("source_field"))}</td><td>{_esc(reused)}</td></tr>')
        out.append("</tbody></table>")
    return "\n".join(out)


def _api_report_html(rep: dict[str, Any], kind: str) -> str:
    s = rep.get("summary", {})
    sev = s.get("findings_by_severity", {}) or {}
    sevline = " · ".join(f"{sev[k]} {k}" for k in ("critical", "high", "medium", "low", "info") if sev.get(k)) or "nenhum"
    title = "Relatório Executivo de API" if kind == "executive" else "Relatório Técnico de API"
    cards = [
        ("Endpoints", s.get("endpoints_total")), ("Testados", f"{s.get('endpoints_tested')}/{s.get('endpoints_total')}"),
        ("Cobertura", f"{s.get('coverage_pct')}%"), ("Da spec", s.get("endpoints_from_spec")),
        ("Descobertos", s.get("endpoints_discovered")), ("Endpoints BAC", s.get("bac_endpoints_tested")),
        ("Achados BAC (conf.)", f"{s.get('bac_confirmed', 0)}/{s.get('bac_findings', 0)}"),
        ("Advisórios", s.get("advisories_total")), ("Achados", s.get("findings_total")),
        ("Skills", f"{s.get('skills_executed')}/{s.get('skills_catalog_total')}"),
    ]
    card_html = "".join(f'<div class="card"><div class="cl">{_esc(l)}</div><div class="cv">{_esc(v)}</div></div>' for l, v in cards)
    cat_rows = "".join(
        f'<tr class="{"bac" if sk.get("is_bac") else ""}"><td>{"●" if sk.get("executed") else "○"}</td><td>{_esc(sk.get("name"))}</td>'
        f'<td>{_esc(sk.get("owasp"))}</td><td>{"BAC" if sk.get("is_bac") else ""}</td><td>{_esc(sk.get("endpoints_covered"))}</td><td>{_esc(sk.get("findings"))}</td></tr>'
        for sk in rep.get("skills_catalog", [])
    )
    attackpath_html = _attackpath_html(rep, kind)
    body = f"""
    <h1>{_esc(title)}</h1>
    <div class="meta">Alvo: <b>{_esc(rep.get('target'))}</b> · Teste #{_esc(rep.get('scan_id'))} · Status: {_esc(rep.get('status'))}</div>
    <div class="cards">{card_html}</div>
    <p class="sev">Severidade dos achados: {_esc(sevline)}</p>
    <h2>Conformidade OWASP API Top 20</h2>
    <table><thead><tr><th></th><th>Teste</th><th>OWASP</th><th></th><th>Endpoints</th><th>Achados</th></tr></thead><tbody>{cat_rows}</tbody></table>
    {attackpath_html}
    """
    if kind == "technical":
        ep_rows = ""
        for e in rep.get("endpoints", []):
            q = e.get("quality", {})
            finds = "".join(f'<li class="s-{_esc(f.get("severity"))}">{_esc(f.get("severity"))}: {_esc(f.get("title"))} ({_esc(f.get("owasp"))})</li>' for f in e.get("findings", []))
            advs = "".join(f'<li class="adv">advisory: {_esc(a.get("title"))}</li>' for a in e.get("advisories", []))
            evs = ""
            for ev in (e.get("evidence") or [])[:4]:
                evs += (f'<div class="ev"><div class="evh">{_esc(ev.get("method"))} {_esc(ev.get("url"))} → HTTP {_esc(ev.get("response_status"))} '
                        f'[{_esc((ev.get("skill_id") or "").replace("skill.api.",""))}]</div>'
                        f'<pre>{_esc(ev.get("curl"))}</pre>'
                        + (f'<pre>req: {_esc(ev.get("request_body"))}</pre>' if ev.get("request_body") else "")
                        + f'<pre>resp: {_esc((ev.get("response_body") or "")[:600])}</pre></div>')
            if not (finds or advs or evs):
                continue
            ep_rows += (f'<div class="epc"><div class="eph"><b>{_esc(e.get("method"))}</b> {_esc(e.get("path"))} '
                        f'<span class="q q-{_esc(q.get("level"))}">{_esc(q.get("label"))}</span> '
                        f'<span class="src">{_esc(e.get("source"))}</span></div>'
                        f'<ul>{finds}{advs}</ul>{evs}</div>')
        body += f"<h2>Detalhe por endpoint (achados, advisórios e evidência)</h2>{ep_rows or '<p>Sem achados/evidências por endpoint.</p>'}"
    css = """
    body{font-family:-apple-system,Segoe UI,Roboto,Arial,sans-serif;color:#1e293b;margin:0;padding:28px;max-width:1000px;margin:auto}
    h1{font-size:22px;margin:0 0 4px} h2{font-size:15px;margin:22px 0 8px;border-bottom:2px solid #e2e8f0;padding-bottom:4px}
    .meta{color:#64748b;font-size:13px;margin-bottom:14px}
    .cards{display:flex;flex-wrap:wrap;gap:8px;margin:10px 0}
    .card{border:1px solid #e2e8f0;border-radius:8px;padding:8px 12px;min-width:92px}
    .cl{font-size:10px;color:#64748b;font-weight:700} .cv{font-size:18px;font-weight:800}
    .sev{font-size:12px;color:#334155} table{width:100%;border-collapse:collapse;font-size:12px}
    th,td{border-bottom:1px solid #e2e8f0;padding:5px 7px;text-align:left} tr.bac{background:rgba(220,38,38,.06)}
    .epc{border:1px solid #e2e8f0;border-radius:8px;padding:10px;margin-bottom:10px} .eph{font-size:13px;margin-bottom:5px}
    .q{font-weight:800;font-size:11px;padding:1px 6px;border-radius:4px} .q-good{color:#16a34a} .q-partial{color:#d97706} .q-weak,.q-none{color:#dc2626}
    .src{color:#2563eb;font-size:11px} ul{margin:4px 0;padding-left:18px;font-size:12px}
    .s-critical,.s-high{color:#dc2626} .s-medium{color:#d97706} .adv{color:#d97706}
    .ev{margin:6px 0;border-left:3px solid #e2e8f0;padding-left:8px} .evh{font-size:11px;font-weight:700;color:#334155}
    pre{background:#f8fafc;border:1px solid #e2e8f0;border-radius:5px;padding:6px;font-size:10.5px;white-space:pre-wrap;word-break:break-all;margin:3px 0}
    .flowmeta{font-size:12px;color:#334155;margin:4px 0 10px}
    .apc{border:1px solid #e2e8f0;border-radius:8px;padding:10px 12px;margin-bottom:10px}
    .apc-conf{border-left:4px solid #dc2626;background:rgba(220,38,38,.04)} .apc-pot{border-left:4px solid #94a3b8}
    .aph{font-size:13px;margin-bottom:6px} .apo{color:#2563eb;font-size:11px;font-weight:700}
    .apb{font-size:10px;font-weight:800;padding:1px 6px;border-radius:4px;color:#fff;background:#94a3b8}
    .apb-critical,.apb-high{background:#dc2626} .apb-medium{background:#d97706} .apb-low,.apb-info{background:#64748b}
    ol.apsteps{margin:4px 0;padding-left:20px;font-size:12px} ol.apsteps li{margin:4px 0}
    ol.apsteps code{background:#f1f5f9;padding:1px 5px;border-radius:4px;font-size:11.5px}
    .apr{color:#64748b;font-size:11px;margin-top:2px} .aptag{color:#0f766e} .apfind{color:#dc2626;font-weight:800;font-size:10.5px}
    @media print{body{padding:0} .epc{break-inside:avoid} .apc{break-inside:avoid}}
    """
    return f"<!doctype html><html lang='pt-br'><head><meta charset='utf-8'><title>{_esc(title)}</title><style>{css}</style></head><body>{body}</body></html>"


@router.get("/{test_id}/openapi.json")
def api_test_openapi_json(test_id: int, download: bool = False, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    """Swagger/OpenAPI 3.0 GERADO a partir dos endpoints descobertos (fuzzing/brute/
    crawl/tráfego) quando não há spec fornecido — baixável como JSON."""
    import json as _json

    from fastapi import Response

    from app.models.models import ObservedRequest, OffensiveEndpoint
    from app.services.api_openapi_builder import build_openapi_spec

    job = _get_api_job(db, current_user, test_id)
    rows: list[dict] = []
    # 1) tráfego observado (tem corpo/headers/resposta -> schemas mais ricos)
    for r in db.query(ObservedRequest).filter(ObservedRequest.scan_job_id == job.id).limit(2000).all():
        if not r.url:
            continue
        rows.append({
            "method": r.method, "url": r.url, "request_headers": dict(r.request_headers or {}),
            "request_body": r.request_body, "status_code": r.status_code, "response_body": r.response_excerpt,
        })
    seen = {(str(x["method"]).upper(), str(x["url"])) for x in rows}
    # 2) endpoints descobertos (brute/crawl/spec) — garante presença mesmo sem tráfego
    for e in db.query(OffensiveEndpoint).filter(OffensiveEndpoint.scan_job_id == job.id).limit(3000).all():
        url = str(getattr(e, "normalized_url", None) or getattr(e, "url", "") or "")
        m = str(getattr(e, "method", "GET") or "GET").upper()
        if not url or (m, url) in seen:
            continue
        seen.add((m, url))
        rows.append({"method": m, "url": url, "status_code": getattr(e, "status_code", None)})
    spec = build_openapi_spec(rows, title=f"API descoberta — {job.target_query}", base_url="")
    content = _json.dumps(spec, ensure_ascii=False, indent=2)
    headers = {}
    if download:
        headers["Content-Disposition"] = f'attachment; filename="openapi-scan-{test_id}.json"'
    return Response(content=content, media_type="application/json", headers=headers)


@router.get("/{test_id}/technical.html")
def api_test_technical_html(test_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    from fastapi import Response
    from app.services.api_endpoint_report import build_api_endpoint_report
    job = _get_api_job(db, current_user, test_id)
    return Response(content=_api_report_html(build_api_endpoint_report(db, job), "technical"), media_type="text/html")


@router.get("/{test_id}/executive.html")
def api_test_executive_html(test_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    from fastapi import Response
    from app.services.api_endpoint_report import build_api_endpoint_report
    job = _get_api_job(db, current_user, test_id)
    return Response(content=_api_report_html(build_api_endpoint_report(db, job), "executive"), media_type="text/html")


@router.get("/{test_id}/report")
def api_test_report(
    test_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    _get_api_job(db, current_user, test_id)
    # Pass explicit values: scan_report's pagination params use FastAPI Query()
    # defaults that only resolve under request DI, not on a direct call.
    return scan_report(
        test_id,
        prioritized_limit=10,
        prioritized_offset=0,
        findings_limit=300,
        findings_offset=0,
        include_targets=None,
        db=db,
        current_user=current_user,
    )


@router.get("/{test_id}/coverage")
def api_test_coverage(
    test_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Per-endpoint API report (the 'forest'): quality of testing PER ENDPOINT
    (spec + crawled), OWASP API Top 20 catalog coverage, and BAC focus."""
    job = _get_api_job(db, current_user, test_id)
    from app.services.api_endpoint_report import build_api_endpoint_report

    return build_api_endpoint_report(db, job)


@router.get("/{test_id}/report.csv")
def api_test_report_csv(
    test_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """CSV extraível com 3 seções: resumo, conformidade OWASP API Top 20
    (por skill: executou/cobertura/achados) e qualidade POR ENDPOINT."""
    import csv
    import io

    from fastapi import Response

    from app.services.api_endpoint_report import build_api_endpoint_report

    job = _get_api_job(db, current_user, test_id)
    rep = build_api_endpoint_report(db, job)
    s = rep.get("summary", {})
    buf = io.StringIO()
    w = csv.writer(buf)

    w.writerow(["# RESUMO"])
    w.writerow(["scan_id", "alvo", "status", "endpoints_total", "da_spec", "descobertos",
                "testados", "cobertura_%", "endpoints_bac_testados", "achados", "achados_bac_confirmados",
                "advisorios", "skills_executadas", "skills_catalogo"])
    w.writerow([rep.get("scan_id"), rep.get("target"), rep.get("status"), s.get("endpoints_total"),
                s.get("endpoints_from_spec"), s.get("endpoints_discovered"), s.get("endpoints_tested"),
                s.get("coverage_pct"), s.get("bac_endpoints_tested"), s.get("findings_total"),
                s.get("bac_confirmed"), s.get("advisories_total"), s.get("skills_executed"), s.get("skills_catalog_total")])
    w.writerow([])

    w.writerow(["# CONFORMIDADE OWASP API TOP 20"])
    w.writerow(["skill_id", "nome", "owasp", "BAC", "executou", "endpoints_cobertos", "achados"])
    for sk in rep.get("skills_catalog", []):
        w.writerow([sk.get("id"), sk.get("name"), sk.get("owasp"), "sim" if sk.get("is_bac") else "",
                    "sim" if sk.get("executed") else "nao", sk.get("endpoints_covered"), sk.get("findings")])
    w.writerow([])

    w.writerow(["# QUALIDADE POR ENDPOINT"])
    w.writerow(["metodo", "path", "origem", "testado", "qualidade", "score", "skills_testadas",
                "bac_testado", "status_http", "achados", "severidades", "advisorios"])
    for e in rep.get("endpoints", []):
        q = e.get("quality", {})
        sev = ";".join(f"{k}:{v}" for k, v in (e.get("findings_by_severity") or {}).items())
        http = ";".join(f"{k}x{v}" for k, v in (e.get("http_status_counts") or {}).items())
        w.writerow([e.get("method"), e.get("path"), e.get("source"), "sim" if e.get("tested") else "nao",
                    q.get("label"), q.get("score"), e.get("skills_tested_count"),
                    "sim" if e.get("bac_tested") else "nao", http, len(e.get("findings") or []),
                    sev, len(e.get("advisories") or [])])
    w.writerow([])

    w.writerow(["# ATTACK PATH"])
    w.writerow(["path_nome", "confirmado", "severidade", "owasp", "ordem", "metodo", "endpoint",
                "produz", "reusa", "achado", "resultado"])
    for p in rep.get("attack_paths", []):
        owasp = "|".join(p.get("owasp") or [])
        for st in p.get("steps", []):
            w.writerow([p.get("name"), "sim" if p.get("confirmed") else "nao", p.get("severity"), owasp,
                        st.get("order"), st.get("method"), st.get("path"),
                        ";".join(st.get("produces") or []), ";".join(st.get("consumes") or []),
                        "sim" if st.get("finding") else "", st.get("result")])
    w.writerow([])

    w.writerow(["# VARIAVEIS / LINEAGE"])
    w.writerow(["variavel", "origem_endpoint", "campo_origem", "reutilizada_em"])
    for v in rep.get("variables", []):
        w.writerow([v.get("name"), v.get("source_endpoint"), v.get("source_field"),
                    ";".join(v.get("reused_in") or [])])
    if not rep.get("variables"):
        for ev in (rep.get("flow", {}) or {}).get("external_variables", []):
            w.writerow([ev, "(sem produtor — seed necessário)", "", ""])

    filename = f"api-report-scan-{test_id}.csv"
    return Response(content=buf.getvalue(), media_type="text/csv",
                    headers={"Content-Disposition": f'attachment; filename="{filename}"'})
