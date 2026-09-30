import { Fragment, useEffect, useMemo, useRef, useState } from "react";
import client from "../api/client";
import CompanyScopeSelect from "../components/CompanyScopeSelect";
import { remediationPriority, remediationSla } from "../lib/reportQuality";
import "../styles/dashboard.css";

/* Relatório de Exposição (Red Team) — dado 100% real de /api/cockpit. */

function _truncate(s, max) {
  const v = String(s || "");
  return v.length <= max ? v : `${v.slice(0, max)}…`;
}

// Searchable + paginated scan/target picker — the native <select> was unusable
// once a company had many scans/targets.
function ScanSearchSelect({ scans, value, onChange, accessGroupId }) {
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");
  const [page, setPage] = useState(0);
  const PAGE = 12;
  const boxRef = useRef(null);

  useEffect(() => {
    const onDoc = (e) => { if (boxRef.current && !boxRef.current.contains(e.target)) setOpen(false); };
    document.addEventListener("mousedown", onDoc);
    return () => document.removeEventListener("mousedown", onDoc);
  }, []);
  useEffect(() => { setPage(0); }, [query, open]);

  const list = Array.isArray(scans) ? scans : [];
  const q = query.trim().toLowerCase();
  const filtered = q ? list.filter((s) => `#${s.id} ${s.target_query || ""} ${s.status || ""}`.toLowerCase().includes(q)) : list;
  const pages = Math.max(1, Math.ceil(filtered.length / PAGE));
  const safePage = Math.min(page, pages - 1);
  const pageItems = filtered.slice(safePage * PAGE, safePage * PAGE + PAGE);
  const selected = list.find((s) => String(s.id) === String(value));
  const label = selected ? `#${selected.id} ${_truncate(selected.target_query, 44)}` : `Último scan${accessGroupId ? " da empresa" : ""}`;
  const pick = (v) => { onChange(v); setOpen(false); setQuery(""); };
  const optStyle = (active) => ({ display: "block", width: "100%", textAlign: "left", padding: "7px 10px", border: "none", borderBottom: "1px solid var(--line,#f0f0f0)", background: active ? "var(--brand-50,#eef2ff)" : "transparent", cursor: "pointer", fontSize: 12.5, color: "var(--ink,#222)" });
  const pagerBtn = { padding: "2px 10px", border: "1px solid var(--line,#ddd)", borderRadius: 6, background: "#fff", cursor: "pointer" };

  return (
    <div ref={boxRef} style={{ position: "relative", minWidth: 260 }}>
      <button type="button" onClick={() => setOpen((v) => !v)} className="scan-select" style={{ width: "100%", textAlign: "left", cursor: "pointer" }} aria-haspopup="listbox" aria-expanded={open}>
        {label} <span style={{ float: "right", opacity: 0.6 }}>▾</span>
      </button>
      {open && (
        <div style={{ position: "absolute", zIndex: 30, top: "calc(100% + 4px)", left: 0, right: 0, background: "var(--surface,#fff)", border: "1px solid var(--line,#ddd)", borderRadius: 8, boxShadow: "0 8px 24px rgba(0,0,0,.12)", overflow: "hidden" }}>
          <div style={{ padding: 6, borderBottom: "1px solid var(--line,#eee)" }}>
            <input autoFocus type="text" value={query} onChange={(e) => setQuery(e.target.value)} placeholder={`Buscar entre ${list.length} scans/alvos…`} style={{ width: "100%", padding: "6px 8px", borderRadius: 6, border: "1px solid var(--line,#ddd)", fontSize: 13 }} />
          </div>
          <div style={{ maxHeight: 240, overflowY: "auto" }}>
            <button type="button" onClick={() => pick("")} style={optStyle(!value)}>Último scan{accessGroupId ? " da empresa" : ""}</button>
            {pageItems.map((s) => (
              <button key={s.id} type="button" onClick={() => pick(String(s.id))} style={optStyle(String(s.id) === String(value))}>
                <b>#{s.id}</b> {_truncate(s.target_query, 56)}{s.status ? ` · ${s.status}` : ""}
              </button>
            ))}
            {pageItems.length === 0 && <div style={{ padding: 10, fontSize: 12, color: "var(--ink-muted,#888)" }}>Nenhum scan corresponde.</div>}
          </div>
          {filtered.length > PAGE && (
            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", padding: 6, borderTop: "1px solid var(--line,#eee)", fontSize: 11, color: "var(--ink-muted,#888)" }}>
              <button type="button" onClick={() => setPage((p) => Math.max(0, p - 1))} disabled={safePage <= 0} style={{ ...pagerBtn, opacity: safePage <= 0 ? 0.4 : 1 }}>‹</button>
              <span>{filtered.length} · pág {safePage + 1}/{pages}</span>
              <button type="button" onClick={() => setPage((p) => Math.min(pages - 1, p + 1))} disabled={safePage >= pages - 1} style={{ ...pagerBtn, opacity: safePage >= pages - 1 ? 0.4 : 1 }}>›</button>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

const SEV_LABEL = { critical: "Crítico", high: "Alto", medium: "Médio", low: "Baixo", info: "Info" };
const STATUS_LABEL = { confirmed: "Confirmado", candidate: "Candidato", hypothesis: "Hipótese", refuted: "Refutado", confirmado: "Confirmado", candidato: "Candidato" };
const HEAT_SEV = ["critical", "high", "medium", "low"];
const HEAT_BASE = { critical: "214,69,69", high: "254,123,2", medium: "212,165,0", low: "34,145,96" };
function heatColor(v, sev, max) {
  if (!v) return "var(--surface-soft)";
  const alpha = 0.15 + (v / Math.max(1, max)) * 0.85;
  return `rgba(${HEAT_BASE[sev]}, ${alpha.toFixed(3)})`;
}

export default function RedTeamReportPage() {
  const [data, setData] = useState(null);
  const [scanId, setScanId] = useState("");
  const [accessGroupId, setAccessGroupId] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [reportContract, setReportContract] = useState(null);
  const [extras, setExtras] = useState(null);
  const [companyName, setCompanyName] = useState("");

  useEffect(() => {
    setLoading(true);
    const params = new URLSearchParams();
    if (scanId) params.set("scan_id", scanId);
    if (accessGroupId) params.set("access_group_id", accessGroupId);
    const qs = params.toString() ? `?${params.toString()}` : "";
    client
      .get(`/api/cockpit${qs}`)
      .then(async ({ data }) => {
        setData(data || null);
        const selectedId = data?.scan?.id;
        if (!selectedId) { setReportContract(null); setExtras(null); return; }
        try {
          const response = await client.get(`/api/pentest/scans/${selectedId}/report-contract`, {
            params: { findings_limit: 200, findings_offset: 0 },
            _skipToast: true,
          });
          setReportContract(response.data || null);
        } catch {
          setReportContract(null);
        }
        try {
          const ex = await client.get(`/api/scans/${selectedId}/report-extras`, { _skipToast: true });
          setExtras(ex.data || null);
        } catch {
          setExtras(null);
        }
      })
      .catch(() => setError("Falha ao carregar o relatório."))
      .finally(() => setLoading(false));
  }, [scanId, accessGroupId]);

  const findings = useMemo(() => (Array.isArray(data?.findings) ? data.findings.map((f) => ({
    ...f,
    isJewel: Boolean(f.is_jewel),
    mitreStr: Array.isArray(f.mitre) && f.mitre.length ? f.mitre.map((m) => m.id).join(", ") : "—",
  })) : []), [data]);

  const plan = useMemo(() => {
    const withP = findings.map((f) => {
      const p = remediationPriority(f);
      return { ...f, p, remediation: remediationSla(p) };
    }).filter((f) => f.p);
    const order = { P0: 0, P1: 1, P2: 2 };
    return withP.sort((a, b) => order[a.p] - order[b.p] || -(a.cvss || 0) - -(b.cvss || 0) || (b.epss || 0) - (a.epss || 0));
  }, [findings]);
  // Plano de ação mostra apenas P0 e P1 (ações imediatas).
  const planTop = useMemo(() => plan.filter((f) => f.p === "P0" || f.p === "P1"), [plan]);

  const trend = data?.score?.trend || [];
  const sev = data?.severity || {};
  const kpis = data?.kpis || {};
  const jewels = data?.crown_jewels || [];
  const heatmap = data?.heatmap || null;
  const quality = data?.quality || null;
  const findingsPage = data?.findings_page || {};
  const execution = quality?.execution_metrics || {};
  const readiness = reportContract?.readiness || {};
  const attackPaths = extras?.attack_paths?.paths || [];
  const frameworkRisk = extras?.framework_risk || {};
  const vulnByClass = extras?.vuln_by_class || [];
  const attackSurface = extras?.attack_surface || [];
  const crownValidation = extras?.crown_validation || null;
  const FW_LABEL = { iso27001: "ISO 27001", nist: "NIST CSF", cis_v8: "CIS v8", pci: "PCI DSS" };
  const SURFACE_SEV = ["critical", "high", "medium", "low"];
  const classMax = Math.max(1, ...vulnByClass.flatMap((r) => SURFACE_SEV.map((s) => r[s] || 0)));

  // Exporta o CSV completo (id, alvo, host, família, severidade, cvss, cve,
  // verificação, url, recomendação). dedupe=false ⇒ inventário integral, igual
  // ao Anexo B do relatório (todos os achados e alvos, sem colapsar repetidos).
  const exportCsv = async () => {
    const sid = data?.scan?.id;
    try {
      const res = await client.get("/api/findings/export.csv", {
        params: {
          dedupe: false,
          ...(sid ? { scan_id: sid } : (accessGroupId ? { access_group_id: accessGroupId } : {})),
        },
        responseType: "blob",
        _skipToast: true,
      });
      const url = URL.createObjectURL(new Blob([res.data], { type: "text/csv;charset=utf-8" }));
      const a = document.createElement("a");
      a.href = url;
      a.download = `vulnerabilidades${sid ? `-scan-${sid}` : ""}.csv`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      setTimeout(() => URL.revokeObjectURL(url), 60000);
    } catch {
      window.alert("Falha ao exportar CSV.");
    }
  };

  // Abre o Relatório Executivo v2 com o nome da empresa no cabeçalho.
  const openValidExec = async () => {
    const sid = data?.scan?.id;
    if (!sid) return;
    try {
      const res = await client.get(`/api/scans/${sid}/valid-executive-report`, {
        params: companyName.trim() ? { company: companyName.trim() } : {},
        responseType: "blob",
        _skipToast: true,
      });
      const url = URL.createObjectURL(new Blob([res.data], { type: "text/html;charset=utf-8" }));
      window.open(url, "_blank", "noopener,noreferrer");
      setTimeout(() => URL.revokeObjectURL(url), 60000);
    } catch {
      window.alert("Não foi possível gerar o Relatório Executivo.");
    }
  };

  // Abre o Relatório Técnico v2 — mesmo design, com inventário completo,
  // attack paths, MITRE/NIST/CIS/ISO, CVEs e catálogo de recomendações.
  const openValidTech = async () => {
    const sid = data?.scan?.id;
    if (!sid) return;
    try {
      const res = await client.get(`/api/scans/${sid}/valid-technical-report`, {
        params: companyName.trim() ? { company: companyName.trim() } : {},
        responseType: "blob",
        _skipToast: true,
      });
      const url = URL.createObjectURL(new Blob([res.data], { type: "text/html;charset=utf-8" }));
      window.open(url, "_blank", "noopener,noreferrer");
      setTimeout(() => URL.revokeObjectURL(url), 60000);
    } catch {
      window.alert("Não foi possível gerar o Relatório Técnico.");
    }
  };

  if (loading) {
    return <main className="dash"><div className="content" style={{ padding: "32px 40px" }}><div className="dash-state"><div><div className="spin" /><p className="st-title">Gerando relatório…</p></div></div></div></main>;
  }
  if (error) {
    return <main className="dash"><div className="content" style={{ padding: "32px 40px" }}><div className="dash-err">{error}</div></div></main>;
  }

  const score = Number(data?.score?.value || 0);
  const grade = data?.score?.grade || "—";
  const scan = data?.scan;

  return (
    <main className="dash">
      <div className="content report-shell">
        {/* Ações (não imprimem) */}
        <section className="report-actions no-print">
          <CompanyScopeSelect value={accessGroupId} onChange={(value) => { setAccessGroupId(value); setScanId(""); }} style={{ minWidth: 220 }} />
          <ScanSearchSelect scans={data?.scans || []} value={scanId} onChange={setScanId} accessGroupId={accessGroupId} />
          {scan?.id && (
            <input
              type="text"
              value={companyName}
              onChange={(e) => setCompanyName(e.target.value)}
              placeholder="Empresa dona do relatório"
              aria-label="Nome da empresa dona do relatório"
              style={{ padding: "7px 11px", borderRadius: 8, border: "1px solid var(--line)", fontSize: 13, minWidth: 200 }}
            />
          )}
          <div className="report-actions-right">
            <button className="sk-btn-ghost" onClick={exportCsv}>Baixar CSV</button>
            {scan?.id && (
              <button className="sk-btn-primary" onClick={openValidTech}>Relatório Técnico</button>
            )}
            {scan?.id && (
              <button className="sk-btn-primary" onClick={openValidExec}>Relatório Executivo</button>
            )}
          </div>
        </section>

        <section className="report-section">
          <div className="sk-eyebrow">Qualidade e completude do teste</div>
          {quality ? (
            <div className="report-kpis" style={{ marginTop: 10 }}>
              <div><span>Quality score</span><strong className="sk-mono">{Number(quality.score || 0).toFixed(1)} · {quality.grade || "—"}</strong></div>
              <div><span>Gate</span><strong className="sk-mono">{String(quality.quality_gate?.status || "não executado").replaceAll("_", " ")}</strong></div>
              <div><span>Fases saudáveis</span><strong className="sk-mono">{Number(quality.summary?.healthy_phases || 0)}/{Number(quality.summary?.expected_phases || 0)}</strong></div>
              <div><span>Verificados</span><strong className="sk-mono">{Number(quality.summary?.verified_findings || 0)}/{Number(quality.summary?.findings_total || 0)}</strong></div>
              <div><span>Sucesso de execução</span><strong className="sk-mono">{Number(execution.success_pct || 0).toFixed(1)}%</strong></div>
              <div><span>Paralelismo médio</span><strong className="sk-mono">{Number(execution.average_parallelism || 0).toFixed(1)}×</strong></div>
              <div><span>Espera p95</span><strong className="sk-mono">{execution.queue_wait_p95_seconds ? `${Math.round(execution.queue_wait_p95_seconds / 60)} min` : "—"}</strong></div>
              <div><span>ETA</span><strong className="sk-mono">{execution.eta_seconds != null ? `${Math.round(execution.eta_seconds / 60)} min` : "concluído"}</strong></div>
            </div>
          ) : <div className="report-empty">Qualidade ainda não calculada.</div>}
          {quality?.gaps?.length > 0 && (
            <ul style={{ margin: "12px 0 0", paddingLeft: 18 }}>
              {quality.gaps.slice(0, 5).map((gap, index) => <li key={index}><b>{gap.title}</b> — {gap.action}</li>)}
            </ul>
          )}
          {reportContract && (
            <p className="report-sub" style={{ marginTop: 10 }}>
              Readiness: <b>{String(readiness.status || "unknown").replaceAll("_", " ")}</b>
              {readiness.blockers?.length ? ` · ${readiness.blockers.length} blocker(s)` : ""}
              {reportContract.auth?.required ? ` · autenticação ${reportContract.auth.ready ? "pronta" : "incompleta"}` : " · escopo anônimo"}
            </p>
          )}
        </section>

        {/* Cabeçalho do documento */}
        <header className="report-head">
          <div>
            <div className="sk-eyebrow" style={{ color: "var(--brand-700)" }}>Relatório de Exposição · confidencial</div>
            <h1>O que o time precisa atacar e validar primeiro</h1>
            <p className="report-meta sk-mono">
              {scan?.target_query || "—"} · {scan ? `ciclo #${scan.id}` : "—"} · {scan?.status || ""}
            </p>
          </div>
          <div className="report-rating">
            <div><b className="sk-mono">{grade}</b><span>grade</span></div>
            <i />
            <div><b className="sk-mono">{score.toFixed(1)}</b><span>score</span></div>
          </div>
        </header>

        {/* 01 Sumário executivo */}
        <section className="report-section">
          <div className="sk-eyebrow">01 · Sumário executivo</div>
          <div className="report-summary-grid">
            <p className="report-narrative">
              Neste ciclo foram observados <b>{Number(sev.critical || 0)}</b> achados críticos e <b>{Number(sev.high || 0)}</b> altos
              em <b>{Number(kpis.assets_exposed || 0)}</b> ativo(s) da superfície analisada.
              {" "}<b>{Number(kpis.jewels_at_risk || 0)}</b> de <b>{Number(kpis.jewels_total || 0)}</b> joia(s) da coroa apresentam achado correlacionado.
              {" "}O rating consolidado do alvo é <b>{score.toFixed(1)}</b> (grade <b>{grade}</b>).
            </p>
            <div className="report-kpis">
              <div><span>Críticos + Altos</span><strong className="sk-mono">{Number(kpis.critical_high || 0)}</strong></div>
              <div><span>Achados abertos</span><strong className="sk-mono">{Number(kpis.findings_open || 0)}</strong></div>
              <div><span>Joias em risco</span><strong className="sk-mono">{Number(kpis.jewels_at_risk || 0)}/{Number(kpis.jewels_total || 0)}</strong></div>
              <div><span>Ativos expostos</span><strong className="sk-mono">{Number(kpis.assets_exposed || 0)}</strong></div>
            </div>
          </div>
        </section>

        {/* 02 Risco por framework */}
        <section className="report-section">
          <div className="sk-eyebrow">02 · Risco por framework</div>
          <span className="report-sub">maturidade estimada por framework a partir das evidências reais do scan</span>
          {Object.keys(frameworkRisk).length === 0 ? (
            <div className="report-empty">Risco por framework indisponível.</div>
          ) : (
            <div className="report-kpis" style={{ marginTop: 10 }}>
              {Object.entries(frameworkRisk).map(([key, fw]) => {
                const score = Number(fw.score || 0);
                const tone = score >= 70 ? "var(--sev-low-text)" : score >= 40 ? "var(--sev-medium-text)" : "var(--sev-critical-text)";
                return (
                  <div key={key}>
                    <span>{FW_LABEL[key] || key}</span>
                    <strong className="sk-mono" style={{ color: tone }}>{score.toFixed(1)} · {fw.grade || "—"}</strong>
                  </div>
                );
              })}
            </div>
          )}
        </section>

        {/* 03 Heatmap vulnerabilidades por classe */}
        <section className="report-section">
          <div className="sk-eyebrow">03 · Heatmap · vulnerabilidades por classe</div>
          <span className="report-sub">famílias de vulnerabilidade × severidade (dado real por finding)</span>
          {vulnByClass.length === 0 ? (
            <div className="report-empty">Sem vulnerabilidades classificáveis neste ciclo.</div>
          ) : (
            <div className="report-heatgrid">
              <span />
              {HEAT_SEV.map((s) => <b key={s}>{SEV_LABEL[s]}</b>)}
              <b>Tot</b>
              {vulnByClass.slice(0, 20).map((row) => (
                <Fragment key={row.family}>
                  <strong className="report-heat-label">{row.label}</strong>
                  {HEAT_SEV.map((s) => {
                    const v = Number(row[s] || 0);
                    const light = classMax > 0 && v / classMax > 0.45;
                    return <span key={s} className="report-heat-cell sk-mono" style={{ background: heatColor(v, s, classMax), color: light ? "#fff" : "var(--ink-soft)" }}>{v || ""}</span>;
                  })}
                  <em className="report-heat-tot sk-mono">{row.total}</em>
                </Fragment>
              ))}
            </div>
          )}
        </section>

        {/* 04 Plano de ação priorizado */}
        <section className="report-section">
          <div className="sk-eyebrow">04 · Plano de ação priorizado (P0/P1)</div>
          <span className="report-sub">somente P0 e P1 — ordenado por severidade, valor do alvo (joia), CVSS e EPSS</span>
          {planTop.length === 0 ? (
            <div className="report-empty">Não há achados P0 ou P1 neste ciclo.</div>
          ) : (
            <div className="attack-table-wrap">
              <table className="attack-table report-plan">
                <thead>
                  <tr><th>Prio</th><th>Achado</th><th>Alvo</th><th>Esforço</th><th>CVSS</th><th>EPSS</th><th>Evidência</th></tr>
                </thead>
                <tbody>
                  {planTop.map((f) => (
                    <tr key={f.id}>
                      <td><span className={`prio-badge prio-${f.p}`}>{f.p}</span></td>
                      <td>
                        <b>{f.title}</b>
                        {f.isJewel && <small className="report-jewel-flag">↳ atinge joia da coroa</small>}
                        <small className="report-plan-reco"><b>Recomendação:</b> {f.recommendation || "Sem recomendação registrada."}</small>
                      </td>
                      <td className="sk-mono">{f.target}</td>
                      <td>{f.remediation.effort}</td>
                      <td className="num sk-mono">{f.cvss ? Number(f.cvss).toFixed(1) : "—"}</td>
                      <td className="num sk-mono">{f.epss ? `${Math.round(f.epss * 100)}%` : "—"}</td>
                      <td><span className="evidence-pill">{STATUS_LABEL[f.status] || f.status}</span></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>

        <div className="report-two-col">
          {/* 03 Heatmap superfície × severidade */}
          <section className="report-section">
            <div className="sk-eyebrow">05 · Heatmap superfície × severidade</div>
            <span className="report-sub">onde os achados se acumulam</span>
            {!heatmap || (heatmap.total_findings || 0) === 0 ? (
              <div className="report-empty">Sem achados classificáveis neste ciclo.</div>
            ) : (
              <div className="report-heatgrid">
                <span />
                {HEAT_SEV.map((s) => <b key={s}>{SEV_LABEL[s]}</b>)}
                <b>Tot</b>
                {(heatmap.categories || []).map((cat) => {
                  const row = heatmap.matrix?.[cat] || {};
                  const tot = HEAT_SEV.reduce((a, s) => a + Number(row[s] || 0), 0);
                  return (
                    <Fragment key={cat}>
                      <strong className="report-heat-label">{cat}</strong>
                      {HEAT_SEV.map((s) => {
                        const v = Number(row[s] || 0);
                        const light = heatmap.max > 0 && v / heatmap.max > 0.45;
                        return <span key={s} className="report-heat-cell sk-mono" style={{ background: heatColor(v, s, heatmap.max), color: light ? "#fff" : "var(--ink-soft)" }}>{v || ""}</span>;
                      })}
                      <em className="report-heat-tot sk-mono">{tot}</em>
                    </Fragment>
                  );
                })}
              </div>
            )}
          </section>

          {/* 04 Joias da coroa */}
          <section className="report-section">
            <div className="sk-eyebrow">06 · Joias da coroa</div>
            {crownValidation && (
              <div className="report-sub" style={{ marginBottom: 8 }}>
                {crownValidation.total === 0
                  ? "Nenhuma joia da coroa definida para este alvo — defina ativos de alto valor para validar exposição direcionada."
                  : `${crownValidation.total} joia(s) definida(s) · ${crownValidation.with_findings} com achado correlacionado.`}
              </div>
            )}
            {jewels.length === 0 && !(crownValidation?.hosts?.length) ? (
              <div className="report-empty">Nenhuma joia da coroa identificada neste ciclo.</div>
            ) : (
              <ul className="report-jewels">
                {(crownValidation?.hosts?.length ? crownValidation.hosts.map((h) => ({
                  target: h.host, label: `${h.vulns} achado(s)`, findings_total: h.vulns,
                  flag: h.critical > 0 ? `${h.critical} crítico(s)` : h.high > 0 ? `${h.high} alto(s)` : "",
                })) : jewels.slice(0, 8)).map((j, i) => (
                  <li key={i}>
                    <b className="sk-mono">{j.target || j.asset || j.host || "joia"}</b>
                    <span>
                      {j.label || j.type || j.category || "ativo de alto valor"}
                      {j.findings_total && !j.label?.includes("achado") ? ` · ${j.findings_total} achado(s)` : ""}
                      {j.flag ? ` · ${j.flag}` : ""}
                    </span>
                  </li>
                ))}
              </ul>
            )}
          </section>
        </div>

        {/* 05 Evolução — só com histórico real (≥2 scans do mesmo alvo) */}
        {trend.length >= 2 && (
          <section className="report-section">
            <div className="sk-eyebrow">07 · Evolução entre ciclos</div>
            <div className="report-evolution">
              {trend.map((t) => {
                const h = Math.max(4, Math.min(100, Number(t.rating_score || 0)));
                const tone = h >= 80 ? "low" : h >= 60 ? "medium" : "critical";
                return (
                  <div key={t.scan_id} className="evo-bar">
                    <span className="evo-val sk-mono">{Number(t.rating_score || 0).toFixed(0)}</span>
                    <i className={`evo-fill evo-${tone}`} style={{ height: `${h}%` }} />
                    <span className="evo-scan sk-mono">#{t.scan_id}</span>
                  </div>
                );
              })}
            </div>
          </section>
        )}

        {/* 06 Superfície de ataque × vulnerabilidades */}
        <section className="report-section">
          <div className="sk-eyebrow">08 · Superfície de ataque</div>
          <span className="report-sub">ativos expostos ordenados por criticidade e volume de vulnerabilidades</span>
          {attackSurface.length === 0 ? (
            <div className="report-empty">Sem superfície com vulnerabilidades classificáveis.</div>
          ) : (
            <div className="attack-table-wrap">
              <table className="attack-table">
                <thead>
                  <tr><th>Ativo / superfície</th><th className="num">Vulns</th><th className="num">Críticas</th><th className="num">Altas</th><th className="num">Médias</th><th className="num">Baixas</th></tr>
                </thead>
                <tbody>
                  {attackSurface.slice(0, 30).map((r) => (
                    <tr key={r.host}>
                      <td className="sk-mono">{r.host}</td>
                      <td className="num sk-mono"><b>{r.total}</b></td>
                      <td className="num sk-mono" style={{ color: r.critical ? "var(--sev-critical-text)" : "var(--ink-muted)" }}>{r.critical || "—"}</td>
                      <td className="num sk-mono" style={{ color: r.high ? "var(--sev-high-text)" : "var(--ink-muted)" }}>{r.high || "—"}</td>
                      <td className="num sk-mono">{r.medium || "—"}</td>
                      <td className="num sk-mono">{r.low || "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {attackSurface.length > 30 && <p className="report-sub">Exibindo os 30 ativos mais críticos de {attackSurface.length}. Use o CSV para o inventário completo.</p>}
            </div>
          )}
        </section>

        {/* 09 Caminhos de ataque */}
        <section className="report-section">
          <div className="sk-eyebrow">09 · Caminhos de ataque</div>
          <span className="report-sub">cadeias de exposição rumo aos objetivos, ordenadas por severidade</span>
          {attackPaths.length === 0 ? (
            <div className="report-empty">Nenhum caminho de ataque correlacionado neste ciclo.</div>
          ) : (
            <ol className="report-attack-paths" style={{ margin: "8px 0 0", paddingLeft: 18, display: "grid", gap: 10 }}>
              {attackPaths.slice(0, 10).map((p, i) => {
                const steps = Array.isArray(p.steps) ? p.steps : [];
                const obj = p.objective?.target || p.objective?.subdomain || p.objective || "objetivo";
                return (
                  <li key={i}>
                    <b className="sk-mono">{String(obj)}</b>
                    {p.objective_reachable ? <span className="report-jewel-flag"> ↳ alcançável</span> : null}
                    <div className="sk-mono" style={{ fontSize: 12, color: "var(--ink-muted)", marginTop: 3 }}>
                      {steps.slice(0, 6).map((s, j) => (
                        <span key={j}>
                          {j > 0 ? " → " : ""}
                          <span style={{ color: s.severity === "critical" ? "var(--sev-critical-text)" : s.severity === "high" ? "var(--sev-high-text)" : "var(--ink-soft)" }}>
                            {s.family || s.title || s.id || "passo"}
                          </span>
                        </span>
                      ))}
                      {steps.length > 6 ? ` … (+${steps.length - 6})` : ""}
                      {steps.length === 0 ? "sem passos correlacionados" : ""}
                    </div>
                  </li>
                );
              })}
            </ol>
          )}
        </section>

        <footer className="report-foot sk-mono">
          ScriptKidd.o · Relatório gerado automaticamente · uso interno confidencial
        </footer>
      </div>
    </main>
  );
}
