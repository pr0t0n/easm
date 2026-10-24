// API Security report — the "forest": per-endpoint test quality.
// Fetches GET /api/apitest/{id}/coverage and renders: summary, the OWASP API
// Top 20 catalog (which tests exist / ran), and a per-endpoint table validating
// testing quality PER ENDPOINT (spec + crawler-discovered), BAC-focused.
import { Fragment, useCallback, useEffect, useState } from "react";
import { useParams, useNavigate } from "react-router-dom";
import client from "../api/client";

const SEV_COLOR = {
  critical: "var(--sev-high-text, #dc2626)",
  high: "var(--sev-high-text, #dc2626)",
  medium: "var(--sev-medium-text, #d97706)",
  low: "var(--sev-low-text, #16a34a)",
  info: "var(--ink-muted, #64748b)",
};
const QUALITY = {
  good: { label: "completo", color: "#16a34a" },
  partial: { label: "parcial", color: "#d97706" },
  weak: { label: "superficial", color: "#dc2626" },
  none: { label: "não testado", color: "#64748b" },
};

function Stat({ label, value, color }) {
  return (
    <div style={{ background: "var(--surface-2, #f8fafc)", border: "1px solid var(--border, #e2e8f0)", borderRadius: 10, padding: "10px 14px", minWidth: 120 }}>
      <div style={{ fontSize: 11, color: "var(--ink-muted)", fontWeight: 700 }}>{label}</div>
      <div className="sk-mono" style={{ fontSize: 20, fontWeight: 800, color: color || "var(--ink)" }}>{value}</div>
    </div>
  );
}

function ApiReportIndex() {
  const navigate = useNavigate();
  const [rows, setRows] = useState([]);
  const [loading, setLoading] = useState(true);
  useEffect(() => {
    client.get("/api/apitest").then(({ data }) => setRows(Array.isArray(data) ? data : [])).catch(() => {}).finally(() => setLoading(false));
  }, []);
  const card = { background: "var(--surface, #fff)", border: "1px solid var(--border, #e2e8f0)", borderRadius: 12, padding: 18 };
  return (
    <div style={{ padding: "22px 26px", maxWidth: 1000, margin: "0 auto" }}>
      <div className="sk-eyebrow">Entrega</div>
      <h1 style={{ margin: "2px 0 14px", fontSize: 21, fontWeight: 800, color: "var(--ink)" }}>Relatórios de API</h1>
      <div style={card}>
        {loading ? <div style={{ color: "var(--ink-muted)" }}>Carregando…</div>
          : rows.length === 0 ? <div style={{ color: "var(--ink-muted)" }}>Nenhum teste de API ainda. Crie um em <a href="/api" style={{ color: "var(--brand,#2563eb)" }}>API</a>.</div>
          : (
          <table className="sk-mono" style={{ width: "100%", borderCollapse: "collapse", fontSize: 12.5 }}>
            <thead><tr style={{ textAlign: "left", color: "var(--ink-muted)", borderBottom: "1px solid var(--border)" }}>
              <th style={{ padding: "7px 8px" }}>#</th><th style={{ padding: "7px 8px" }}>Alvo</th><th style={{ padding: "7px 8px" }}>Status</th><th style={{ padding: "7px 8px" }}>Achados</th><th></th>
            </tr></thead>
            <tbody>
              {rows.map((t) => (
                <tr key={t.id} style={{ borderBottom: "1px solid var(--border)" }}>
                  <td style={{ padding: "7px 8px", fontWeight: 800 }}>{t.id}</td>
                  <td style={{ padding: "7px 8px" }}>{t.target_query}</td>
                  <td style={{ padding: "7px 8px" }}>{t.status}</td>
                  <td style={{ padding: "7px 8px", color: t.open_critical ? "var(--sev-high-text,#dc2626)" : "var(--ink)" }}>
                    {(t.open_critical||0)+(t.open_high||0)+(t.open_medium||0)+(t.open_low||0)+(t.open_info||0)}
                  </td>
                  <td style={{ padding: "7px 8px" }}>
                    <button type="button" onClick={() => navigate(`/relatorios/api/${t.id}`)}
                      style={{ padding: "4px 10px", borderRadius: 6, border: "1px solid var(--border)", background: "transparent", color: "var(--brand,#2563eb)", cursor: "pointer", fontWeight: 700 }}>Abrir relatório</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}

export default function ApiReportPage() {
  const { id } = useParams();
  return id ? <ApiReportDetail id={id} /> : <ApiReportIndex />;
}

function ApiReportDetail({ id }) {
  const navigate = useNavigate();
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [err, setErr] = useState("");
  const [expanded, setExpanded] = useState(null);

  const load = useCallback(async () => {
    try {
      const { data } = await client.get(`/api/apitest/${id}/coverage`);
      setData(data); setErr("");
    } catch (e) {
      setErr(e?.response?.data?.detail || "Falha ao carregar o relatório.");
    } finally { setLoading(false); }
  }, [id]);

  useEffect(() => { load(); }, [load]);

  if (loading) return <div style={{ padding: 26, color: "var(--ink-muted)" }}>Carregando relatório…</div>;
  if (err) return <div style={{ padding: 26, color: "var(--sev-high-text, #dc2626)" }}>{err}</div>;
  if (!data) return null;

  const s = data.summary || {};
  const sev = s.findings_by_severity || {};
  const card = { background: "var(--surface, #fff)", border: "1px solid var(--border, #e2e8f0)", borderRadius: 12, padding: 18, marginBottom: 18 };

  return (
    <div style={{ padding: "22px 26px", maxWidth: 1240, margin: "0 auto" }}>
      <button type="button" onClick={() => navigate("/api")}
        style={{ background: "none", border: "none", color: "var(--brand, #2563eb)", cursor: "pointer", fontSize: 12, padding: 0, marginBottom: 8 }}>← Voltar para API</button>
      <div style={{ marginBottom: 14 }}>
        <div className="sk-eyebrow">Relatório de API · teste #{data.scan_id}</div>
        <h1 style={{ margin: "2px 0 2px", fontSize: 21, fontWeight: 800, color: "var(--ink)" }}>{data.target}</h1>
        <span className="sk-mono" style={{ fontSize: 12, color: "var(--ink-muted)" }}>status: {data.status}</span>
      </div>

      {/* Forest summary */}
      <div style={{ ...card, display: "flex", gap: 10, flexWrap: "wrap" }}>
        <Stat label="Endpoints" value={s.endpoints_total} />
        <Stat label="Testados" value={`${s.endpoints_tested}/${s.endpoints_total}`} color="#16a34a" />
        <Stat label="Cobertura" value={`${s.coverage_pct}%`} color={s.coverage_pct >= 80 ? "#16a34a" : s.coverage_pct >= 40 ? "#d97706" : "#dc2626"} />
        <Stat label="Da spec" value={s.endpoints_from_spec} />
        <Stat label="Descobertos (crawler)" value={s.endpoints_discovered} color="var(--brand, #2563eb)" />
        <Stat label="Endpoints BAC testados" value={s.bac_endpoints_tested} />
        <Stat label="Achados BAC" value={s.bac_findings} color={s.bac_findings ? "#dc2626" : "var(--ink)"} />
        <Stat label="Achados" value={s.findings_total} color={sev.critical ? "#dc2626" : "var(--ink)"} />
        <Stat label="Skills executadas" value={`${s.skills_executed}/${s.skills_catalog_total}`} />
      </div>
      {(sev.critical || sev.high || sev.medium) && (
        <div style={{ marginTop: -8, marginBottom: 18, fontSize: 12, color: "var(--ink-muted)" }} className="sk-mono">
          Severidade: {["critical", "high", "medium", "low", "info"].filter((k) => sev[k]).map((k) => (
            <span key={k} style={{ color: SEV_COLOR[k], fontWeight: 800, marginRight: 10 }}>{sev[k]} {k}</span>
          ))}
        </div>
      )}

      {/* OWASP API Top 20 catalog (which tests exist / ran) */}
      <div style={card}>
        <h2 style={{ margin: "0 0 10px", fontSize: 15, fontWeight: 800, color: "var(--ink)" }}>Testes OWASP API Top 20</h2>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(260px, 1fr))", gap: 7 }}>
          {(data.skills_catalog || []).map((sk) => (
            <div key={sk.id} className="sk-mono" style={{ fontSize: 11, padding: "7px 9px", borderRadius: 7, border: "1px solid var(--border)",
              background: sk.is_bac ? "var(--sev-high-bg, rgba(220,38,38,.07))" : "transparent", opacity: sk.executed ? 1 : 0.55 }}>
              <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                <span style={{ color: sk.executed ? "#16a34a" : "var(--ink-muted)" }}>{sk.executed ? "●" : "○"}</span>
                <span style={{ fontWeight: 800, color: "var(--ink)" }}>{sk.name}</span>
                {sk.is_bac && <span style={{ color: "var(--sev-high-text, #dc2626)", fontWeight: 800 }}>BAC</span>}
              </div>
              <div style={{ color: "var(--ink-muted)", marginTop: 2 }}>
                {sk.owasp} · {sk.endpoints_covered} endpoints · {sk.findings} achados
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Per-endpoint forest */}
      <div style={card}>
        <h2 style={{ margin: "0 0 10px", fontSize: 15, fontWeight: 800, color: "var(--ink)" }}>
          Qualidade por endpoint <span className="sk-mono" style={{ fontSize: 11, color: "var(--ink-muted)", fontWeight: 400 }}>(pior cobertura primeiro)</span>
        </h2>
        <div style={{ overflowX: "auto" }}>
          <table className="sk-mono" style={{ width: "100%", borderCollapse: "collapse", fontSize: 12 }}>
            <thead>
              <tr style={{ textAlign: "left", color: "var(--ink-muted)", borderBottom: "1px solid var(--border)" }}>
                <th style={{ padding: "6px 8px" }}>Método</th>
                <th style={{ padding: "6px 8px" }}>Endpoint</th>
                <th style={{ padding: "6px 8px" }}>Origem</th>
                <th style={{ padding: "6px 8px" }}>Qualidade</th>
                <th style={{ padding: "6px 8px" }}>Skills</th>
                <th style={{ padding: "6px 8px" }}>BAC</th>
                <th style={{ padding: "6px 8px" }}>HTTP</th>
                <th style={{ padding: "6px 8px" }}>Achados</th>
              </tr>
            </thead>
            <tbody>
              {(data.endpoints || []).map((e, i) => {
                const q = QUALITY[e.quality?.level] || QUALITY.none;
                const open = expanded === i;
                const http = Object.entries(e.http_status_counts || {}).map(([k, v]) => `${k}×${v}`).join(" ");
                const fsev = e.findings_by_severity || {};
                return (
                  <Fragment key={i}>
                    <tr onClick={() => setExpanded(open ? null : i)} style={{ borderBottom: "1px solid var(--border)", cursor: "pointer" }}>
                      <td style={{ padding: "6px 8px", fontWeight: 800 }}>{e.method}</td>
                      <td style={{ padding: "6px 8px", maxWidth: 320, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={e.path}>{e.path}</td>
                      <td style={{ padding: "6px 8px", color: e.source === "crawled" ? "var(--brand, #2563eb)" : "var(--ink-muted)" }}>{e.source === "crawled" ? "crawler" : "spec"}</td>
                      <td style={{ padding: "6px 8px" }}>
                        <span style={{ color: q.color, fontWeight: 800 }}>{q.label}</span>
                        <span style={{ color: "var(--ink-muted)", marginLeft: 5 }}>{e.quality?.score ?? 0}</span>
                      </td>
                      <td style={{ padding: "6px 8px" }}>{e.skills_tested_count}</td>
                      <td style={{ padding: "6px 8px", color: e.bac_tested ? "#16a34a" : "var(--sev-high-text, #dc2626)", fontWeight: 800 }}>{e.bac_tested ? "✓" : "✗"}</td>
                      <td style={{ padding: "6px 8px", color: "var(--ink-muted)" }}>{http || "—"}</td>
                      <td style={{ padding: "6px 8px" }}>
                        {["critical", "high", "medium", "low", "info"].filter((k) => fsev[k]).map((k) => (
                          <span key={k} style={{ color: SEV_COLOR[k], fontWeight: 800, marginRight: 6 }}>{fsev[k]}{k[0].toUpperCase()}</span>
                        )) || "—"}
                        {!e.findings?.length && "—"}
                      </td>
                    </tr>
                    {open && (
                      <tr style={{ background: "var(--surface-2, #f8fafc)" }}>
                        <td colSpan={8} style={{ padding: "8px 14px" }}>
                          <div style={{ fontSize: 11, color: "var(--ink-muted)", marginBottom: 4 }}>URL: {e.url}</div>
                          <div style={{ fontSize: 11, marginBottom: 6 }}>Skills aplicadas: {e.skills_tested?.length ? e.skills_tested.map((x) => x.replace("skill.api.", "")).join(", ") : "nenhuma"}</div>
                          {e.identities?.length > 0 && <div style={{ fontSize: 11, marginBottom: 6 }}>Identidades: {e.identities.join(", ")}</div>}
                          {e.findings?.length > 0 ? (
                            <div>
                              {e.findings.map((f, j) => (
                                <div key={j} style={{ fontSize: 11.5, padding: "3px 0" }}>
                                  <span style={{ color: SEV_COLOR[f.severity], fontWeight: 800 }}>{f.severity}</span>
                                  {f.is_bac && <span style={{ color: "var(--sev-high-text, #dc2626)", fontWeight: 800, marginLeft: 5 }}>BAC</span>}
                                  <span style={{ marginLeft: 6, color: "var(--ink)" }}>{f.title}</span>
                                  {f.owasp && <span style={{ color: "var(--ink-muted)", marginLeft: 5 }}>({f.owasp})</span>}
                                </div>
                              ))}
                            </div>
                          ) : <div style={{ fontSize: 11, color: "var(--ink-muted)" }}>Sem achados neste endpoint.</div>}
                        </td>
                      </tr>
                    )}
                  </Fragment>
                );
              })}
            </tbody>
          </table>
        </div>
        {data.shadow_paths?.length > 0 && (
          <div style={{ marginTop: 10, fontSize: 11, color: "var(--ink-muted)" }} className="sk-mono">
            {data.shadow_paths.length} caminho(s) observados fora da spec/inventário: {data.shadow_paths.slice(0, 10).join(", ")}
          </div>
        )}
      </div>
    </div>
  );
}
