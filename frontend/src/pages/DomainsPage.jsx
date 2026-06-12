import { useEffect, useMemo, useState } from "react";
import client from "../api/client";
import "../styles/domains.css";

const SEVERITIES = ["critical", "high", "medium", "low", "info"];

const SEVERITY_LABELS = {
  critical: "Crítica",
  high: "Alta",
  medium: "Média",
  low: "Baixa",
  info: "Info",
};

const STATUS_LABELS = {
  queued: "BackLog",
  pending: "BackLog",
  scheduled: "BackLog",
  running: "Executando",
  retrying: "Executando",
  paused: "Pausado",
  completed: "Finalizado",
  finished: "Finalizado",
  failed: "Finalizado",
  stopped: "Finalizado",
  blocked: "Finalizado",
};

function fmtDate(value) {
  if (!value) return "—";
  try {
    return new Intl.DateTimeFormat("pt-BR", {
      dateStyle: "short",
      timeStyle: "short",
    }).format(new Date(value));
  } catch {
    return "—";
  }
}

function statusLabel(value) {
  const key = String(value || "").toLowerCase();
  return STATUS_LABELS[key] || value || "—";
}

function severityCount(counts, severity) {
  return Number(counts?.[severity] || 0);
}

function SeverityPills({ counts }) {
  return (
    <div className="domain-sev-pills">
      {SEVERITIES.map((sev) => (
        <span key={sev} className={`domain-sev ${sev}`}>
          {SEVERITY_LABELS[sev]} <b>{severityCount(counts, sev)}</b>
        </span>
      ))}
    </div>
  );
}

// Small inline badge showing per-subdomain analysis status
const ANALYSIS_BADGE = {
  done:        { label: "✓ Analisado",   color: "#16a34a", bg: "#dcfce7" },
  analyzing:   { label: "⟳ Em análise", color: "#2563eb", bg: "#dbeafe" },
  waiting:     { label: "⌛ Aguardando", color: "#d97706", bg: "#fef3c7" },
  not_started: { label: "○ Não iniciado", color: "#6b7280", bg: "var(--surface-soft)" },
};

function AnalysisStatusBadge({ status }) {
  const cfg = ANALYSIS_BADGE[status] || ANALYSIS_BADGE.not_started;
  return (
    <span style={{
      display: "inline-flex", alignItems: "center",
      padding: "1px 6px", borderRadius: 4, fontSize: 10,
      fontWeight: 600, color: cfg.color, background: cfg.bg,
      flexShrink: 0,
    }}>
      {cfg.label}
    </span>
  );
}

// Scan progress KPI — shows % of subdomains analyzed
function ScanProgressKpi({ domain }) {
  const status = String(domain?.latest_scan_status || "").toLowerCase();
  const isRunning = status === "running" || status === "retrying";
  const total = domain?.subdomain_count ?? 0;
  const analyzed = domain?.analyzed_subdomain_count ?? domain?.scanned_subdomain_count ?? 0;
  const analyzing = domain?.analyzing_subdomain_count ?? 0;
  const waiting = domain?.waiting_subdomain_count ?? 0;
  const notStarted = domain?.not_started_subdomain_count ?? 0;
  const pct = domain?.subdomain_progress_pct ?? (total > 0 ? Math.round(analyzed * 100 / total) : 0);

  const hasData = total > 0 && (analyzed + analyzing + waiting + notStarted) > 0;

  if (!hasData && isRunning) {
    return (
      <>
        <span>Cobertura de subdomínios</span>
        <strong style={{ color: "var(--brand-600, #2563eb)", fontSize: 18 }}>Em andamento</strong>
      </>
    );
  }

  if (!hasData) {
    return (
      <>
        <span>Cobertura de subdomínios</span>
        <strong>—</strong>
      </>
    );
  }

  return (
    <>
      <span>Cobertura de subdomínios</span>
      <strong style={{ fontSize: 22, color: pct === 100 ? "var(--sev-low-text)" : "var(--brand-600, #2563eb)" }}>
        {pct}%
      </strong>
      {/* Progress bar */}
      <div style={{
        marginTop: 8, display: "flex", height: 6, borderRadius: 4, overflow: "hidden", background: "var(--line)",
      }}>
        <div style={{ width: `${pct}%`, background: "#22c55e", transition: "width 0.8s" }} title={`Analisados: ${analyzed}`} />
        <div style={{ width: `${total > 0 ? Math.round(analyzing * 100 / total) : 0}%`, background: "#3b82f6", transition: "width 0.8s" }} title={`Em análise: ${analyzing}`} />
        <div style={{ width: `${total > 0 ? Math.round(waiting * 100 / total) : 0}%`, background: "#f59e0b", transition: "width 0.8s" }} title={`Aguardando: ${waiting}`} />
      </div>
      {/* Legend */}
      <div style={{ marginTop: 6, display: "flex", flexWrap: "wrap", gap: "4px 10px", fontSize: 10.5 }}>
        {analyzed > 0 && (
          <span style={{ color: "#16a34a" }}>✓ {analyzed} analisados</span>
        )}
        {analyzing > 0 && (
          <span style={{ color: "#2563eb" }}>⟳ {analyzing} em análise</span>
        )}
        {waiting > 0 && (
          <span style={{ color: "#d97706" }}>⌛ {waiting} aguardando</span>
        )}
        {notStarted > 0 && (
          <span style={{ color: "var(--ink-muted)" }}>○ {notStarted} não iniciados</span>
        )}
      </div>
    </>
  );
}

// Normalise service name for display
function formatService(service) {
  if (!service) return "—";
  return service
    .replace(/ssl\//i, "SSL/")
    .replace(/^([a-z])/, (m) => m.toUpperCase())
    .replace(/\?$/, "")
    .trim() || "—";
}

// ── Crown jewel label colors ──────────────────────────────────────────────────
const CROWN_LABEL_COLOR = {
  "identity/auth": "#7c3aed",
  "payment/financial": "#b45309",
  "admin_panel": "#dc2626",
  "data_store": "#1d4ed8",
  "cicd": "#0f766e",
  "api_gateway": "#065f46",
  "secrets_mgmt": "#7c3aed",
  "internal_service": "#1e40af",
  "customer_app": "#64748b",
};

function CrownJewelBadge({ label }) {
  const color = CROWN_LABEL_COLOR[label] || "#6b7280";
  return (
    <span title={`Crown Jewel: ${label}`} style={{
      display: "inline-flex", alignItems: "center", gap: 2,
      padding: "1px 5px", borderRadius: 3, fontSize: 9.5,
      fontWeight: 700, color, border: `1px solid ${color}`,
      flexShrink: 0,
    }}>
      ⭐ {label.replace(/_/g, " ")}
    </span>
  );
}

// Aggregate confirmation quality across all findings of a subdomain
function VerificationQualityBar({ findings = [] }) {
  if (!findings.length) return null;
  const confirmed  = findings.filter((f) => f.verification_status === "confirmed").length;
  const candidate  = findings.filter((f) => f.verification_status === "candidate").length;
  const hypothesis = findings.filter((f) => f.verification_status === "hypothesis").length;
  const total = findings.length;
  if (total === 0) return null;
  return (
    <div style={{ marginTop: 6 }}>
      <div style={{ fontSize: 10, color: "var(--ink-muted)", marginBottom: 2 }}>
        qualidade de evidência: {confirmed} confirmados · {candidate} candidatos · {hypothesis} hipóteses
      </div>
      <div style={{ display: "flex", height: 4, borderRadius: 2, overflow: "hidden", background: "var(--line)" }}>
        <div style={{ width: `${(confirmed / total) * 100}%`, background: "#16a34a" }} title={`Confirmados: ${confirmed}`} />
        <div style={{ width: `${(candidate / total) * 100}%`, background: "#f59e0b" }} title={`Candidatos: ${candidate}`} />
        <div style={{ width: `${(hypothesis / total) * 100}%`, background: "#9ca3af" }} title={`Hipóteses: ${hypothesis}`} />
      </div>
    </div>
  );
}

export default function DomainsPage({ embedded = false, scanId = "" }) {
  const [domains, setDomains] = useState([]);
  const [selectedDomain, setSelectedDomain] = useState("");
  const [selectedSubdomain, setSelectedSubdomain] = useState("");
  const [portFilter, setPortFilter] = useState(null); // e.g. "443/tcp"
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [refreshKey, setRefreshKey] = useState(0);
  // New: crown jewels + OSINT per scan
  const [crownJewels, setCrownJewels] = useState([]);
  const [osintData, setOsintData] = useState(null);

  useEffect(() => {
    let active = true;
    const load = async () => {
      setLoading(true);
      setError("");
      try {
        const { data } = await client.get("/api/domains/overview", { params: scanId ? { scan_id: scanId } : {} });
        if (!active) return;
        const rows = Array.isArray(data) ? data : [];
        setDomains(rows);
        setSelectedDomain((current) => {
          const exists = rows.some((r) => r.domain === current);
          return exists ? current : (rows[0]?.domain || "");
        });
      } catch (err) {
        if (!active) return;
        setError(err?.response?.data?.detail || "Falha ao carregar domínios.");
      } finally {
        if (active) setLoading(false);
      }
    };
    load();
    return () => { active = false; };
  }, [refreshKey, scanId]);

  // Load crown jewels + OSINT when domain changes (uses latest scan)
  useEffect(() => {
    const dom = domains.find((d) => d.domain === selectedDomain);
    const scanId = dom?.latest_scan_id;
    if (!scanId) return;
    let active = true;
    client.get(`/api/scans/${scanId}/crown-jewels`).then(({ data }) => {
      if (active) setCrownJewels(Array.isArray(data?.crown_jewels) ? data.crown_jewels : []);
    }).catch(() => {});
    client.get(`/api/scans/${scanId}/osint`, { _skipToast: true }).then(({ data }) => {
      if (active) setOsintData(data?.osint || null);
    }).catch(() => {});
    return () => { active = false; };
  }, [selectedDomain, domains]);

  const domain = useMemo(
    () => domains.find((item) => item.domain === selectedDomain) || domains[0] || null,
    [domains, selectedDomain]
  );

  // When domain changes: clear subdomain + port filter
  useEffect(() => {
    setSelectedSubdomain("");
    setPortFilter(null);
  }, [selectedDomain]);

  const allSubdomains = domain?.subdomains || [];

  // Filter subdomains by port if a port filter is active
  const subdomains = useMemo(() => {
    if (!portFilter) return allSubdomains;
    return allSubdomains.filter((sub) =>
      (sub.ports || []).some(
        (p) => `${p.port}/${p.protocol}` === portFilter
      )
    );
  }, [allSubdomains, portFilter]);

  const selectedSub = useMemo(() => {
    if (!subdomains.length) return null;
    return subdomains.find((item) => item.name === selectedSubdomain) || subdomains[0];
  }, [subdomains, selectedSubdomain]);

  const totals = domain?.severity_counts || {};
  const ports = domain?.ports || [];

  // Map subdomain → crown jewel label
  const crownMap = Object.fromEntries(
    crownJewels.map((cj) => [String(cj.target || "").toLowerCase(), cj.label])
  );

  const Wrapper = embedded ? "div" : "main";
  return (
    <Wrapper className="domains-page">
      {error && <div className="err-box">{error}</div>}

      {!embedded && (
      <section className="domains-page-head">
        <div>
          <p className="domain-eyebrow">Inventário vivo</p>
          <h1>Superfície de ataque</h1>
          <p>
            Domínios, subdomínios, portas, origem da descoberta, joias e findings consolidados por scan.
          </p>
        </div>
        <button
          type="button"
          onClick={() => setRefreshKey((k) => k + 1)}
          title="Recarregar inventário"
        >
          Atualizar inventário
        </button>
      </section>
      )}

      <section className="domains-layout">
        <aside className="domains-list">
          <div className="domains-list-head">
            <h3>Escopos</h3>
            <span>{domains.length} itens</span>
          </div>
          <div className="domains-scroll">
            {loading && <div className="domain-empty">Carregando domínios...</div>}
            {!loading && domains.length === 0 && <div className="domain-empty">Nenhum domínio encontrado.</div>}
            {domains.map((item) => (
              <button
                key={item.domain}
                type="button"
                className={`domain-row${item.domain === domain?.domain ? " active" : ""}`}
                onClick={() => setSelectedDomain(item.domain)}
              >
                <span className="domain-name">{item.domain}</span>
                <span className="domain-meta">
                  #{item.latest_scan_id || "—"} · {item.subdomain_count || 0} subdomínios · {item.total_findings || 0} findings
                </span>
              </button>
            ))}
          </div>
        </aside>

        <section className="domain-detail">
          <div className="domain-hero">
            <div>
              <p className="domain-eyebrow">Superfície por escopo</p>
              <h2>{domain?.domain || "Selecione um domínio"}</h2>
              <div className="domain-hero-meta">
                Scan #{domain?.latest_scan_id || "—"} · {statusLabel(domain?.latest_scan_status)} · {fmtDate(domain?.latest_scan_at)}
              </div>
            </div>
            <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
              <button
                type="button"
                onClick={() => setRefreshKey((k) => k + 1)}
                title="Recarregar dados (após deletar scans)"
                style={{
                  background: "none", border: "1px solid var(--line)", borderRadius: 8,
                  padding: "6px 12px", cursor: "pointer", color: "var(--ink-soft)",
                  fontSize: 12, display: "flex", alignItems: "center", gap: 5,
                }}
              >
                ↻ Atualizar
              </button>
              <div className="domain-total">
                <span>Total</span>
                <strong>{domain?.total_findings || 0}</strong>
              </div>
            </div>
          </div>

          <div className="domain-kpis">
            {/* Row 1: 3 small counters */}
            <div className="domain-kpi">
              <span>Subdomínios</span>
              <strong>{domain?.subdomain_count || 0}</strong>
            </div>
            <div className="domain-kpi">
              <span>Com findings</span>
              <strong style={{ color: "var(--sev-low-text)" }}>{domain?.active_subdomain_count || 0}</strong>
            </div>
            <div className="domain-kpi">
              <span>Sem findings</span>
              <strong style={{ color: "var(--sev-info-text)" }}>{domain?.inactive_subdomain_count || 0}</strong>
            </div>
            {/* Row 2: coverage spans full width */}
            <div className="domain-kpi" style={{ gridColumn: "1 / -1" }}>
              <ScanProgressKpi domain={domain} />
            </div>
            {/* Row 3: severity */}
            <div className="domain-kpi wide">
              <span>Criticidade consolidada</span>
              <SeverityPills counts={totals} />
            </div>
          </div>

          {/* ── OSINT Phase Zero panel ──────────────────────────────────── */}
          {osintData && (
            <div style={{ margin: "12px 0", padding: "14px 18px", background: "var(--canvas-soft)", borderRadius: 10, border: "1px solid var(--line)" }}>
              <div style={{ fontWeight: 700, fontSize: 12, color: "var(--ink)", marginBottom: 10, textTransform: "uppercase", letterSpacing: "0.06em" }}>
                🔍 OSINT Phase Zero
              </div>
              <div style={{ display: "flex", gap: 12, flexWrap: "wrap" }}>
                {/* HIBP */}
                {osintData.hibp && !osintData.hibp.skipped && (
                  <div style={{ flex: 1, minWidth: 140, padding: "8px 12px", background: "#fff", borderRadius: 8, border: `1px solid ${osintData.hibp.emails_breached > 0 ? "#fca5a5" : "var(--line)"}` }}>
                    <div style={{ fontSize: 10.5, color: "var(--ink-muted)", fontWeight: 600 }}>HIBP Breaches</div>
                    <div style={{ fontSize: 22, fontWeight: 700, color: osintData.hibp.emails_breached > 0 ? "#dc2626" : "#16a34a", marginTop: 2 }}>
                      {osintData.hibp.emails_breached || 0}
                    </div>
                    <div style={{ fontSize: 10.5, color: "var(--ink-muted)" }}>emails em vazamentos</div>
                  </div>
                )}
                {/* GitHub dork */}
                {osintData.github_dork && !osintData.github_dork.skipped && (
                  <div style={{ flex: 1, minWidth: 140, padding: "8px 12px", background: "#fff", borderRadius: 8, border: `1px solid ${osintData.github_dork.results_count > 0 ? "#fde68a" : "var(--line)"}` }}>
                    <div style={{ fontSize: 10.5, color: "var(--ink-muted)", fontWeight: 600 }}>GitHub Expostos</div>
                    <div style={{ fontSize: 22, fontWeight: 700, color: osintData.github_dork.results_count > 0 ? "#b45309" : "#16a34a", marginTop: 2 }}>
                      {osintData.github_dork.results_count || 0}
                    </div>
                    <div style={{ fontSize: 10.5, color: "var(--ink-muted)" }}>resultados secrets/env</div>
                  </div>
                )}
                {/* Shodan ASN */}
                {osintData.shodan_asn && !osintData.shodan_asn.skipped && (
                  <div style={{ flex: 1, minWidth: 180, padding: "8px 12px", background: "#fff", borderRadius: 8, border: "1px solid var(--line)" }}>
                    <div style={{ fontSize: 10.5, color: "var(--ink-muted)", fontWeight: 600 }}>Shodan ASN {osintData.shodan_asn.asn}</div>
                    <div style={{ fontSize: 14, fontWeight: 700, color: "var(--brand-700)", marginTop: 2 }}>{osintData.shodan_asn.org || "—"}</div>
                    <div style={{ fontSize: 10.5, color: "var(--ink-muted)" }}>
                      {osintData.shodan_asn.total_hosts_in_asn?.toLocaleString("pt-BR") || 0} IPs no ASN ·{" "}
                      {(osintData.shodan_asn.discovered_ips || []).filter((ip) => ip.vulns?.length > 0).length} com CVEs conhecidos
                    </div>
                  </div>
                )}
                {/* Crown jewels summary */}
                {crownJewels.length > 0 && (
                  <div style={{ flex: 2, minWidth: 200, padding: "8px 12px", background: "#fff", borderRadius: 8, border: "1px solid var(--line)" }}>
                    <div style={{ fontSize: 10.5, color: "var(--ink-muted)", fontWeight: 600, marginBottom: 6 }}>⭐ Crown Jewels ({crownJewels.length})</div>
                    <div style={{ display: "flex", flexWrap: "wrap", gap: 4 }}>
                      {crownJewels.slice(0, 6).map((cj) => (
                        <span key={cj.target} title={cj.target} style={{
                          padding: "2px 6px", borderRadius: 4, fontSize: 10.5, fontWeight: 600,
                          color: CROWN_LABEL_COLOR[cj.label] || "#6b7280",
                          border: `1px solid ${CROWN_LABEL_COLOR[cj.label] || "#6b7280"}20`,
                          background: `${CROWN_LABEL_COLOR[cj.label] || "#6b7280"}08`,
                        }}>
                          {String(cj.target).split(".")[0]}
                        </span>
                      ))}
                      {crownJewels.length > 6 && (
                        <span style={{ fontSize: 10.5, color: "var(--ink-muted)" }}>+{crownJewels.length - 6}</span>
                      )}
                    </div>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* ── Ports table ──────────────────────────────────────────────── */}
          {ports.length > 0 && (
            <div className="domain-ports-section">
              <div className="domain-ports-head">
                <h4>Portas descobertas</h4>
                {portFilter && (
                  <button
                    type="button"
                    className="port-filter-clear"
                    onClick={() => setPortFilter(null)}
                  >
                    ✕ Limpar filtro: {portFilter}
                  </button>
                )}
              </div>
              <div className="domain-ports-table-wrap">
                <table className="domain-ports-table">
                  <thead>
                    <tr>
                      <th>Porta</th>
                      <th>Protocolo</th>
                      <th>Serviço / Aplicação</th>
                      <th>Subdomínios</th>
                    </tr>
                  </thead>
                  <tbody>
                    {ports.map((p) => {
                      const pk = `${p.port}/${p.protocol}`;
                      const isActive = portFilter === pk;
                      return (
                        <tr
                          key={pk}
                          className={`port-row${isActive ? " active" : ""}`}
                          onClick={() => setPortFilter(isActive ? null : pk)}
                          title={`Filtrar subdomínios com porta ${pk}`}
                          style={{ cursor: "pointer" }}
                        >
                          <td>
                            <span className="port-badge">{p.port}</span>
                          </td>
                          <td>
                            <span className={`port-proto proto-${(p.protocol || "tcp").toLowerCase()}`}>
                              {(p.protocol || "tcp").toUpperCase()}
                            </span>
                          </td>
                          <td>{formatService(p.service)}</td>
                          <td>
                            <span className="port-count">{p.subdomain_count}</span>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          <div className="subdomain-grid">
            <section className="subdomain-panel">
              <div className="panel-head">
                <h3>
                  Subdomínios
                  {portFilter && (
                    <span style={{ fontSize: 11, fontWeight: 400, color: "var(--brand-500)", marginLeft: 8 }}>
                      filtrado por porta {portFilter}
                    </span>
                  )}
                </h3>
                <span>{subdomains.length} encontrados</span>
              </div>
              <div className="subdomain-scroll">
                {subdomains.length === 0 && (
                  <div className="domain-empty">
                    {portFilter
                      ? `Nenhum subdomínio com porta ${portFilter}.`
                      : "Sem subdomínios para este domínio."}
                  </div>
                )}
                {subdomains.map((item) => (
                  <button
                    key={item.name}
                    type="button"
                    className={`subdomain-row${item.name === selectedSub?.name ? " active" : ""}`}
                    onClick={() => setSelectedSubdomain(item.name)}
                  >
                    <span className="subdomain-name">{item.name}</span>
                    <span className="subdomain-meta" style={{ display: "flex", alignItems: "center", gap: 6, flexWrap: "wrap" }}>
                      <AnalysisStatusBadge status={item.analysis_status} />
                      {crownMap[String(item.name || "").toLowerCase()] && (
                        <CrownJewelBadge label={crownMap[String(item.name || "").toLowerCase()]} />
                      )}
                      Scan #{item.scan_id || "—"} · {fmtDate(item.scan_created_at)}
                    </span>
                    {/* Show ports in subdomain row when port filter is active */}
                    {(item.ports || []).length > 0 && (
                      <div className="subdomain-ports">
                        {(item.ports || []).slice(0, 6).map((p) => (
                          <span key={`${p.port}/${p.protocol}`} className="subdomain-port-tag">
                            {p.port}/{p.protocol}
                          </span>
                        ))}
                        {(item.ports || []).length > 6 && (
                          <span className="subdomain-port-tag muted">+{(item.ports || []).length - 6}</span>
                        )}
                      </div>
                    )}
                    <SeverityPills counts={item.severity_counts} />
                    <VerificationQualityBar findings={item.findings || []} />
                  </button>
                ))}
              </div>
            </section>

            <section className="findings-panel">
              <div className="panel-head">
                <div>
                  <h3>{selectedSub?.name || "Findings"}</h3>
                  <span>
                    Scan #{selectedSub?.scan_id || "—"} · {fmtDate(selectedSub?.scan_created_at)} · total {selectedSub?.total_findings || 0}
                  </span>
                </div>
              </div>
              <div className="findings-table-wrap">
                <table className="findings-domain-table">
                  <thead>
                    <tr>
                      <th>Vulnerabilidade</th>
                      <th>Criticidade</th>
                      <th>CVE / CVSS</th>
                      <th>Verificação</th>
                      <th>Status</th>
                    </tr>
                  </thead>
                  <tbody>
                    {!selectedSub?.findings?.length && (
                      <tr>
                        <td colSpan={4} className="domain-empty">Sem vulnerabilidades para este subdomínio.</td>
                      </tr>
                    )}
                    {(selectedSub?.findings || []).map((finding) => (
                      <tr key={`${finding.id}-${finding.scan_id}`}>
                        <td>
                          {(finding.vuln_family_label || finding.vuln_family) && (
                            <span style={{ display: "inline-block", fontSize: 9.5, fontWeight: 800, textTransform: "uppercase", letterSpacing: "0.04em", color: "var(--brand-700)", background: "var(--sev-info-bg)", border: "1px solid var(--sev-info-border)", borderRadius: 4, padding: "1px 6px", marginBottom: 3 }}>
                              {finding.vuln_family_label || finding.vuln_family}
                            </span>
                          )}
                          <strong style={{ display: "block" }}>{finding.title || "Finding sem título"}</strong>
                          {(finding.url || finding.path) && (
                            <span style={{ display: "block", fontSize: 11, color: "var(--ink-muted)", wordBreak: "break-all", marginTop: 2 }}>
                              {finding.url || finding.path}
                            </span>
                          )}
                        </td>
                        <td>
                          <span className={`domain-sev ${String(finding.severity || "info").toLowerCase()}`}>
                            {finding.severity || "info"}
                          </span>
                        </td>
                        <td>
                          {finding.cve ? (
                            <>
                              <span style={{ fontWeight: 600, color: "var(--sev-info-text)", fontSize: 12 }}>{finding.cve}</span>
                              {finding.cvss != null && (
                                <span style={{ color: "var(--ink-muted)", fontSize: 11, marginLeft: 4 }}>· {Number(finding.cvss).toFixed(1)}</span>
                              )}
                            </>
                          ) : "—"}
                        </td>
                        <td>
                          {finding.verification_status ? (
                            <span style={{
                              padding: "2px 5px", borderRadius: 3, fontSize: 9.5, fontWeight: 600,
                              color: finding.verification_status === "confirmed" ? "#15803d" : finding.verification_status === "hypothesis" ? "#6b7280" : "#b45309",
                              background: finding.verification_status === "confirmed" ? "#dcfce7" : finding.verification_status === "hypothesis" ? "#f3f4f6" : "#fef3c7",
                            }}>
                              {finding.verification_status === "confirmed" ? "✅" : finding.verification_status === "hypothesis" ? "💭" : "⚠️"} {finding.verification_status}
                            </span>
                          ) : "—"}
                        </td>
                        <td>
                          <span className={`lifecycle-badge ${finding.lifecycle_status || "open"}`}>
                            {finding.lifecycle_status || "open"}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                  <tfoot>
                    <tr>
                      <td>Total do subdomínio</td>
                      <td colSpan={3}>{selectedSub?.total_findings || 0} vulnerabilidades</td>
                    </tr>
                  </tfoot>
                </table>
              </div>
            </section>
          </div>
        </section>
      </section>
    </Wrapper>
  );
}
