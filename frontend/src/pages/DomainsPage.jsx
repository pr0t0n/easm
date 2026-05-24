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

export default function DomainsPage() {
  const [domains, setDomains] = useState([]);
  const [selectedDomain, setSelectedDomain] = useState("");
  const [selectedSubdomain, setSelectedSubdomain] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    let active = true;
    const load = async () => {
      setLoading(true);
      setError("");
      try {
        const { data } = await client.get("/api/domains/overview");
        if (!active) return;
        const rows = Array.isArray(data) ? data : [];
        setDomains(rows);
        setSelectedDomain((current) => current || rows[0]?.domain || "");
      } catch (err) {
        if (!active) return;
        setError(err?.response?.data?.detail || "Falha ao carregar domínios.");
      } finally {
        if (active) setLoading(false);
      }
    };
    load();
    return () => {
      active = false;
    };
  }, []);

  const domain = useMemo(
    () => domains.find((item) => item.domain === selectedDomain) || domains[0] || null,
    [domains, selectedDomain]
  );

  const subdomains = domain?.subdomains || [];
  const selectedSub = useMemo(() => {
    if (!subdomains.length) return null;
    return subdomains.find((item) => item.name === selectedSubdomain) || subdomains[0];
  }, [subdomains, selectedSubdomain]);

  useEffect(() => {
    setSelectedSubdomain("");
  }, [selectedDomain]);

  const totals = domain?.severity_counts || {};

  return (
    <main className="domains-page">
      {error && <div className="err-box">{error}</div>}

      <section className="domains-layout">
        <aside className="domains-list">
          <div className="domains-list-head">
            <h3>Domínios</h3>
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
              <p className="domain-eyebrow">Superfície por domínio</p>
              <h2>{domain?.domain || "Selecione um domínio"}</h2>
              <div className="domain-hero-meta">
                Scan #{domain?.latest_scan_id || "—"} · {statusLabel(domain?.latest_scan_status)} · {fmtDate(domain?.latest_scan_at)}
              </div>
            </div>
            <div className="domain-total">
              <span>Total</span>
              <strong>{domain?.total_findings || 0}</strong>
            </div>
          </div>

          <div className="domain-kpis">
            <div className="domain-kpi">
              <span>Subdomínios</span>
              <strong>{domain?.subdomain_count || 0}</strong>
            </div>
            <div className="domain-kpi">
              <span>Scans</span>
              <strong>{domain?.scan_count || 0}</strong>
            </div>
            <div className="domain-kpi wide">
              <span>Criticidade consolidada</span>
              <SeverityPills counts={totals} />
            </div>
          </div>

          <div className="subdomain-grid">
            <section className="subdomain-panel">
              <div className="panel-head">
                <h3>Subdomínios</h3>
                <span>{subdomains.length} encontrados</span>
              </div>
              <div className="subdomain-scroll">
                {subdomains.length === 0 && <div className="domain-empty">Sem subdomínios para este domínio.</div>}
                {subdomains.map((item) => (
                  <button
                    key={item.name}
                    type="button"
                    className={`subdomain-row${item.name === selectedSub?.name ? " active" : ""}`}
                    onClick={() => setSelectedSubdomain(item.name)}
                  >
                    <span className="subdomain-name">{item.name}</span>
                    <span className="subdomain-meta">
                      Scan #{item.scan_id || "—"} · {statusLabel(item.scan_status)} · {fmtDate(item.scan_created_at)}
                    </span>
                    <SeverityPills counts={item.severity_counts} />
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
                      <th>Ferramenta</th>
                      <th>CVE/CVSS</th>
                      <th>Status</th>
                    </tr>
                  </thead>
                  <tbody>
                    {!selectedSub?.findings?.length && (
                      <tr>
                        <td colSpan={5} className="domain-empty">Sem vulnerabilidades para este subdomínio.</td>
                      </tr>
                    )}
                    {(selectedSub?.findings || []).map((finding) => (
                      <tr key={`${finding.id}-${finding.scan_id}`}>
                        <td>
                          <strong>{finding.title || "Finding sem título"}</strong>
                          <span>{finding.url || finding.path || "—"}</span>
                        </td>
                        <td><span className={`domain-sev ${String(finding.severity || "info").toLowerCase()}`}>{finding.severity || "info"}</span></td>
                        <td>{finding.tool || "—"}</td>
                        <td>{finding.cve || "—"} {finding.cvss ? `· ${finding.cvss}` : ""}</td>
                        <td>{finding.lifecycle_status || "open"}</td>
                      </tr>
                    ))}
                  </tbody>
                  <tfoot>
                    <tr>
                      <td>Total do subdomínio</td>
                      <td colSpan={4}>{selectedSub?.total_findings || 0} vulnerabilidades</td>
                    </tr>
                  </tfoot>
                </table>
              </div>
            </section>
          </div>
        </section>
      </section>
    </main>
  );
}
