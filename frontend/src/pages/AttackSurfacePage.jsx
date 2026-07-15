import { useEffect, useMemo, useState } from "react";
import client from "../api/client";
import CompanyScopeSelect from "../components/CompanyScopeSelect";
import ScanSelect from "../components/ScanSelect";
import "../styles/dashboard.css";

/* Superfície de ataque — inventário de ativos descobertos (dado REAL de
   /api/dashboard/assets). Classificação por superfície é derivação
   determinística do host/tipo; nada é fabricado. */

const SEV_LABEL = { critical: "Crítico", high: "Alto", medium: "Médio", low: "Baixo", info: "Info" };
const CATEGORIES = ["Aplicações web", "APIs", "Infraestrutura / IPs", "Painéis & consoles", "DNS / certificados"];
const NEW_WINDOW_MS = 7 * 24 * 60 * 60 * 1000;

function classifySurface(host = "", type = "") {
  const h = String(host).toLowerCase().replace(/^[a-z]+:\/\//, "").split("/")[0];
  const t = String(type).toLowerCase();
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(h) || /(ssh|ftp|smtp|database|db)/.test(t)) return "Infraestrutura / IPs";
  if (/(grafana|portainer|jenkins|kibana|zabbix|prometheus|console|painel|admin|dashboard|metabase|portal)/.test(h) || t === "login")
    return "Painéis & consoles";
  if (h.startsWith("api") || h.includes(".api.") || h.includes("api-") || h.includes("-api")) return "APIs";
  if (/(^ns\b|\.ns\.|dns|^mx\b|mail|smtp|cert)/.test(h)) return "DNS / certificados";
  return "Aplicações web";
}

function topSeverity(a) {
  if (Number(a.open_critical || 0) > 0) return "critical";
  if (Number(a.open_high || 0) > 0) return "high";
  if (Number(a.open_medium || 0) > 0) return "medium";
  return null;
}

function fmtDate(value) {
  if (!value) return "—";
  try {
    return new Intl.DateTimeFormat("pt-BR", { day: "2-digit", month: "2-digit", year: "2-digit" }).format(new Date(value));
  } catch {
    return "—";
  }
}

export default function AttackSurfacePage() {
  const [assets, setAssets] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [filter, setFilter] = useState("Todos");
  const [scanId, setScanId] = useState("");
  const [accessGroupId, setAccessGroupId] = useState("");

  useEffect(() => {
    setLoading(true);
    const params = {};
    if (scanId) params.scan_id = scanId;
    if (accessGroupId) params.access_group_id = accessGroupId;
    client
      .get("/api/dashboard/assets", { params })
      .then(({ data }) => setAssets(Array.isArray(data) ? data : []))
      .catch(() => setError("Falha ao carregar a superfície de ataque."))
      .finally(() => setLoading(false));
  }, [scanId, accessGroupId]);

  const enriched = useMemo(() => {
    const now = Date.now();
    return assets.map((a) => {
      const host = a.domain_or_ip || "—";
      const surface = classifySurface(host, a.asset_type);
      const findings = Number(a.open_critical || 0) + Number(a.open_high || 0) + Number(a.open_medium || 0);
      const seenMs = a.last_seen ? new Date(a.last_seen).getTime() : 0;
      return {
        ...a,
        host,
        surface,
        findings,
        sev: topSeverity(a),
        isNew: seenMs > 0 && now - seenMs < NEW_WINDOW_MS,
        isJewel: Number(a.criticality_score || 0) >= 70,
      };
    });
  }, [assets]);

  const groups = useMemo(() => {
    const base = Object.fromEntries(
      CATEGORIES.map((c) => [c, { grupo: c, qtd: 0, expostos: 0, crit: 0, high: 0, novos: 0 }])
    );
    for (const a of enriched) {
      const g = base[a.surface];
      if (!g) continue;
      g.qtd += 1;
      if (String(a.status || "").toLowerCase() === "active") g.expostos += 1;
      g.crit += Number(a.open_critical || 0);
      g.high += Number(a.open_high || 0);
      if (a.isNew) g.novos += 1;
    }
    return CATEGORIES.map((c) => base[c]);
  }, [enriched]);

  const rows = useMemo(() => {
    let r = enriched;
    if (filter === "Novos") r = r.filter((a) => a.isNew);
    else if (filter === "Joias") r = r.filter((a) => a.isJewel);
    else if (filter === "Com achados") r = r.filter((a) => a.findings > 0);
    const sevRank = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    return [...r].sort((a, b) => (sevRank[a.sev] ?? 9) - (sevRank[b.sev] ?? 9) || b.findings - a.findings);
  }, [enriched, filter]);

  if (loading) {
    return (
      <main className="dash"><div className="content" style={{ padding: "32px 40px" }}>
        <div className="dash-state"><div><div className="spin" /><p className="st-title">Carregando superfície…</p></div></div>
      </div></main>
    );
  }
  if (error) {
    return <main className="dash"><div className="content" style={{ padding: "32px 40px" }}><div className="dash-err">{error}</div></div></main>;
  }

  return (
    <main className="dash">
      <div className="content cockpit-shell">
        <section className="cockpit-page-head">
          <div>
            <div className="sk-eyebrow">Superfície de ataque</div>
            <h1>Ativos descobertos</h1>
            <p className="cockpit-sub">{enriched.length} ativos · descoberta contínua</p>
          </div>
          <div className="cockpit-actions">
            <CompanyScopeSelect value={accessGroupId} onChange={(value) => { setAccessGroupId(value); setScanId(""); }} />
            <ScanSelect value={scanId} onChange={setScanId} accessGroupId={accessGroupId} />
          </div>
        </section>

        <section className="surface-counters">
          {groups.map((g) => (
            <div key={g.grupo} className="sk-panel surface-counter">
              <span className="surface-counter-label">{g.grupo}</span>
              <strong className="sk-mono">{g.qtd}</strong>
              <div className="surface-counter-meta">
                {g.novos > 0 && <em className="surface-new">+{g.novos} novos</em>}
                <span>{g.expostos} expostos · {g.crit}C {g.high}A</span>
              </div>
            </div>
          ))}
        </section>

        <section className="surface-filter-strip">
          {["Todos", "Novos", "Joias", "Com achados"].map((f) => (
            <button key={f} className={`surface-chip${filter === f ? " active" : ""}`} onClick={() => setFilter(f)} type="button">
              {f}
            </button>
          ))}
          <span className="surface-count-note">{rows.length} de {enriched.length} ativos</span>
        </section>

        <section className="sk-panel surface-table-panel">
          <div className="attack-table-wrap">
            <table className="attack-table">
              <thead>
                <tr>
                  <th>Ativo</th>
                  <th>Superfície</th>
                  <th>Exposição</th>
                  <th>Visto</th>
                  <th>Achados</th>
                  <th>Severidade</th>
                </tr>
              </thead>
              <tbody>
                {rows.length === 0 && <tr><td colSpan={6}>Nenhum ativo no filtro atual.</td></tr>}
                {rows.map((a) => (
                  <tr key={a.id}>
                    <td>
                      <div className="surface-asset">
                        <b className="sk-mono">{a.host}</b>
                        {a.isNew && <span className="surface-tag new">NOVO</span>}
                        {a.isJewel && <span className="surface-tag jewel">JOIA</span>}
                      </div>
                    </td>
                    <td>{a.surface}</td>
                    <td className="sk-mono">{a.port ? `:${a.port}` : (a.asset_type || "—")}</td>
                    <td className="sk-mono" style={{ color: a.isNew ? "var(--sev-info-text)" : "var(--ink-muted)" }}>{fmtDate(a.last_seen)}</td>
                    <td className="num sk-mono">{a.findings || "—"}</td>
                    <td>
                      {a.sev ? (
                        <span className={`sk-badge sk-badge--${a.sev}`}><span className={`sk-dot sk-dot--${a.sev}`} />{SEV_LABEL[a.sev]}</span>
                      ) : (
                        <span style={{ fontSize: 11, color: "var(--ink-muted)" }}>limpo</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      </div>
    </main>
  );
}
