import { useEffect, useMemo, useState } from "react";
import client from "../api/client";

const STATUS = {
  partial: { label: "Em construcao", color: "#d4a500", bg: "rgba(212,165,0,.12)" },
  emerging: { label: "Novo modulo", color: "#6aa7ff", bg: "rgba(106,167,255,.12)" },
  ready: { label: "Pronto", color: "#229160", bg: "rgba(34,145,96,.12)" },
};

const CATEGORY_LABELS = {
  all: "Todas",
  agent_execution: "Agentes",
  tooling: "Ferramentas",
  ai_security: "IA/RAG/MCP",
  quality: "Benchmark",
  evidence: "Evidencia",
};

function Metric({ label, value }) {
  return (
    <div style={{
      background: "var(--surface)",
      border: "1px solid var(--line)",
      borderRadius: 10,
      padding: "14px 16px",
      minWidth: 0,
      boxShadow: "var(--shadow-card)",
    }}>
      <div style={{ fontFamily: "var(--font-mono)", fontSize: 25, fontWeight: 800, color: "var(--ink)", lineHeight: 1 }}>{value}</div>
      <div style={{ marginTop: 6, fontSize: 12, color: "var(--ink-muted)" }}>{label}</div>
    </div>
  );
}

function Pill({ children }) {
  return (
    <span style={{
      display: "inline-flex",
      alignItems: "center",
      border: "1px solid var(--line)",
      borderRadius: 999,
      padding: "3px 8px",
      fontSize: 11,
      color: "var(--ink-muted)",
      background: "var(--canvas-soft, var(--canvas))",
      whiteSpace: "nowrap",
    }}>
      {children}
    </span>
  );
}

function StatusBadge({ status }) {
  const meta = STATUS[status] || STATUS.partial;
  return (
    <span style={{
      display: "inline-flex",
      alignItems: "center",
      gap: 7,
      borderRadius: 999,
      padding: "5px 9px",
      fontSize: 11,
      fontWeight: 800,
      textTransform: "uppercase",
      letterSpacing: ".04em",
      color: meta.color,
      background: meta.bg,
      border: `1px solid ${meta.color}`,
      whiteSpace: "nowrap",
    }}>
      <span style={{ width: 7, height: 7, borderRadius: 99, background: meta.color }} />
      {meta.label}
    </span>
  );
}

function CapabilityCard({ item }) {
  return (
    <article style={{
      background: "var(--surface)",
      border: "1px solid var(--line)",
      borderRadius: 10,
      padding: 16,
      boxShadow: "var(--shadow-card)",
      minWidth: 0,
    }}>
      <header style={{ display: "flex", justifyContent: "space-between", gap: 12, alignItems: "flex-start" }}>
        <div style={{ minWidth: 0 }}>
          <div style={{ fontSize: 11, color: "var(--ink-muted)", fontFamily: "var(--font-mono)" }}>
            P{String(item.priority).padStart(2, "0")} · {CATEGORY_LABELS[item.category] || item.category}
          </div>
          <h3 style={{ margin: "4px 0 6px", fontSize: 17, color: "var(--ink)" }}>{item.name}</h3>
          <p style={{ margin: 0, color: "var(--ink-soft)", fontSize: 13, lineHeight: 1.5 }}>{item.product_goal}</p>
        </div>
        <StatusBadge status={item.status} />
      </header>

      <div style={{ marginTop: 12, display: "flex", gap: 6, flexWrap: "wrap" }}>
        {(item.inspired_by || []).map((source) => <Pill key={source}>{source}</Pill>)}
      </div>

      <section style={{ marginTop: 14, display: "grid", gap: 12, gridTemplateColumns: "minmax(0,1fr) minmax(0,1fr)" }}>
        <div>
          <div style={{ fontSize: 11, fontWeight: 800, color: "var(--ink)", textTransform: "uppercase", letterSpacing: ".06em", marginBottom: 6 }}>
            Padrao de execucao
          </div>
          <div style={{ color: "var(--ink-soft)", fontSize: 12.5, lineHeight: 1.5 }}>{item.execution_pattern}</div>
        </div>
        <div>
          <div style={{ fontSize: 11, fontWeight: 800, color: "var(--ink)", textTransform: "uppercase", letterSpacing: ".06em", marginBottom: 6 }}>
            Visibilidade
          </div>
          <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
            {(item.operator_visibility || []).map((label) => <Pill key={label}>{label}</Pill>)}
          </div>
        </div>
      </section>

      <section style={{ marginTop: 14, display: "grid", gap: 12, gridTemplateColumns: "minmax(0,1fr) minmax(0,1fr)" }}>
        <ListBlock title="Proximos passos" items={item.next_steps} />
        <ListBlock title="Gates de aceite" items={item.acceptance_gates} />
      </section>

      <details style={{ marginTop: 12 }}>
        <summary style={{ cursor: "pointer", color: "var(--ink-muted)", fontSize: 12, fontWeight: 700 }}>
          Ancoras no codigo
        </summary>
        <div style={{ marginTop: 8, display: "flex", flexDirection: "column", gap: 4 }}>
          {(item.current_anchors || []).map((anchor) => (
            <code key={anchor} style={{
              fontSize: 11.5,
              color: "var(--ink-muted)",
              background: "var(--canvas-soft, var(--canvas))",
              border: "1px solid var(--line)",
              borderRadius: 6,
              padding: "5px 7px",
              overflowWrap: "anywhere",
            }}>{anchor}</code>
          ))}
        </div>
      </details>
    </article>
  );
}

function ListBlock({ title, items }) {
  return (
    <div>
      <div style={{ fontSize: 11, fontWeight: 800, color: "var(--ink)", textTransform: "uppercase", letterSpacing: ".06em", marginBottom: 6 }}>
        {title}
      </div>
      <ul style={{ margin: 0, paddingLeft: 16, color: "var(--ink-soft)", fontSize: 12.5, lineHeight: 1.55 }}>
        {(items || []).map((item) => <li key={item}>{item}</li>)}
      </ul>
    </div>
  );
}

export default function CapabilityBlueprintPage() {
  const [payload, setPayload] = useState(null);
  const [category, setCategory] = useState("all");
  const [error, setError] = useState("");

  useEffect(() => {
    const params = category === "all" ? "" : `?category=${encodeURIComponent(category)}`;
    client
      .get(`/api/pentest/capability-blueprint${params}`)
      .then(({ data }) => setPayload(data))
      .catch((e) => setError(e?.response?.data?.detail || "Falha ao carregar blueprint de capacidades."));
  }, [category]);

  const capabilities = payload?.capabilities || [];
  const summary = payload?.summary || {};
  const categories = useMemo(() => {
    const keys = Object.keys(summary.by_category || {});
    return ["all", ...keys];
  }, [summary.by_category]);
  const partial = summary.by_status?.partial || 0;
  const emerging = summary.by_status?.emerging || 0;

  return (
    <main className="dpage">
      <section style={{ marginBottom: 18 }}>
        <p style={{ margin: 0, fontSize: 11, fontWeight: 800, letterSpacing: ".08em", textTransform: "uppercase", color: "var(--ink-muted)" }}>
          Estrategia de Produto · Best-of Platforms
        </p>
        <h2 style={{ margin: "4px 0 8px", color: "var(--ink)" }}>Blueprint de Pentest Automatizado</h2>
        <p style={{ margin: 0, color: "var(--ink-soft)", fontSize: 13.5, lineHeight: 1.55, maxWidth: 900 }}>
          {summary.north_star || "Carregando contrato operacional..."}
        </p>
        {summary.non_goal && (
          <p style={{ margin: "8px 0 0", color: "var(--ink-muted)", fontSize: 12.5 }}>
            <b style={{ color: "var(--ink)" }}>Nao objetivo:</b> {summary.non_goal}
          </p>
        )}
      </section>

      {error && (
        <div style={{
          marginBottom: 16,
          padding: "12px 14px",
          borderRadius: 10,
          background: "var(--sev-critical-bg)",
          color: "var(--sev-critical-text)",
          border: "1px solid var(--sev-critical-text)",
          fontSize: 13,
        }}>{error}</div>
      )}

      <section style={{ display: "grid", gridTemplateColumns: "repeat(4, minmax(0, 1fr))", gap: 12, marginBottom: 16 }}>
        <Metric label="capacidades mapeadas" value={summary.total ?? 0} />
        <Metric label="em construcao" value={partial} />
        <Metric label="novos modulos" value={emerging} />
        <Metric label="categorias" value={Object.keys(summary.by_category || {}).length} />
      </section>

      <section style={{ display: "flex", gap: 8, flexWrap: "wrap", marginBottom: 16 }}>
        {categories.map((key) => (
          <button
            key={key}
            onClick={() => setCategory(key)}
            style={{
              border: "1px solid var(--line)",
              borderRadius: 999,
              padding: "7px 11px",
              cursor: "pointer",
              fontSize: 12,
              fontWeight: category === key ? 800 : 600,
              color: category === key ? "#fff" : "var(--ink-muted)",
              background: category === key ? "var(--brand-500)" : "var(--surface)",
            }}
          >
            {CATEGORY_LABELS[key] || key}
          </button>
        ))}
      </section>

      <section style={{ display: "grid", gridTemplateColumns: "minmax(0,1fr)", gap: 14 }}>
        {capabilities.map((item) => <CapabilityCard key={item.id} item={item} />)}
      </section>

      {!payload && !error && (
        <div style={{ padding: 40, textAlign: "center", color: "var(--ink-muted)" }}>Carregando blueprint...</div>
      )}
    </main>
  );
}
