import { useEffect, useMemo, useState } from "react";
import client from "../api/client";
import CompanyScopeSelect from "../components/CompanyScopeSelect";

const STATUS = {
  runtime_active: { label: "Runtime ativo", color: "#229160", bg: "rgba(34,145,96,.12)" },
  roadmap: { label: "Evolucao planejada", color: "#6aa7ff", bg: "rgba(106,167,255,.12)" },
  partial: { label: "Evolucao planejada", color: "#6aa7ff", bg: "rgba(106,167,255,.12)" },
  emerging: { label: "Evolucao planejada", color: "#6aa7ff", bg: "rgba(106,167,255,.12)" },
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

function RuntimeBlock({ title, value, lines }) {
  return (
    <div style={{ border: "1px solid var(--line)", borderRadius: 8, padding: 12, background: "var(--canvas-soft, var(--canvas))", minWidth: 0 }}>
      <div style={{ fontSize: 11, fontWeight: 800, color: "var(--ink-muted)", textTransform: "uppercase", letterSpacing: ".06em" }}>{title}</div>
      <div style={{ marginTop: 5, fontSize: 18, fontWeight: 800, color: "var(--ink)", overflowWrap: "anywhere" }}>{value}</div>
      <div style={{ marginTop: 8, display: "flex", flexDirection: "column", gap: 4 }}>
        {(lines || []).length ? lines.map((line) => (
          <div key={line} style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--ink-muted)", overflowWrap: "anywhere" }}>{line}</div>
        )) : (
          <div style={{ fontSize: 12, color: "var(--ink-muted)" }}>sem dados ainda</div>
        )}
      </div>
    </div>
  );
}

function Timeline({ events = [] }) {
  const rows = events.slice(-18).reverse();
  return (
    <div style={{ display: "grid", gap: 8 }}>
      {rows.length === 0 ? (
        <div style={{ color: "var(--ink-muted)", fontSize: 12 }}>Sem eventos de runtime persistidos.</div>
      ) : rows.map((event, idx) => (
        <div key={`${event.source || "event"}-${event.ts || idx}-${idx}`} style={{
          display: "grid",
          gridTemplateColumns: "110px minmax(0, 1fr)",
          gap: 10,
          border: "1px solid var(--line)",
          borderRadius: 8,
          padding: 10,
          background: "var(--canvas-soft, var(--canvas))",
        }}>
          <div>
            <div style={{ fontSize: 11, fontWeight: 800, color: "var(--ink)", textTransform: "uppercase" }}>
              {event.source || "runtime"}
            </div>
            <div style={{ marginTop: 4, fontSize: 11, color: "var(--ink-muted)", fontFamily: "var(--font-mono)" }}>
              {event.ts ? new Date(event.ts).toLocaleTimeString() : "-"}
            </div>
          </div>
          <div style={{ minWidth: 0 }}>
            <div style={{ fontSize: 12, fontWeight: 800, color: "var(--ink)" }}>
              {event.type || event.status || "evento"}
            </div>
            <div style={{ marginTop: 4, fontSize: 12, color: "var(--ink-soft)", lineHeight: 1.45, overflowWrap: "anywhere" }}>
              {event.message || event.reason || event.decision || event.skill_id || event.node || "-"}
            </div>
            {(event.capability || event.status || event.tools?.length > 0) && (
              <div style={{ display: "flex", gap: 6, flexWrap: "wrap", marginTop: 7 }}>
                {event.capability && <Pill>{event.capability}</Pill>}
                {event.status && <Pill>{event.status}</Pill>}
                {(event.tools || []).slice(0, 3).map((tool) => <Pill key={tool}>{tool}</Pill>)}
              </div>
            )}
          </div>
        </div>
      ))}
    </div>
  );
}

export default function CapabilityBlueprintPage() {
  const [payload, setPayload] = useState(null);
  const [category, setCategory] = useState("all");
  const [scans, setScans] = useState([]);
  const [selectedScan, setSelectedScan] = useState("");
  const [runtime, setRuntime] = useState(null);
  const [error, setError] = useState("");
  const [accessGroupId, setAccessGroupId] = useState("");

  useEffect(() => {
    const params = category === "all" ? "" : `?category=${encodeURIComponent(category)}`;
    client
      .get(`/api/pentest/capability-blueprint${params}`)
      .then(({ data }) => setPayload(data))
      .catch((e) => setError(e?.response?.data?.detail || "Falha ao carregar blueprint de capacidades."));
  }, [category]);

  useEffect(() => {
    client
      .get("/api/scans")
      .then(({ data }) => {
        const rows = Array.isArray(data) ? data : [];
        setScans(rows);
        if (!selectedScan && rows[0]?.id) setSelectedScan(String(rows[0].id));
      })
      .catch(() => {});
  }, []);

  const scopedScans = useMemo(
    () => scans.filter((scan) => !accessGroupId || String(scan.access_group_id || "") === String(accessGroupId)),
    [scans, accessGroupId],
  );

  useEffect(() => {
    if (scopedScans.some((scan) => String(scan.id) === String(selectedScan))) return;
    setSelectedScan(scopedScans[0]?.id ? String(scopedScans[0].id) : "");
    setRuntime(null);
  }, [scopedScans, selectedScan]);

  useEffect(() => {
    if (!selectedScan) return;
    client
      .get(`/api/pentest/scans/${selectedScan}/strategy-runtime`)
      .then(({ data }) => setRuntime(data))
      .catch(() => setRuntime(null));
  }, [selectedScan]);

  const capabilities = payload?.capabilities || [];
  const summary = payload?.summary || {};
  const categories = useMemo(() => {
    const keys = Object.keys(summary.by_category || {});
    return ["all", ...keys];
  }, [summary.by_category]);
  const runtimeActive = summary.by_status?.runtime_active || summary.by_status?.ready || 0;
  const roadmap = (summary.by_status?.roadmap || 0) + (summary.by_status?.partial || 0) + (summary.by_status?.emerging || 0);

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
        <Metric label="runtime ativo" value={runtimeActive} />
        <Metric label="evolucao planejada" value={roadmap} />
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

      <section style={{
        background: "var(--surface)",
        border: "1px solid var(--line)",
        borderRadius: 10,
        padding: 16,
        boxShadow: "var(--shadow-card)",
        marginBottom: 16,
      }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10, justifyContent: "space-between", flexWrap: "wrap" }}>
          <div>
            <div style={{ fontSize: 11, fontWeight: 800, color: "var(--ink-muted)", textTransform: "uppercase", letterSpacing: ".06em" }}>
              Runtime por scan
            </div>
            <h3 style={{ margin: "3px 0 0", color: "var(--ink)", fontSize: 16 }}>Estratégia aplicada na execução</h3>
          </div>
          <div style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "end" }}>
            <CompanyScopeSelect value={accessGroupId} onChange={(value) => { setAccessGroupId(value); setSelectedScan(""); }} style={{ minWidth: 220 }} />
            <select value={selectedScan} onChange={(e) => setSelectedScan(e.target.value)} style={{
              border: "1px solid var(--line)",
              borderRadius: 8,
              padding: "8px 10px",
              background: "var(--surface)",
              color: "var(--ink)",
              minWidth: 260,
            }}>
              {scopedScans.map((scan) => (
                <option key={scan.id} value={String(scan.id)}>
                  #{scan.id} · {String(scan.target_query || "").slice(0, 46)}
                </option>
              ))}
            </select>
          </div>
        </div>

        {runtime ? (
          <div style={{ display: "grid", gridTemplateColumns: "repeat(3, minmax(0, 1fr))", gap: 12, marginTop: 14 }}>
            <RuntimeBlock
              title="Agente atual"
              value={runtime.current?.agent?.name || "Aguardando rota"}
              lines={[
                `capability: ${runtime.current?.capability || "-"}`,
                `skill: ${runtime.current?.selected_skill?.skill_id || runtime.current?.skill_invocation?.skill_id || "-"}`,
                `strategy: ${runtime.strategy?.id || "-"}`,
              ]}
            />
            <RuntimeBlock
              title="LLM reasoning"
              value={`${(runtime.llm_reasoning || []).length} decisão(ões)`}
              lines={(runtime.llm_reasoning || []).slice(-3).map((item) =>
                `${item.phase || "-"} · ${item.skill_id || "-"} · ${item.decision?.execution_decision || item.decision?.notes || "-"}`
              )}
            />
            <RuntimeBlock
              title="MCP adapters"
              value={`${(runtime.mcp_adapter_contracts || []).length} contrato(s)`}
              lines={(runtime.mcp_adapter_contracts || []).slice(-3).map((item) =>
                `${item.capability || "-"} · ${item.skill_id || "-"} · ${(item.tools || []).slice(0, 3).join(", ")}`
              )}
            />
            <RuntimeBlock
              title="Gate de autorização"
              value={runtime.current?.authorization_gate?.approved ? "Aprovado" : runtime.current?.authorization_gate ? "Bloqueado" : "Sem gate"}
              lines={[
                `modo: ${runtime.current?.authorization_gate?.mode || "-"}`,
                `motivo: ${runtime.current?.authorization_gate?.reason || "-"}`,
                `escopo: ${(runtime.current?.authorization_gate?.authorized_scope || []).slice(0, 3).join(", ") || "-"}`,
              ]}
            />
            <RuntimeBlock
              title="Feedback do reasoning"
              value={`${(runtime.llm_reasoning_feedback || []).length} feedback(s)`}
              lines={(runtime.llm_reasoning_feedback || []).slice(-3).map((item) =>
                `${item.status || "-"} · ${item.skill_id || "-"} · findings=${item.findings_added ?? 0}`
              )}
            />
            <div style={{ gridColumn: "span 3" }}>
              <div style={{ fontSize: 11, fontWeight: 800, color: "var(--ink)", textTransform: "uppercase", letterSpacing: ".06em", marginBottom: 8 }}>
                Orquestração multi-agente por fase
              </div>
              <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))", gap: 8 }}>
                {Object.entries(runtime.agent_orchestration || {}).slice(-8).map(([phase, contract]) => (
                  <div key={phase} style={{ border: "1px solid var(--line)", borderRadius: 8, padding: 10, background: "var(--canvas-soft, var(--canvas))" }}>
                    <div style={{ fontFamily: "var(--font-mono)", fontSize: 12, fontWeight: 800, color: "var(--ink)" }}>{phase}</div>
                    <div style={{ marginTop: 4, fontSize: 12, color: "var(--ink-soft)" }}>
                      obrigatórios: {(contract.mandatory_agents || []).length} · tools: {(contract.mandatory_tools || []).slice(0, 4).join(", ") || "-"}
                    </div>
                  </div>
                ))}
              </div>
            </div>
            <div style={{ gridColumn: "span 3" }}>
              <div style={{ fontSize: 11, fontWeight: 800, color: "var(--ink)", textTransform: "uppercase", letterSpacing: ".06em", marginBottom: 8 }}>
                Timeline operacional
              </div>
              <Timeline events={runtime.timeline || []} />
            </div>
          </div>
        ) : (
          <div style={{ marginTop: 12, color: "var(--ink-muted)", fontSize: 13 }}>
            Selecione um scan com estado persistido para ver agentes, LLM e contratos MCP.
          </div>
        )}
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
