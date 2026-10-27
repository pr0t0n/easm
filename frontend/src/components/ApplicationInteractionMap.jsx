import { useMemo, useState } from "react";

const STAGE_ORDER = ["setup", "create", "step", "read", "admin", "delete", "other"];
const STAGE_LABEL = { setup: "Configuração", create: "Criação", step: "Etapas", read: "Leitura", admin: "Admin", delete: "Exclusão", other: "Outros" };
const STAGE_COLOR = { setup: "#8b5cf6", create: "#22c55e", step: "#06b6d4", read: "#3b82f6", admin: "#f97316", delete: "#ef4444", other: "#64748b" };

function shortPath(path, max = 30) {
  const value = String(path || "/");
  return value.length > max ? `${value.slice(0, max - 1)}…` : value;
}

function methodColor(method) {
  return { GET: "#60a5fa", POST: "#4ade80", PUT: "#fbbf24", PATCH: "#f59e0b", DELETE: "#fb7185" }[String(method || "GET").toUpperCase()] || "#cbd5e1";
}

function endpointKey(method, path) {
  return `${String(method || "GET").toUpperCase()} ${String(path || "/")}`;
}

export default function ApplicationInteractionMap({ flow, endpoints = [], variables = [], attackPaths = [] }) {
  const [selectedId, setSelectedId] = useState("");
  const [focusVariable, setFocusVariable] = useState("");
  const [showEdges, setShowEdges] = useState(true);

  const model = useMemo(() => {
    const sourceNodes = Array.isArray(flow?.nodes) ? flow.nodes : [];
    const sourceEdges = Array.isArray(flow?.edges) ? flow.edges : [];
    const nodeLimit = 64;
    const nodes = sourceNodes.slice(0, nodeLimit).map((node) => ({
      ...node,
      stage: STAGE_ORDER.includes(node.stage) ? node.stage : "other",
      id: String(node.id || endpointKey(node.method, node.path)),
    }));
    const nodeIds = new Set(nodes.map((node) => node.id));
    const edges = sourceEdges.filter((edge) => nodeIds.has(String(edge.from)) && nodeIds.has(String(edge.to)));
    const endpointMap = new Map((Array.isArray(endpoints) ? endpoints : []).map((endpoint) => [endpointKey(endpoint.method, endpoint.path), endpoint]));
    const enriched = nodes.map((node) => ({ ...node, endpoint: endpointMap.get(endpointKey(node.method, node.path)) }));
    const byStage = new Map();
    STAGE_ORDER.forEach((stage) => byStage.set(stage, []));
    enriched.forEach((node) => byStage.get(node.stage).push(node));
    const columns = STAGE_ORDER.filter((stage) => byStage.get(stage)?.length).map((stage) => ({ stage, nodes: byStage.get(stage) }));
    const positions = new Map();
    const colWidth = 238;
    const cardWidth = 210;
    const cardHeight = 58;
    columns.forEach((column, columnIndex) => {
      column.nodes.forEach((node, rowIndex) => positions.set(node.id, { x: 22 + columnIndex * colWidth, y: 54 + rowIndex * 76, width: cardWidth, height: cardHeight }));
    });
    const maxRows = Math.max(1, ...columns.map((column) => column.nodes.length));
    const width = Math.max(720, columns.length * colWidth + 28);
    const height = Math.max(430, 54 + maxRows * 76 + 32);
    const variableCounts = new Map();
    edges.forEach((edge) => {
      const variable = String(edge.variable || "").trim();
      if (!variable) return;
      const current = variableCounts.get(variable) || { variable, links: 0, producers: new Set(), consumers: new Set() };
      current.links += 1;
      current.producers.add(String(edge.from));
      current.consumers.add(String(edge.to));
      variableCounts.set(variable, current);
    });
    (Array.isArray(variables) ? variables : []).forEach((item) => {
      const variable = String(item.name || item.variable || "").trim();
      if (!variable) return;
      const current = variableCounts.get(variable) || { variable, links: 0, producers: new Set(), consumers: new Set() };
      current.links += Math.max(1, (item.reused_in || []).length);
      variableCounts.set(variable, current);
    });
    const variableRows = Array.from(variableCounts.values()).map((row) => ({ ...row, producers: row.producers.size, consumers: row.consumers.size })).sort((a, b) => b.links - a.links);
    return { nodes: enriched, edges, columns, positions, width, height, variableRows, totalNodes: sourceNodes.length, totalEdges: sourceEdges.length };
  }, [flow, endpoints, variables]);

  const selected = model.nodes.find((node) => node.id === selectedId) || null;
  const focusedEdges = focusVariable ? model.edges.filter((edge) => String(edge.variable || "") === focusVariable) : model.edges;
  const selectedEndpoint = selected?.endpoint || {};
  const relatedFindings = selectedEndpoint.findings || [];

  return (
    <section style={{ background: "#0b1220", border: "1px solid #26364d", borderRadius: 14, color: "#e5edf7", marginBottom: 18, overflow: "hidden" }}>
      <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", gap: 18, padding: "16px 18px 12px", flexWrap: "wrap" }}>
        <div>
          <div style={{ color: "#7dd3fc", fontFamily: "var(--font-mono)", fontSize: 10, letterSpacing: "0.12em", textTransform: "uppercase" }}>Application Interaction Map</div>
          <h2 style={{ margin: "4px 0 4px", fontSize: 17, color: "#f8fafc" }}>Visão física de interação e variáveis</h2>
          <div style={{ color: "#91a4ba", fontSize: 11.5 }}>Produtores → consumidores, interseções de variáveis e evidência observada por endpoint.</div>
        </div>
        <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
          <span style={{ color: "#9fb0c5", fontFamily: "var(--font-mono)", fontSize: 10 }}>{model.totalNodes} nós · {model.totalEdges} dependências</span>
          <button type="button" onClick={() => setShowEdges((value) => !value)} style={{ background: "#111d2d", border: "1px solid #31445c", borderRadius: 7, color: "#d6e3f1", cursor: "pointer", fontSize: 10.5, padding: "5px 8px" }}>{showEdges ? "Ocultar relações" : "Mostrar relações"}</button>
        </div>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "minmax(0, 1fr) 260px", gap: 0, borderTop: "1px solid #1e3047" }}>
        <div style={{ minWidth: 0, overflowX: "auto", padding: "12px 14px 18px" }}>
          <div style={{ minWidth: model.width, position: "relative" }}>
            <svg width={model.width} height={model.height} viewBox={`0 0 ${model.width} ${model.height}`} role="img" aria-label="Mapa de interação entre endpoints">
              <defs>
                <marker id="api-map-arrow" markerWidth="7" markerHeight="7" refX="6" refY="3.5" orient="auto"><path d="M0,0 L7,3.5 L0,7 z" fill="#6383a7" /></marker>
                <marker id="api-map-arrow-focus" markerWidth="7" markerHeight="7" refX="6" refY="3.5" orient="auto"><path d="M0,0 L7,3.5 L0,7 z" fill="#fbbf24" /></marker>
              </defs>
              {model.columns.map((column, columnIndex) => <g key={column.stage}>
                <text x={22 + columnIndex * 238} y="20" fill={STAGE_COLOR[column.stage]} fontSize="10" fontWeight="700" letterSpacing="1">{STAGE_LABEL[column.stage].toUpperCase()}</text>
                <line x1={22 + columnIndex * 238} y1="28" x2={22 + columnIndex * 238 + 210} y2="28" stroke="#23344a" />
              </g>)}
              {showEdges && focusedEdges.map((edge, index) => {
                const from = model.positions.get(String(edge.from));
                const to = model.positions.get(String(edge.to));
                if (!from || !to) return null;
                const active = !focusVariable || String(edge.variable || "") === focusVariable;
                const x1 = from.x + from.width;
                const y1 = from.y + from.height / 2;
                const x2 = to.x;
                const y2 = to.y + to.height / 2;
                const mx = (x1 + x2) / 2;
                return <g key={`${edge.from}-${edge.to}-${edge.variable}-${index}`} opacity={active ? 0.9 : 0.12}>
                  <path d={`M ${x1} ${y1} C ${mx} ${y1}, ${mx} ${y2}, ${x2} ${y2}`} fill="none" stroke={active && focusVariable ? "#fbbf24" : "#557495"} strokeWidth={active && focusVariable ? 2.2 : 1.2} markerEnd={`url(#${active && focusVariable ? "api-map-arrow-focus" : "api-map-arrow"})`} />
                  {active && <text x={mx} y={(y1 + y2) / 2 - 3} textAnchor="middle" fill={focusVariable ? "#fde68a" : "#88a4c4"} fontSize="9" fontFamily="var(--font-mono)">{edge.variable || "relação"}</text>}
                </g>;
              })}
              {model.nodes.map((node) => {
                const pos = model.positions.get(node.id);
                if (!pos) return null;
                const isSelected = node.id === selectedId;
                const nodeVars = [...(node.consumes || []), ...(node.produces || [])];
                const isFocused = focusVariable && nodeVars.includes(focusVariable);
                return <g key={node.id} transform={`translate(${pos.x},${pos.y})`} onClick={() => setSelectedId(node.id)} style={{ cursor: "pointer" }} opacity={focusVariable && !isFocused ? 0.35 : 1}>
                  <rect width={pos.width} height={pos.height} rx="8" fill={isSelected ? "#162b45" : "#101d2e"} stroke={isSelected || isFocused ? "#fbbf24" : "#2f4662"} strokeWidth={isSelected ? 2 : 1} />
                  <rect width="4" height={pos.height} rx="2" fill={STAGE_COLOR[node.stage]} />
                  <text x="13" y="17" fill={methodColor(node.method)} fontSize="9" fontWeight="800">{String(node.method || "GET").toUpperCase()}</text>
                  <text x="48" y="17" fill="#e5edf7" fontSize="10" fontFamily="var(--font-mono)">{shortPath(node.path, 26)}</text>
                  <text x="13" y="34" fill="#91a4ba" fontSize="9.5">{(node.consumes || []).length ? `← ${(node.consumes || []).slice(0, 3).join(", ")}` : "sem entrada de variável"}</text>
                  <text x="13" y="48" fill={(node.produces || []).length ? "#86efac" : "#71849a"} fontSize="9.5">{(node.produces || []).length ? `→ ${(node.produces || []).slice(0, 3).join(", ")}` : "sem saída de variável"}</text>
                </g>;
              })}
            </svg>
          </div>
        </div>

        <aside style={{ borderLeft: "1px solid #1e3047", padding: 14, minWidth: 0 }}>
          <div style={{ color: "#f8fafc", fontSize: 11, fontWeight: 800, marginBottom: 8 }}>Interseções de variáveis</div>
          <div style={{ display: "grid", gap: 5, maxHeight: 220, overflowY: "auto" }}>
            {model.variableRows.slice(0, 18).map((row) => <button key={row.variable} type="button" onClick={() => setFocusVariable((value) => value === row.variable ? "" : row.variable)} style={{ background: focusVariable === row.variable ? "#3a2b0a" : "#101d2e", border: `1px solid ${focusVariable === row.variable ? "#fbbf24" : "#2f4662"}`, borderRadius: 7, color: "#d9e7f5", cursor: "pointer", display: "flex", justifyContent: "space-between", padding: "6px 8px", textAlign: "left", width: "100%" }}><span style={{ fontFamily: "var(--font-mono)", fontSize: 10 }}>{row.variable}</span><span style={{ color: "#fbbf24", fontFamily: "var(--font-mono)", fontSize: 9 }}>{row.links}×</span></button>)}
            {!model.variableRows.length && <div style={{ color: "#8295ab", fontSize: 10 }}>Nenhuma variável compartilhada derivada do contrato.</div>}
          </div>
          {selected && <div style={{ borderTop: "1px solid #1e3047", marginTop: 12, paddingTop: 11 }}>
            <div style={{ color: "#f8fafc", fontFamily: "var(--font-mono)", fontSize: 10.5, fontWeight: 800 }}>{selected.method} {selected.path}</div>
            <div style={{ color: "#91a4ba", fontSize: 10, marginTop: 5 }}>estágio: {STAGE_LABEL[selected.stage]} · {selected.documented ? "na spec" : "descoberto"}</div>
            <div style={{ color: "#91a4ba", fontSize: 10, marginTop: 5 }}>consome: {(selected.consumes || []).join(", ") || "—"}</div>
            <div style={{ color: "#86efac", fontSize: 10, marginTop: 3 }}>produz: {(selected.produces || []).join(", ") || "—"}</div>
            <div style={{ color: "#91a4ba", fontSize: 10, marginTop: 7 }}>HTTP: {Object.entries(selectedEndpoint.http_status_counts || {}).map(([status, count]) => `${status}×${count}`).join(" ") || "sem observação"}</div>
            <div style={{ color: relatedFindings.length ? "#fca5a5" : "#91a4ba", fontSize: 10, marginTop: 3 }}>{relatedFindings.length ? `${relatedFindings.length} achado(s) associado(s)` : "sem achado associado"}</div>
          </div>}
          <div style={{ borderTop: "1px solid #1e3047", marginTop: 12, paddingTop: 11 }}>
            <div style={{ color: "#f8fafc", fontSize: 11, fontWeight: 800, marginBottom: 6 }}>Legenda operacional</div>
            {STAGE_ORDER.filter((stage) => model.columns.some((column) => column.stage === stage)).map((stage) => <div key={stage} style={{ alignItems: "center", color: "#91a4ba", display: "flex", fontSize: 10, gap: 7, margin: "4px 0" }}><span style={{ background: STAGE_COLOR[stage], borderRadius: 3, height: 8, width: 8 }} />{STAGE_LABEL[stage]}</div>)}
            <div style={{ color: "#8295ab", fontSize: 9.5, lineHeight: 1.45, marginTop: 8 }}>Clique em um nó para inspecionar o comportamento observado. Clique em uma variável para isolar sua interseção no fluxo.</div>
          </div>
        </aside>
      </div>
    </section>
  );
}
