import { useEffect, useMemo, useState } from "react";
import client from "../api/client";
import CompanyScopeSelect from "../components/CompanyScopeSelect";
import "../styles/app-pages.css";

const NODE_LABELS = {
  internet: "Origem",
  capability: "Capacidade",
  asset: "Ativo",
  data_sink: "Objetivo",
};

const SEVERITY_LABELS = {
  critical: "Crítico",
  high: "Alto",
  medium: "Médio",
  low: "Baixo",
  info: "Info",
};

const TYPE_COLUMNS = {
  internet: 70,
  capability: 330,
  asset: 590,
  data_sink: 850,
};

function sev(value) {
  return String(value || "info").toLowerCase();
}

function shortLabel(value, max = 18) {
  const text = String(value || "-").replace(/\s+/g, " ").trim();
  return text.length > max ? `${text.slice(0, max - 1)}…` : text;
}

function groupLayout(nodes = []) {
  const groups = { internet: [], capability: [], asset: [], data_sink: [] };
  nodes.forEach((node) => {
    const type = groups[node.type] ? node.type : "capability";
    groups[type].push(node);
  });

  const positions = {};
  Object.entries(groups).forEach(([type, list]) => {
    const usable = 470;
    const gap = list.length > 1 ? usable / (list.length - 1) : 0;
    const start = list.length > 1 ? 55 : 240;
    list.slice(0, 16).forEach((node, index) => {
      positions[node.id] = {
        x: TYPE_COLUMNS[type],
        y: start + (gap * index),
      };
    });
  });
  return positions;
}

function linePath(a, b) {
  const mid = Math.max(40, Math.abs(b.x - a.x) * 0.44);
  return `M ${a.x} ${a.y} C ${a.x + mid} ${a.y}, ${b.x - mid} ${b.y}, ${b.x} ${b.y}`;
}

function StatCard({ label, value, hint }) {
  return (
    <div className="kpi">
      <span className="k">{label}</span>
      <span className="v">{value ?? "0"}</span>
      {hint && <span className="hint">{hint}</span>}
    </div>
  );
}

function AttackGraphSvg({ graph, selected, onSelect }) {
  const nodes = Array.isArray(graph?.nodes) ? graph.nodes : [];
  const edges = Array.isArray(graph?.edges) ? graph.edges : [];
  const positions = useMemo(() => groupLayout(nodes), [nodes]);
  const visibleNodeIds = new Set(Object.keys(positions));
  const visibleEdges = edges.filter((edge) => visibleNodeIds.has(edge.source) && visibleNodeIds.has(edge.target));

  if (nodes.length === 0) {
    return (
      <div className="ag-empty">
        Nenhum nó de ataque foi materializado para este scan.
      </div>
    );
  }

  return (
    <svg viewBox="0 0 930 540" className="ag-svg" role="img" aria-label="Grafo real de ataque">
      {Object.entries(TYPE_COLUMNS).map(([type, x]) => (
        <g key={type}>
          <text className="ag-column-label" x={x} y="24">{NODE_LABELS[type]}</text>
          <line className="ag-column-guide" x1={x} y1="42" x2={x} y2="512" />
        </g>
      ))}

      {visibleEdges.map((edge, index) => {
        const a = positions[edge.source];
        const b = positions[edge.target];
        const active = selected?.kind === "edge" && selected?.index === index;
        return (
          <path
            key={`${edge.source}-${edge.target}-${index}`}
            className={`ag-edge ${active ? "active" : ""}`}
            d={linePath(a, b)}
            onClick={() => onSelect({ kind: "edge", index, edge })}
          />
        );
      })}

      {nodes.filter((node) => visibleNodeIds.has(node.id)).map((node) => {
        const pos = positions[node.id];
        const active = selected?.kind === "node" && selected?.node?.id === node.id;
        return (
          <g
            key={node.id}
            className={`ag-node-wrap ${active ? "active" : ""}`}
            transform={`translate(${pos.x} ${pos.y})`}
            onClick={() => onSelect({ kind: "node", node })}
          >
            <circle className={`ag-node ag-node-${node.type || "capability"} ag-sev-${sev(node.severity)}`} r={node.type === "internet" || node.type === "data_sink" ? 27 : 22} />
            <text className="ag-node-label" y="4">{shortLabel(node.label, node.type === "capability" ? 13 : 11)}</text>
          </g>
        );
      })}
    </svg>
  );
}

function DetailPanel({ selected }) {
  if (!selected) {
    return (
      <div className="card ag-detail">
        <div className="s-eb">Detalhe</div>
        <p className="ag-muted">Selecione um nó ou aresta para ver evidência, MITRE e relação de exploração.</p>
      </div>
    );
  }

  if (selected.kind === "edge") {
    const edge = selected.edge || {};
    return (
      <div className="card ag-detail">
        <div className="s-eb">Aresta</div>
        <h3>{edge.type || "relação"}</h3>
        <p>{edge.description || "Relação entre capacidades do caminho de ataque."}</p>
        <dl>
          <dt>Origem</dt><dd>{edge.source}</dd>
          <dt>Destino</dt><dd>{edge.target}</dd>
          <dt>Peso</dt><dd>{edge.weight ?? "-"}</dd>
          <dt>Finding</dt><dd>{edge.finding_id || "sem finding direto"}</dd>
        </dl>
      </div>
    );
  }

  const node = selected.node || {};
  return (
    <div className="card ag-detail">
      <div className="s-eb">Nó</div>
      <h3>{node.label}</h3>
      <p>{node.description || "Nó materializado pelo grafo de ataque."}</p>
      <dl>
        <dt>Tipo</dt><dd>{NODE_LABELS[node.type] || node.type || "-"}</dd>
        <dt>Severidade</dt><dd><span className={`b b-${sev(node.severity)}`}>{SEVERITY_LABELS[sev(node.severity)] || node.severity}</span></dd>
        <dt>Domínio</dt><dd>{node.domain || "-"}</dd>
        <dt>Findings</dt><dd>{Array.isArray(node.finding_ids) && node.finding_ids.length ? node.finding_ids.join(", ") : "-"}</dd>
      </dl>
      {Array.isArray(node.attack_techniques) && node.attack_techniques.length > 0 && (
        <div className="ag-techs">
          {node.attack_techniques.map((tech) => (
            <span key={tech.id}>{tech.id} · {tech.name}</span>
          ))}
        </div>
      )}
    </div>
  );
}

function KillChainList({ chains = [] }) {
  if (!chains.length) {
    return (
      <div className="card-soft ag-empty-small">
        Nenhuma kill chain completa chegou até exfiltração de dados neste scan.
      </div>
    );
  }
  return (
    <div className="stack">
      {chains.slice(0, 8).map((chain) => (
        <article className="card-soft ag-chain" key={chain.chain_id}>
          <div className="ag-chain-head">
            <div>
              <strong>{chain.chain_id}</strong>
              <span>{chain.target_asset || "Dados sensíveis"}</span>
            </div>
            <span className={`b b-${sev(chain.severity)}`}>{SEVERITY_LABELS[sev(chain.severity)] || chain.severity}</span>
          </div>
          <div className="ag-chain-path">
            {(chain.path_labels || []).map((label, index) => (
              <span key={`${chain.chain_id}-${index}`}>{shortLabel(label, 24)}</span>
            ))}
          </div>
          <p>{chain.narrative}</p>
          {Array.isArray(chain.mitigations) && chain.mitigations.length > 0 && (
            <ul className="ag-mitigations">
              {chain.mitigations.slice(0, 3).map((item) => <li key={item}>{item}</li>)}
            </ul>
          )}
        </article>
      ))}
    </div>
  );
}

export default function AttackGraphPage() {
  const [scans, setScans] = useState([]);
  const [selectedScanId, setSelectedScanId] = useState("");
  const [accessGroupId, setAccessGroupId] = useState("");
  const [graph, setGraph] = useState(null);
  const [selected, setSelected] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    client.get("/api/scans", { _skipToast: true })
      .then(({ data }) => {
        const rows = Array.isArray(data) ? data : [];
        setScans(rows);
        if (!selectedScanId && rows.length > 0) {
          setSelectedScanId(String(rows[0].id));
        }
      })
      .catch(() => setScans([]));
  }, []);

  const scopedScans = useMemo(
    () => scans.filter((scan) => !accessGroupId || String(scan.access_group_id || "") === String(accessGroupId)),
    [scans, accessGroupId],
  );

  useEffect(() => {
    if (scopedScans.some((scan) => String(scan.id) === String(selectedScanId))) return;
    setSelectedScanId(scopedScans[0]?.id ? String(scopedScans[0].id) : "");
  }, [scopedScans, selectedScanId]);

  useEffect(() => {
    if (!selectedScanId) {
      setGraph(null);
      setSelected(null);
      return;
    }
    setLoading(true);
    setError("");
    setSelected(null);
    client.get(`/api/scans/${selectedScanId}/attack-graph`)
      .then(({ data }) => setGraph(data || null))
      .catch((err) => {
        setGraph(null);
        setError(err?.response?.data?.detail || "Falha ao carregar grafo de ataque.");
      })
      .finally(() => setLoading(false));
  }, [selectedScanId]);

  const summary = graph?.risk_summary || {};
  const chains = Array.isArray(graph?.kill_chains) ? graph.kill_chains : [];
  const selectedScan = scopedScans.find((scan) => String(scan.id) === String(selectedScanId));

  return (
    <div className="dpage attack-graph-page">
      <div className="page-intro">
        <h2>Attack Graph</h2>
        <div className="sub">caminhos reais de exploração · capacidades · ativos críticos · kill chains</div>
      </div>

      <div className="ag-toolbar card">
        <CompanyScopeSelect value={accessGroupId} onChange={(value) => { setAccessGroupId(value); setSelectedScanId(""); }} style={{ minWidth: 220 }} />
        <label>
          <span>Scan</span>
          <select value={selectedScanId} onChange={(event) => setSelectedScanId(event.target.value)}>
            {scopedScans.map((scan) => (
              <option key={scan.id} value={scan.id}>
                #{scan.id} · {scan.target_query || "sem alvo"} · {scan.status}
              </option>
            ))}
          </select>
        </label>
        <div className="ag-scan-meta">
          <strong>{selectedScan?.target_query || "Nenhum scan selecionado"}</strong>
          <span>{selectedScan?.current_step || selectedScan?.status || "aguardando dados"}</span>
        </div>
      </div>

      {error && <div className="card-soft ag-error">{error}</div>}

      <section className="grid-4 ag-stats">
        <StatCard label="Nós" value={graph?.node_count || 0} hint="capabilities e ativos" />
        <StatCard label="Arestas" value={graph?.edge_count || 0} hint="relações de exploração" />
        <StatCard label="Kill chains" value={graph?.kill_chain_count || 0} hint={`${summary.critical_paths || 0} críticas`} />
        <StatCard label="Menor caminho" value={summary.shortest_path_weight ?? "—"} hint="menor peso = mais fácil" />
      </section>

      <section className="grid-2-1">
        <div className="card ag-visual-card">
          <div className="card-h">
            <div>
              <h3>Grafo de ataque real</h3>
              <div className="sub">renderizado a partir de `/attack-graph`, sem nós fabricados</div>
            </div>
            <div className="meta">
              {loading ? "carregando..." : `${graph?.node_count || 0} nós · ${graph?.edge_count || 0} edges`}
            </div>
          </div>
          <AttackGraphSvg graph={graph} selected={selected} onSelect={setSelected} />
        </div>
        <DetailPanel selected={selected} />
      </section>

      <section className="grid-2-1 ag-bottom">
        <div className="card">
          <div className="card-h">
            <div>
              <h3>Kill chains priorizadas</h3>
              <div className="sub">ordenadas por menor peso de exploração</div>
            </div>
            <div className="meta"><b>{chains.length}</b> caminhos</div>
          </div>
          <KillChainList chains={chains} />
        </div>
        <div className="card">
          <div className="card-h">
            <div>
              <h3>Técnicas MITRE</h3>
              <div className="sub">técnicas mais recorrentes nas cadeias</div>
            </div>
          </div>
          <div className="ag-tech-list">
            {(summary.top_attack_techniques || []).length === 0 ? (
              <span className="ag-muted">Sem técnica ATT&CK associada.</span>
            ) : summary.top_attack_techniques.map((tech) => (
              <span key={tech.id}>{tech.id} · {tech.name} <b>{tech.frequency}</b></span>
            ))}
          </div>
        </div>
      </section>
    </div>
  );
}
