import { useEffect, useMemo, useState } from "react";
import client from "../api/client";
import CompanyScopeSelect from "../components/CompanyScopeSelect";

const STATUS_COLOR = {
  completed:   { bg: "rgba(34,145,96,0.08)",  border: "#1f8a59", text: "#1f8a59"  },
  approved:    { bg: "rgba(34,145,96,0.08)",  border: "#1f8a59", text: "#1f8a59"  },
  running:     { bg: "rgba(254,123,2,0.08)",  border: "#fe7b02", text: "#c25500"  },
  failed:      { bg: "rgba(176,51,51,0.08)",  border: "#b03333", text: "#b03333"  },
  rejected:    { bg: "rgba(176,51,51,0.08)",  border: "#b03333", text: "#b03333"  },
  pending:     { bg: "#fafafa",               border: "#d8cdc4", text: "#6b6b6b"  },
};

function statusStyle(status) {
  return STATUS_COLOR[status] || STATUS_COLOR.pending;
}

function Badge({ label, color }) {
  return (
    <span style={{
      display: "inline-block", padding: "1px 8px", borderRadius: 4,
      fontSize: 11, fontWeight: 600, border: `1px solid ${color}`,
      color, background: "transparent",
    }}>
      {label}
    </span>
  );
}

function ScoreBar({ value }) {
  const pct = Math.min(100, Math.round((value || 0) * 100));
  const color = pct >= 70 ? "#1f8a59" : pct >= 40 ? "#fe7b02" : "#b03333";
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
      <div style={{ flex: 1, height: 4, background: "#f0ebe7", borderRadius: 2, overflow: "hidden" }}>
        <div style={{ width: `${pct}%`, height: "100%", background: color, borderRadius: 2 }} />
      </div>
      <span style={{ fontSize: 11, color, fontWeight: 600, minWidth: 30 }}>{pct}%</span>
    </div>
  );
}

function ActivityCard({ act, index }) {
  const [open, setOpen] = useState(false);
  const s = statusStyle(act.status);
  const approved = act.approved;

  return (
    <div style={{
      background: "#ffffff",
      border: `1px solid ${s.border}`,
      borderLeft: `3px solid ${s.border}`,
      borderRadius: 8,
      marginBottom: 8,
      overflow: "hidden",
      boxShadow: "0 1px 2px rgba(28,28,28,0.04)",
    }}>
      {/* HEADER ROW */}
      <div
        onClick={() => setOpen((v) => !v)}
        style={{ display: "flex", alignItems: "center", gap: 10, padding: "10px 14px", cursor: "pointer", background: s.bg }}
      >
        <span style={{ fontFamily: "IBM Plex Mono, monospace", fontSize: 11, color: "#9a8e83", minWidth: 28 }}>
          #{String(index + 1).padStart(2, "0")}
        </span>
        <span style={{ fontFamily: "IBM Plex Mono, monospace", fontSize: 11, color: "#6b6b6b", minWidth: 26 }}>
          i{act.iteration}
        </span>

        {/* Skill */}
        <span style={{ fontSize: 13, fontWeight: 600, color: "#1c1c1c", flex: 1, minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
          {act.skill_lookup?.skill_name || act.supervisor_demand?.activity_type || "—"}
        </span>

        {/* Tool */}
        {act.tool_selection?.tool_name && (
          <code style={{ fontFamily: "IBM Plex Mono, monospace", fontSize: 11, background: "#f0ebe7", color: "#1c1c1c", padding: "1px 6px", borderRadius: 4 }}>
            {act.tool_selection.tool_name}
          </code>
        )}

        {/* Score */}
        {act.agent_report?.quality_score > 0 && (
          <span style={{ fontSize: 11, color: "#6b6b6b", minWidth: 50 }}>
            score: <strong style={{ color: "#1c1c1c" }}>{act.agent_report.quality_score}</strong>
          </span>
        )}

        {/* Findings */}
        {act.agent_report?.findings_count > 0 && (
          <span style={{
            fontSize: 11, fontWeight: 600, color: "#b03333",
            background: "rgba(176,51,51,0.08)", border: "1px solid #b03333",
            padding: "1px 6px", borderRadius: 4,
          }}>
            {act.agent_report.findings_count} finding{act.agent_report.findings_count !== 1 ? "s" : ""}
          </span>
        )}

        {/* Status + approved */}
        <Badge label={act.status} color={s.text} />
        {approved !== null && approved !== undefined && (
          <Badge
            label={approved ? "✓ aprovado" : "✗ rejeitado"}
            color={approved ? "#1f8a59" : "#b03333"}
          />
        )}

        <span style={{ fontSize: 12, color: "#9a8e83", marginLeft: 4 }}>{open ? "▲" : "▼"}</span>
      </div>

      {/* EXPANDED DETAIL */}
      {open && (
        <div style={{ padding: "12px 14px", borderTop: "1px solid #f0ebe7", display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>

          {/* 1 — Supervisor demand */}
          <Section title="1 · Demanda do Supervisor">
            <Row label="Activity type" value={act.supervisor_demand?.activity_type} />
            <Row label="Skill category" value={act.supervisor_demand?.skill_category} />
            <Row label="Kill chain" value={(act.supervisor_demand?.kill_chain_phases || []).join(", ")} />
            <Row label="Target" value={act.supervisor_demand?.target} mono />
            <Row label="Objetivo" value={act.supervisor_demand?.objective} />
            <Row label="Qualidade esperada" value={act.supervisor_demand?.quality_criteria} />
          </Section>

          {/* 2 — Skill lookup */}
          <Section title="2 · Skill Encontrada">
            <Row label="Skill" value={act.skill_lookup?.skill_name} />
            <Row label="Categoria" value={act.skill_lookup?.skill_category} />
            <Row label="Fonte" value={act.skill_lookup?.source} />
            <Row label="Tools disponíveis" value={act.skill_lookup?.tools_available} />
            {(act.skill_lookup?.top_tools || []).length > 0 && (
              <div style={{ marginTop: 4 }}>
                <span style={labelStyle}>Top tools</span>
                <div style={{ display: "flex", flexWrap: "wrap", gap: 4, marginTop: 2 }}>
                  {act.skill_lookup.top_tools.map((t) => (
                    <span key={t.tool_name} style={chip}>
                      {t.tool_name} <strong style={{ color: "#1c1c1c" }}>{t.score.toFixed(2)}</strong>
                    </span>
                  ))}
                </div>
              </div>
            )}
          </Section>

          {/* 3 — Tool selection */}
          <Section title="3 · Tool Selecionada">
            <Row label="Tool" value={act.tool_selection?.tool_name} mono />
            <div style={{ marginTop: 4 }}>
              <span style={labelStyle}>Score de seleção</span>
              <ScoreBar value={act.tool_selection?.score} />
            </div>
            {act.tool_selection?.usage_guide && (
              <Row label="Guia de uso" value={act.tool_selection.usage_guide} />
            )}
          </Section>

          {/* 4 — Agent report */}
          <Section title="4 · Relatório do Agente">
            <Row label="Operação realizada" value={act.agent_report?.operation_performed} />
            <Row label="Findings" value={act.agent_report?.findings_count} />
            <div style={{ marginTop: 4 }}>
              <span style={labelStyle}>Quality score</span>
              <ScoreBar value={act.agent_report?.quality_score} />
            </div>
            {act.agent_report?.question_to_supervisor && (
              <Row label="Pergunta ao supervisor" value={act.agent_report.question_to_supervisor} />
            )}
            {(act.agent_report?.data_collected || []).length > 0 && (
              <div style={{ marginTop: 4 }}>
                <span style={labelStyle}>Dados coletados (amostra)</span>
                <ul style={{ margin: "4px 0 0 16px", fontSize: 12, color: "#3d3d3d" }}>
                  {act.agent_report.data_collected.map((d, i) => (
                    <li key={i}>{typeof d === "string" ? d : JSON.stringify(d)}</li>
                  ))}
                </ul>
              </div>
            )}
          </Section>

          {/* 5 — Supervisor evaluation */}
          <Section title="5 · Avaliação do Supervisor" style={{ gridColumn: "1 / -1" }}>
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8 }}>
              <Row label="Aprovado" value={act.supervisor_evaluation?.approved === true ? "✓ Sim" : act.supervisor_evaluation?.approved === false ? "✗ Não" : "—"} />
              <Row label="Próxima fase" value={act.supervisor_evaluation?.next_phase} />
              <Row label="Motivo" value={act.supervisor_evaluation?.reason} />
              <Row label="Avaliação qualitativa" value={act.supervisor_evaluation?.quality_assessment} />
            </div>
          </Section>
        </div>
      )}
    </div>
  );
}

function Section({ title, children, style: extraStyle }) {
  return (
    <div style={{ background: "#faf8f4", borderRadius: 6, padding: "10px 12px", ...extraStyle }}>
      <div style={{ fontSize: 10, fontWeight: 700, color: "#9a8e83", textTransform: "uppercase", letterSpacing: "0.07em", marginBottom: 8 }}>
        {title}
      </div>
      {children}
    </div>
  );
}

function Row({ label, value, mono }) {
  if (!value && value !== 0) return null;
  return (
    <div style={{ marginBottom: 4, fontSize: 12 }}>
      <span style={labelStyle}>{label}: </span>
      <span style={{ color: "#1c1c1c", fontFamily: mono ? "IBM Plex Mono, monospace" : undefined }}>
        {String(value)}
      </span>
    </div>
  );
}

const labelStyle = { fontSize: 11, color: "#9a8e83", fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.05em" };
const chip = { display: "inline-block", padding: "1px 6px", background: "#f0ebe7", border: "1px solid #d8cdc4", color: "#3d3d3d", borderRadius: 4, fontSize: 11 };

export default function AgentFlowPage() {
  const [scans, setScans]         = useState([]);
  const [scanId, setScanId]       = useState("");
  const [data, setData]           = useState(null);
  const [loading, setLoading]     = useState(false);
  const [autoRefresh, setAutoRefresh] = useState(false);
  const [filter, setFilter]       = useState("all");
  const [search, setSearch]       = useState("");
  const [accessGroupId, setAccessGroupId] = useState("");

  useEffect(() => {
    client.get("/api/scans").then((r) => {
      setScans(r.data || []);
      if (!scanId && r.data?.length) setScanId(String(r.data[0].id));
    });
  }, []);

  const scopedScans = useMemo(
    () => scans.filter((scan) => !accessGroupId || String(scan.access_group_id || "") === String(accessGroupId)),
    [scans, accessGroupId],
  );

  useEffect(() => {
    if (scopedScans.some((scan) => String(scan.id) === String(scanId))) return;
    setScanId(scopedScans[0]?.id ? String(scopedScans[0].id) : "");
    setData(null);
  }, [scopedScans, scanId]);

  const fetchFlow = async () => {
    if (!scanId) return;
    setLoading(true);
    try {
      const r = await client.get(`/api/agent-flow/scans/${scanId}`);
      setData(r.data);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { fetchFlow(); }, [scanId]);

  useEffect(() => {
    if (!autoRefresh || !scanId) return;
    const t = setInterval(fetchFlow, 5000);
    return () => clearInterval(t);
  }, [autoRefresh, scanId]);

  const activities = (data?.activities || []).filter((a) => {
    if (filter === "approved"  && !a.approved) return false;
    if (filter === "rejected"  && a.approved !== false) return false;
    if (filter === "findings"  && !(a.agent_report?.findings_count > 0)) return false;
    if (search) {
      const q = search.toLowerCase();
      const blob = [
        a.skill_lookup?.skill_name,
        a.tool_selection?.tool_name,
        a.supervisor_demand?.activity_type,
        a.supervisor_demand?.target,
      ].join(" ").toLowerCase();
      if (!blob.includes(q)) return false;
    }
    return true;
  });

  const approved  = (data?.activities || []).filter((a) => a.approved === true).length;
  const rejected  = (data?.activities || []).filter((a) => a.approved === false).length;
  const findings  = (data?.activities || []).reduce((s, a) => s + (a.agent_report?.findings_count || 0), 0);

  return (
    <div className="dpage">
      <div className="page-intro">
        <h2>Fluxo de Agentes.</h2>
        <div className="sub">ciclo completo: supervisor → skill lookup → tool selection → execução → agent report → avaliação</div>
      </div>

      {/* CONTROLS */}
      <div style={{ display: "flex", gap: 10, alignItems: "center", marginBottom: 14, flexWrap: "wrap" }}>
        <CompanyScopeSelect value={accessGroupId} onChange={(value) => { setAccessGroupId(value); setScanId(""); }} style={{ minWidth: 220 }} />
        <select value={scanId} onChange={(e) => setScanId(e.target.value)} style={inputStyle}>
          {scopedScans.map((s) => (
            <option key={s.id} value={s.id}>
              #{s.id} — {String(s.target_query || "").slice(0, 50)} — {s.status}
            </option>
          ))}
        </select>
        <button onClick={fetchFlow} disabled={loading} style={primaryBtn}>
          {loading ? "…" : "Refresh"}
        </button>
        <label style={{ display: "flex", gap: 6, alignItems: "center", fontSize: 13, color: "#3d3d3d" }}>
          <input type="checkbox" checked={autoRefresh} onChange={(e) => setAutoRefresh(e.target.checked)} />
          Auto (5s)
        </label>
        <select value={filter} onChange={(e) => setFilter(e.target.value)} style={inputStyle}>
          <option value="all">Todos os ciclos</option>
          <option value="approved">Aprovados</option>
          <option value="rejected">Rejeitados</option>
          <option value="findings">Com findings</option>
        </select>
        <input
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder="Filtrar por skill, tool, target…"
          style={{ ...inputStyle, minWidth: 220 }}
        />
      </div>

      {/* METRICS */}
      {data && (
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(160px, 1fr))", gap: 8, marginBottom: 16 }}>
          <Metric label="Total de ciclos" value={data.total_activities ?? 0} />
          <Metric label="Aprovados" value={approved} accent="#1f8a59" />
          <Metric label="Rejeitados" value={rejected} accent="#b03333" />
          <Metric label="Findings gerados" value={findings} accent={findings > 0 ? "#b03333" : "#1c1c1c"} />
          <Metric label="Exibindo" value={activities.length} />
        </div>
      )}

      {/* ACTIVITY LIST */}
      {!data && !loading && <div style={{ color: "#6b6b6b", fontSize: 13 }}>Selecione um scan para ver o fluxo de agentes.</div>}
      {loading && <div style={{ color: "#6b6b6b", fontSize: 13 }}>Carregando…</div>}
      {data && activities.length === 0 && (
        <div style={{ color: "#6b6b6b", fontSize: 13 }}>Nenhum ciclo encontrado para o filtro aplicado.</div>
      )}
      {activities.map((act, i) => (
        <ActivityCard key={act.id} act={act} index={i} />
      ))}
    </div>
  );
}

function Metric({ label, value, accent }) {
  return (
    <div style={{ background: "#ffffff", border: "1px solid #e5dcd5", padding: "10px 14px", borderRadius: 8, boxShadow: "0 1px 2px rgba(28,28,28,0.04)" }}>
      <div style={{ fontSize: 10, color: "#6b6b6b", textTransform: "uppercase", letterSpacing: "0.06em" }}>{label}</div>
      <div style={{ fontSize: 20, fontWeight: 700, marginTop: 4, color: accent || "#1c1c1c" }}>{value}</div>
    </div>
  );
}

const inputStyle = {
  background: "#ffffff", color: "#1c1c1c",
  border: "1px solid #e5dcd5", padding: "6px 10px",
  borderRadius: 6, fontSize: 13,
};

const primaryBtn = {
  background: "var(--brand-500)", color: "#ffffff",
  border: "none", padding: "6px 14px",
  borderRadius: 6, cursor: "pointer",
  fontSize: 13, fontWeight: 500,
};
