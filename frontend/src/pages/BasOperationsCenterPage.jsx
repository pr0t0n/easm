import { useEffect, useState, useCallback } from "react";
import client from "../api/client";

const TV = {
  bg: "#1f242c", surface: "#262c36", surface2: "#2d343f",
  border: "#2f3743", text: "#e8eaed", muted: "#8a93a3", label: "#6b7384",
};

function TvPanel({ title, right, children, span, style }) {
  return (
    <div style={{
      background: TV.surface, borderRadius: 12,
      border: `1px solid ${TV.border}`, padding: "13px 16px",
      gridColumn: span ? `span ${span}` : undefined,
      minWidth: 0, ...style,
    }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline", marginBottom: 10 }}>
        <span style={{ fontSize: 12, fontWeight: 700, color: TV.text }}>{title}</span>
        {right && <span style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: TV.muted }}>{right}</span>}
      </div>
      {children}
    </div>
  );
}

function KpiTile({ label, value, accent, hint }) {
  return (
    <div style={{ background: TV.surface, borderRadius: 12, border: `1px solid ${TV.border}`, padding: "14px 16px" }}>
      <div style={{ fontSize: 10.5, color: TV.muted, textTransform: "uppercase", letterSpacing: "0.06em" }}>{label}</div>
      <div style={{ fontFamily: "var(--font-mono)", fontSize: 26, fontWeight: 700, color: accent || TV.text, marginTop: 4 }}>{value}</div>
      {hint && <div style={{ fontSize: 9.5, color: TV.muted, marginTop: 2 }}>{hint}</div>}
    </div>
  );
}

const STATUS_COLOR = { online: "#7fe0b0", offline: "#8a93a3", pending: "#d4a500", revoked: "#e96363" };

export default function BasOperationsCenterPage() {
  const [summary, setSummary] = useState(null);
  const [center, setCenter] = useState(null);

  const load = useCallback(async () => {
    try {
      const [{ data: s }, { data: c }] = await Promise.all([
        client.get("/api/bas/dashboard/summary"),
        client.get("/api/bas/operations-center"),
      ]);
      setSummary(s);
      setCenter(c);
    } catch {
      /* silent -- next auto-refresh retries */
    }
  }, []);

  useEffect(() => {
    load();
    const id = setInterval(load, 15000);
    return () => clearInterval(id);
  }, [load]);

  const agents = center?.agents || [];
  const jobs = center?.recent_jobs || [];
  const techniqueStats = center?.technique_stats || {};
  const frameworkCoverage = center?.framework_coverage || {};
  const exposure = center?.exposure || {};
  const findings = center?.findings || [];
  const crownJewels = center?.crown_jewels || [];
  const heatmap = center?.attack_heatmap || [];
  const chainPaths = center?.chain_attack_paths || [];
  const riskScore = center?.risk_score || {};
  const scoreValue = riskScore.score;
  const scoreColor = scoreValue == null ? TV.muted : scoreValue >= 60 ? "#e96363" : scoreValue >= 30 ? "#d4a500" : "#7fe0b0";

  return (
    <div style={{ background: TV.bg, minHeight: "100%", padding: 20, borderRadius: 12 }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline", marginBottom: 16 }}>
        <div>
          <div style={{ fontSize: 15, fontWeight: 700, color: TV.text }}>Centro Operacional BAS</div>
          <div style={{ fontSize: 11, color: TV.muted }}>Breach &amp; Attack Simulation — agentes, técnicas e jobs</div>
        </div>
      </div>

      {summary && (
        <div style={{ display: "grid", gridTemplateColumns: "repeat(6, 1fr)", gap: 12, marginBottom: 16 }}>
          <KpiTile
            label="risk score"
            value={scoreValue == null ? "—" : scoreValue}
            accent={scoreColor}
            hint={scoreValue == null ? "sem jobs resolvidos" : `${riskScore.worked} ok · ${riskScore.blocked} bloq.`}
          />
          <KpiTile label="agentes online" value={summary.agents_online} accent="#7fe0b0" />
          <KpiTile label="agentes offline" value={summary.agents_offline} accent="#8a93a3" />
          <KpiTile label="agentes pendentes" value={summary.agents_pending} accent="#d4a500" />
          <KpiTile label="agendamentos ativos" value={summary.schedules_active} />
          <KpiTile label="jobs hoje" value={summary.jobs_today} />
        </div>
      )}

      <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 12 }}>
        <TvPanel title="Agentes" right={`${agents.length}`}>
          <div style={{ display: "grid", gap: 8 }}>
            {agents.length === 0 && <div style={{ fontSize: 11, color: TV.muted }}>Nenhum agente enrolado.</div>}
            {agents.map((a) => (
              <div key={a.id} style={{ display: "flex", justifyContent: "space-between", alignItems: "center", background: TV.surface2, borderRadius: 8, padding: "8px 10px" }}>
                <div>
                  <div style={{ fontSize: 12, color: TV.text, fontWeight: 600 }}>
                    {a.label || a.os || `agente #${a.id}`}
                    <span style={{ marginLeft: 6, fontSize: 9, fontWeight: 700, color: a.kind === "real" ? "#7fe0b0" : "#d4a500" }}>
                      {a.kind === "real" ? "REAL" : "STUB"}
                    </span>
                  </div>
                  <div style={{ fontSize: 10, color: TV.muted }}>heartbeat: {a.last_heartbeat_at || "—"}</div>
                </div>
                <span style={{ fontSize: 10, fontWeight: 700, color: STATUS_COLOR[a.status] || TV.muted }}>{a.status}</span>
              </div>
            ))}
          </div>
        </TvPanel>

        <TvPanel title="Técnicas por status" right={`${Object.keys(techniqueStats).length} catalogada(s)`} span={2}>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(200px, 1fr))", gap: 8, maxHeight: 320, overflowY: "auto" }}>
            {Object.keys(techniqueStats).length === 0 && <div style={{ fontSize: 11, color: TV.muted }}>Nenhuma técnica catalogada.</div>}
            {Object.entries(techniqueStats)
              .sort(([, a], [, b]) => (b.completed + b.failed + b.skipped + b.other) - (a.completed + a.failed + a.skipped + a.other))
              .map(([key, counts]) => (
              <div key={key} style={{ background: TV.surface2, borderRadius: 8, padding: "8px 10px" }}>
                <div style={{ fontSize: 11, color: TV.text, fontWeight: 600, marginBottom: 2 }}>{counts.display_name || key}</div>
                <div style={{ fontSize: 9.5, color: TV.label, textTransform: "uppercase", letterSpacing: "0.04em", marginBottom: 4 }}>{counts.category || "—"}</div>
                <div style={{ display: "flex", gap: 8, fontSize: 10, color: TV.muted }}>
                  <span style={{ color: "#7fe0b0" }}>ok {counts.completed || 0}</span>
                  <span style={{ color: "#e96363" }}>falha {counts.failed || 0}</span>
                  <span>pulado {counts.skipped || 0}</span>
                </div>
              </div>
            ))}
          </div>
        </TvPanel>

        <TvPanel title="Jobs recentes" right="últimos 10" span={3}>
          <div style={{ display: "grid", gap: 6 }}>
            {jobs.length === 0 && <div style={{ fontSize: 11, color: TV.muted }}>Nenhum job disparado ainda.</div>}
            {jobs.map((j) => (
              <div key={j.id} style={{ display: "flex", justifyContent: "space-between", alignItems: "center", background: TV.surface2, borderRadius: 8, padding: "7px 10px" }}>
                <div style={{ fontSize: 11, color: TV.text }}>
                  #{j.id} · {j.technique_key} <span style={{ color: TV.muted }}>({j.risk_tier})</span>
                </div>
                <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                  {j.simulated ? (
                    <span style={{ fontSize: 9.5, fontWeight: 700, color: "#d4a500", border: "1px solid rgba(212,165,0,0.4)", borderRadius: 4, padding: "1px 5px" }}>SIMULADO</span>
                  ) : (
                    <span style={{ fontSize: 9.5, fontWeight: 700, color: "#7fe0b0", border: "1px solid rgba(127,224,176,0.4)", borderRadius: 4, padding: "1px 5px" }}>REAL</span>
                  )}
                  <span style={{ fontSize: 10, color: j.status === "completed" ? "#7fe0b0" : j.status === "failed" ? "#e96363" : TV.muted }}>{j.status}</span>
                </div>
              </div>
            ))}
          </div>
        </TvPanel>

        <TvPanel title="Riscos por framework" right="cobertura de técnicas testadas">
          <div style={{ display: "grid", gap: 8 }}>
            {Object.keys(frameworkCoverage).length === 0 && <div style={{ fontSize: 11, color: TV.muted }}>Sem dados ainda.</div>}
            {Object.entries(frameworkCoverage).map(([key, fw]) => (
              <div key={key}>
                <div style={{ display: "flex", justifyContent: "space-between", fontSize: 11, color: TV.text, marginBottom: 3 }}>
                  <span>{fw.label}</span>
                  <span style={{ color: TV.muted }}>{fw.tested}/{fw.total} técnicas</span>
                </div>
                <div style={{ height: 6, borderRadius: 3, background: TV.surface2, overflow: "hidden" }}>
                  <div style={{ height: "100%", width: `${fw.coverage_pct}%`, background: fw.coverage_pct >= 50 ? "#7fe0b0" : fw.coverage_pct > 0 ? "#d4a500" : TV.border }} />
                </div>
              </div>
            ))}
          </div>
        </TvPanel>

        <TvPanel title="Exposição" right="atividade real do túnel">
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10 }}>
            <div><div style={{ fontSize: 22, fontWeight: 700, color: TV.text }}>{exposure.distinct_targets_tested ?? 0}</div><div style={{ fontSize: 10, color: TV.muted }}>alvos internos testados</div></div>
            <div><div style={{ fontSize: 22, fontWeight: 700, color: "#7fe0b0" }}>{exposure.real_tunnel_roundtrips ?? 0}</div><div style={{ fontSize: 10, color: TV.muted }}>round-trips reais no túnel</div></div>
            <div><div style={{ fontSize: 22, fontWeight: 700, color: TV.text }}>{exposure.total_dispatches ?? 0}</div><div style={{ fontSize: 10, color: TV.muted }}>disparos totais</div></div>
            <div><div style={{ fontSize: 22, fontWeight: 700, color: "#e96363" }}>{exposure.failed_dispatches ?? 0}</div><div style={{ fontSize: 10, color: TV.muted }}>falhas de disparo</div></div>
          </div>
          <div style={{ fontSize: 10, color: TV.muted, marginTop: 10 }}>categorias testadas: {(exposure.categories_tested || []).join(", ") || "—"}</div>
        </TvPanel>

        <TvPanel title="Joias da Coroa" right={`${crownJewels.length} alvo(s) de alto valor`}>
          <div style={{ display: "grid", gap: 6 }}>
            {crownJewels.length === 0 && <div style={{ fontSize: 11, color: TV.muted }}>Nenhum alvo com sinal de alto valor ainda.</div>}
            {crownJewels.map((jewel) => (
              <div key={jewel.target} style={{ display: "flex", justifyContent: "space-between", background: TV.surface2, borderRadius: 8, padding: "7px 10px" }}>
                <div>
                  <div style={{ fontSize: 11, color: TV.text, fontWeight: 600 }}>{jewel.target}</div>
                  <div style={{ fontSize: 9.5, color: TV.muted }}>{jewel.label}</div>
                </div>
                <div style={{ fontSize: 10, color: TV.muted, alignSelf: "center" }}>{jewel.jobs_run} job(s)</div>
              </div>
            ))}
          </div>
        </TvPanel>

        <TvPanel title="Vulnerabilidades (BAS)" right={`${findings.length} · real ou simulado por agente`} span={2}>
          <div style={{ display: "grid", gap: 6, maxHeight: 220, overflowY: "auto" }}>
            {findings.length === 0 && <div style={{ fontSize: 11, color: TV.muted }}>Nenhuma finding do BAS ainda.</div>}
            {findings.map((f) => (
              <div key={f.id} style={{ display: "flex", justifyContent: "space-between", alignItems: "center", background: TV.surface2, borderRadius: 8, padding: "7px 10px" }}>
                <div style={{ fontSize: 11, color: TV.text }}>{f.title}</div>
                {f.simulated ? (
                  <span style={{ fontSize: 9.5, fontWeight: 700, color: "#d4a500", border: "1px solid rgba(212,165,0,0.4)", borderRadius: 4, padding: "1px 5px" }}>SIMULADO</span>
                ) : (
                  <span style={{ fontSize: 9.5, fontWeight: 700, color: "#7fe0b0", border: "1px solid rgba(127,224,176,0.4)", borderRadius: 4, padding: "1px 5px" }}>REAL</span>
                )}
              </div>
            ))}
          </div>
        </TvPanel>

        <TvPanel title="Attack Heat Map (MITRE ATT&CK)" right={`${heatmap.length} técnica(s) catalogada(s)`} span={3}>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(160px, 1fr))", gap: 8 }}>
            {heatmap.map((row) => {
              const intensity = row.times_tested === 0 ? 0 : Math.min(1, 0.25 + row.times_tested * 0.15);
              const bg = row.availability === "future_agent_required"
                ? "rgba(233,99,99,0.08)"
                : row.times_tested === 0 ? TV.surface2 : `rgba(127,224,176,${intensity.toFixed(2)})`;
              return (
                <div key={`${row.mitre_id}-${row.technique_key}`} style={{ background: bg, borderRadius: 8, padding: "8px 10px", border: `1px solid ${TV.border}` }}>
                  <div style={{ fontFamily: "var(--font-mono)", fontSize: 11, fontWeight: 700, color: TV.text }}>{row.mitre_id}</div>
                  <div style={{ fontSize: 9.5, color: TV.muted, marginTop: 2 }}>{row.display_name}</div>
                  <div style={{ fontSize: 9.5, color: TV.muted, marginTop: 4 }}>
                    {row.availability === "future_agent_required" ? "requer agente real" : `testada ${row.times_tested}x`}
                  </div>
                </div>
              );
            })}
          </div>
        </TvPanel>

        <TvPanel title="Attack Path (chains)" right={`${chainPaths.length} chain(s) disparada(s)`} span={3}>
          <div style={{ display: "grid", gap: 10 }}>
            {chainPaths.length === 0 && <div style={{ fontSize: 11, color: TV.muted }}>Nenhuma chain disparada ainda.</div>}
            {chainPaths.map((path) => (
              <div key={path.scan_job_id} style={{ background: TV.surface2, borderRadius: 8, padding: "9px 12px" }}>
                <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 6 }}>
                  <span style={{ fontSize: 11.5, fontWeight: 700, color: TV.text }}>{path.chain_display_name}</span>
                  <span style={{ fontSize: 9.5, fontWeight: 700, color: path.simulated ? "#d4a500" : "#7fe0b0" }}>
                    {path.simulated ? "SIMULADO" : "REAL"}
                  </span>
                </div>
                <div style={{ display: "flex", alignItems: "center", gap: 5, flexWrap: "wrap" }}>
                  {path.steps.map((step, i) => (
                    <span key={step.technique_key + i} style={{ display: "flex", alignItems: "center", gap: 5 }}>
                      <span style={{
                        fontSize: 10, padding: "3px 7px", borderRadius: 6,
                        color: step.status === "completed" ? "#7fe0b0" : step.status === "failed" ? "#e96363" : TV.muted,
                        border: `1px solid ${TV.border}`,
                      }}>
                        {step.display_name}
                      </span>
                      {i < path.steps.length - 1 && <span style={{ color: TV.muted, fontSize: 10 }}>→</span>}
                    </span>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </TvPanel>
      </div>
    </div>
  );
}
