import { useEffect, useState, useCallback, useRef } from "react";
import client from "../api/client";
import { toastError, toastSuccess } from "../utils/toast";
import { TV } from "../theme/basDark";

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
const RISK_COLOR = { high: "#e96363", medium: "#d4a500", low: "#7fe0b0", critical: "#e96363" };
const CONTROL_STATUS_LABEL = { tested: "testado", prevented: "prevenido", detected: "detectado", missed: "perdido", not_applicable: "sem teste" };
const CONTROL_STATUS_COLOR = { tested: TV.muted, prevented: "#7fe0b0", detected: "#72b7ff", missed: "#e96363", not_applicable: "#8a93a3" };

function formatElapsed(sinceIso, nowMs) {
  if (!sinceIso) return "—";
  const since = new Date(sinceIso).getTime();
  if (Number.isNaN(since)) return "—";
  const totalSeconds = Math.max(0, Math.floor((nowMs - since) / 1000));
  const minutes = Math.floor(totalSeconds / 60);
  const seconds = totalSeconds % 60;
  return minutes > 0 ? `${minutes}m ${seconds}s` : `${seconds}s`;
}

export default function BasOperationsCenterPage() {
  const [summary, setSummary] = useState(null);
  const [center, setCenter] = useState(null);
  const [now, setNow] = useState(() => Date.now());
  const [cleanupScope, setCleanupScope] = useState("all");

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

  const activeJobs = center?.active_jobs || [];

  // While something's actually in flight, poll fast enough that "Testes em
  // andamento" reads as live -- 15s made a 3-minute smb_enum_cme run look
  // static. Falls back to a calmer 15s once nothing is running.
  useEffect(() => {
    load();
    const id = setInterval(load, activeJobs.length > 0 ? 4000 : 15000);
    return () => clearInterval(id);
  }, [load, activeJobs.length]);

  // Elapsed-time counters on active jobs tick every second locally --
  // independent of the network poll above, which only needs to run often
  // enough to catch a job finishing/a new one starting.
  useEffect(() => {
    if (activeJobs.length === 0) return;
    const id = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(id);
  }, [activeJobs.length]);

  const agents = center?.agents || [];
  const schedules = center?.schedules || [];
  const jobs = center?.recent_jobs || [];
  const techniqueStats = center?.technique_stats || {};
  const frameworkCoverage = center?.framework_coverage || {};
  const controlMatrix = center?.control_matrix || {};
  const controlMatrixSummary = controlMatrix.summary || {};
  const controlMatrixFrameworks = controlMatrix.frameworks || [];
  const controlMatrixCells = controlMatrix.cells || [];
  const exposure = center?.exposure || {};
  const findings = center?.findings || [];
  const actionPriorities = center?.action_priorities || [];
  const attackInventory = center?.attack_path_inventory || {};
  const attackSummary = attackInventory.summary || {};
  const attackSteps = attackInventory.attack_steps || [];
  const cmdbAssets = attackInventory.cmdb_assets || [];
  const applications = attackInventory.applications || [];
  const observedVulnerabilities = attackInventory.vulnerabilities || [];
  const recommendedTests = attackInventory.recommended_tests || [];
  const portScan = center?.port_scan_observability || {};
  const portScanSummary = portScan.summary || {};
  const portScanRows = portScan.scans || [];
  const crownJewels = center?.crown_jewels || [];
  const heatmap = center?.attack_heatmap || [];
  const chainPaths = center?.chain_attack_paths || [];
  const riskScore = center?.risk_score || {};
  const scoreValue = riskScore.score;
  const scoreColor = scoreValue == null ? TV.muted : scoreValue >= 60 ? "#e96363" : scoreValue >= 30 ? "#d4a500" : "#7fe0b0";

  const resetTestData = async () => {
    const params = {};
    const [scopeType, scopeId] = cleanupScope.split(":");
    if (scopeType === "schedule") params.schedule_id = scopeId;
    if (scopeType === "agent") params.agent_id = scopeId;
    const scopeLabel = cleanupScope === "all"
      ? "TODO o histórico de testes BAS"
      : scopeType === "schedule"
        ? `o histórico do agendamento #${scopeId}`
        : `o histórico do agente #${scopeId}`;
    if (!window.confirm(
      `Apagar ${scopeLabel}? Isso remove os jobs disparados e os achados que eles geraram. Score, exposição e heatmap voltam a refletir apenas os dados restantes. Agentes e agendamentos configurados NÃO são apagados. Não pode ser desfeito.`
    )) return;
    try {
      const { data } = await client.delete("/api/bas/jobs", { params });
      toastSuccess(`Histórico limpo: ${data.jobs_deleted} job(s), ${data.findings_deleted} achado(s) e ${data.scan_jobs_deleted || 0} scan(s) BAS removidos.`);
      load();
    } catch (error) {
      const detail = error?.response?.data?.detail;
      toastError(typeof detail === "string" ? detail : "Falha ao limpar histórico de testes.");
    }
  };

  const deleteAgent = async (agent) => {
    const label = agent.label || agent.os || `agente #${agent.id}`;
    if (!window.confirm(`Remover ${label}? Isso apaga o agente, seus agendamentos, jobs e achados BAS vinculados. Não pode ser desfeito.`)) return;
    try {
      await client.delete(`/api/bas/agents/${agent.id}`);
      toastSuccess("Agente removido com histórico vinculado.");
      load();
    } catch (error) {
      const detail = error?.response?.data?.detail;
      toastError(typeof detail === "string" ? detail : "Falha ao remover agente.");
    }
  };

  return (
    <div style={{ background: TV.bg, minHeight: "100%", padding: 20, borderRadius: 12 }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline", marginBottom: 16 }}>
        <div>
          <div style={{ fontSize: 15, fontWeight: 700, color: TV.text }}>Centro Operacional BAS</div>
          <div style={{ fontSize: 11, color: TV.muted }}>Breach &amp; Attack Simulation — agentes, técnicas e jobs</div>
        </div>
        <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
          <select
            value={cleanupScope}
            onChange={(e) => setCleanupScope(e.target.value)}
            style={{ background: TV.surface, border: `1px solid ${TV.border}`, color: TV.text, borderRadius: 8, padding: "6px 9px", fontSize: 11 }}
          >
            <option value="all">Todo histórico BAS</option>
            {schedules.map((s) => <option key={`s-${s.id}`} value={`schedule:${s.id}`}>Agendamento #{s.id} · {s.name || "sem nome"}</option>)}
            {agents.map((a) => <option key={`a-${a.id}`} value={`agent:${a.id}`}>Agente #{a.id} · {a.label || a.os || "sem nome"}</option>)}
          </select>
          <button
            onClick={resetTestData}
            style={{ background: "transparent", border: `1px solid ${TV.border}`, color: TV.muted, borderRadius: 8, padding: "6px 12px", fontSize: 11, cursor: "pointer" }}
          >
            Limpar histórico
          </button>
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

      <TvPanel title="BAS - Attack Path & CMDB" right={`${attackSummary.assets || 0} ativo(s) · ${attackSummary.vulnerabilities || 0} vulnerabilidade(s)`} span={3} style={{ marginBottom: 12 }}>
        <div style={{ display: "grid", gridTemplateColumns: "1.1fr 1.2fr 0.9fr", gap: 12 }}>
          <div style={{ display: "grid", gap: 8 }}>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 8 }}>
              <div style={{ background: TV.surface2, borderRadius: 8, padding: "9px 10px" }}>
                <div style={{ fontSize: 9.5, color: TV.muted, textTransform: "uppercase" }}>CMDB</div>
                <div style={{ fontFamily: "var(--font-mono)", color: TV.text, fontSize: 20, fontWeight: 700 }}>{attackSummary.assets || 0}</div>
              </div>
              <div style={{ background: TV.surface2, borderRadius: 8, padding: "9px 10px" }}>
                <div style={{ fontSize: 9.5, color: TV.muted, textTransform: "uppercase" }}>Apps</div>
                <div style={{ fontFamily: "var(--font-mono)", color: TV.text, fontSize: 20, fontWeight: 700 }}>{attackSummary.applications || 0}</div>
              </div>
              <div style={{ background: TV.surface2, borderRadius: 8, padding: "9px 10px" }}>
                <div style={{ fontSize: 9.5, color: TV.muted, textTransform: "uppercase" }}>Risco alto</div>
                <div style={{ fontFamily: "var(--font-mono)", color: RISK_COLOR.high, fontSize: 20, fontWeight: 700 }}>{attackSummary.high_risk_assets || 0}</div>
              </div>
            </div>
            <div style={{ background: TV.surface2, borderRadius: 8, padding: "10px 12px" }}>
              <div style={{ fontSize: 11, color: TV.text, fontWeight: 700, marginBottom: 8 }}>Attack Path observado</div>
              {attackSteps.length === 0 && <div style={{ fontSize: 11, color: TV.muted }}>Nenhum caminho observado ainda.</div>}
              <div style={{ display: "grid", gap: 7 }}>
                {attackSteps.map((step) => {
                  const color = step.status === "critical_fix" ? RISK_COLOR.high : step.status === "needs_fix" ? RISK_COLOR.medium : RISK_COLOR.low;
                  return (
                    <div key={step.order} style={{ display: "grid", gridTemplateColumns: "22px 1fr", gap: 8, alignItems: "start" }}>
                      <div style={{ width: 22, height: 22, borderRadius: 11, border: `1px solid ${color}`, color, display: "grid", placeItems: "center", fontSize: 10, fontWeight: 800 }}>{step.order}</div>
                      <div>
                        <div style={{ color: TV.text, fontSize: 11.5, fontWeight: 700 }}>{step.title}</div>
                        <div style={{ color: TV.muted, fontSize: 10.5, marginTop: 2 }}>{step.description}</div>
                        <div style={{ color, fontSize: 10, marginTop: 2 }}>{step.evidence}</div>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          </div>

          <div style={{ background: TV.surface2, borderRadius: 8, padding: "10px 12px", minWidth: 0 }}>
            <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 8 }}>
              <span style={{ fontSize: 11, color: TV.text, fontWeight: 700 }}>CMDB encontrada</span>
              <span style={{ fontSize: 10, color: TV.muted }}>{cmdbAssets.length} ativo(s)</span>
            </div>
            <div style={{ display: "grid", gap: 6, maxHeight: 320, overflowY: "auto" }}>
              {cmdbAssets.length === 0 && <div style={{ fontSize: 11, color: TV.muted }}>Sem ativos descobertos por BAS ainda.</div>}
              {cmdbAssets.slice(0, 12).map((asset) => (
                <div key={asset.ip} style={{ display: "grid", gridTemplateColumns: "1fr auto", gap: 8, border: `1px solid ${TV.border}`, borderRadius: 8, padding: "8px 10px" }}>
                  <div style={{ minWidth: 0 }}>
                    <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
                      <span style={{ fontFamily: "var(--font-mono)", color: TV.text, fontSize: 11.5, fontWeight: 700 }}>{asset.ip}</span>
                      <span style={{ color: RISK_COLOR[asset.risk_level] || TV.muted, fontSize: 9.5, fontWeight: 800 }}>{String(asset.risk_level || "low").toUpperCase()}</span>
                    </div>
                    <div style={{ color: TV.muted, fontSize: 10.5, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>{asset.hostname} · {asset.domain || "sem domínio"}</div>
                    <div style={{ color: TV.muted, fontSize: 10, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>{asset.os || "SO não identificado"}</div>
                  </div>
                  <div style={{ textAlign: "right" }}>
                    <div style={{ color: TV.text, fontSize: 10.5 }}>{(asset.services || []).map((s) => `${s.name}/${s.port}`).join(", ") || "—"}</div>
                    <div style={{ color: TV.muted, fontSize: 10 }}>{(asset.vulnerabilities || []).length} vul.</div>
                  </div>
                </div>
              ))}
            </div>
          </div>

          <div style={{ display: "grid", gap: 8 }}>
            <div style={{ background: TV.surface2, borderRadius: 8, padding: "10px 12px" }}>
              <div style={{ fontSize: 11, color: TV.text, fontWeight: 700, marginBottom: 8 }}>Aplicações e versões</div>
              <div style={{ display: "grid", gap: 6 }}>
                {applications.length === 0 && <div style={{ fontSize: 11, color: TV.muted }}>Sem aplicações identificadas.</div>}
                {applications.slice(0, 5).map((app) => (
                  <div key={`${app.name}-${app.version}-${app.port}`} style={{ border: `1px solid ${TV.border}`, borderRadius: 8, padding: "7px 9px" }}>
                    <div style={{ color: TV.text, fontSize: 11.5, fontWeight: 700 }}>{app.name}</div>
                    <div style={{ color: TV.muted, fontSize: 10.5 }}>{app.version} · {app.protocol}/{app.port}</div>
                    <div style={{ color: TV.muted, fontSize: 10 }}>{(app.hosts || []).length} host(s)</div>
                  </div>
                ))}
              </div>
            </div>

            <div style={{ background: TV.surface2, borderRadius: 8, padding: "10px 12px" }}>
                  <div style={{ fontSize: 11, color: TV.text, fontWeight: 700, marginBottom: 8 }}>Achados encontrados</div>
              <div style={{ display: "grid", gap: 6 }}>
                {observedVulnerabilities.length === 0 && <div style={{ fontSize: 11, color: TV.muted }}>Nenhuma vulnerabilidade real consolidada.</div>}
                {observedVulnerabilities.slice(0, 5).map((vuln) => (
                  <div key={vuln.id} style={{ border: `1px solid ${TV.border}`, borderRadius: 8, padding: "7px 9px" }}>
                    <div style={{ display: "flex", justifyContent: "space-between", gap: 8 }}>
                      <span style={{ color: TV.text, fontSize: 11.5, fontWeight: 700 }}>{vuln.title}</span>
                      <span style={{ color: RISK_COLOR[vuln.severity] || TV.muted, fontSize: 10, fontWeight: 800 }}>{String(vuln.severity || "").toUpperCase()}</span>
                    </div>
                    <div style={{ color: TV.muted, fontSize: 10.5 }}>{(vuln.affected_assets || []).length} ativo(s) afetado(s)</div>
                  </div>
                ))}
              </div>
            </div>

            <div style={{ background: TV.surface2, borderRadius: 8, padding: "10px 12px" }}>
              <div style={{ fontSize: 11, color: TV.text, fontWeight: 700, marginBottom: 8 }}>Próximos testes úteis</div>
              <div style={{ display: "grid", gap: 5 }}>
                {recommendedTests.length === 0 && <div style={{ fontSize: 11, color: TV.muted }}>Sem recomendações adicionais neste momento.</div>}
                {recommendedTests.slice(0, 3).map((item) => (
                  <div key={item} style={{ color: TV.muted, fontSize: 10.5 }}>{item}</div>
                ))}
              </div>
            </div>
          </div>
        </div>
      </TvPanel>

      <TvPanel title="Port Scan" right={`${portScanSummary.scanned_ips || 0} IP(s) · ${portScanSummary.open_port_count || 0} porta(s) aberta(s)`} span={3} style={{ marginBottom: 12 }}>
        <div style={{ display: "grid", gap: 8 }}>
          {portScanRows.length === 0 && <div style={{ fontSize: 11, color: TV.muted }}>Nenhum port scan real concluído ainda.</div>}
          {portScanRows.map((scan) => (
            <div key={scan.job_id} style={{ background: TV.surface2, borderRadius: 8, padding: "10px 12px", border: `1px solid ${TV.border}` }}>
              <div style={{ display: "flex", justifyContent: "space-between", gap: 12, marginBottom: 6 }}>
                <div style={{ minWidth: 0 }}>
                  <div style={{ fontSize: 12, color: TV.text, fontWeight: 700 }}>#{scan.job_id} · {scan.target || "sem alvo"}</div>
                  <div style={{ fontSize: 10.5, color: TV.muted }}>{scan.agent_label} · {scan.scanned_ips || 0} IP(s) varrido(s) · {scan.hosts_up || 0} host(s) tratado(s) como ativo(s)</div>
                </div>
                <div style={{ textAlign: "right" }}>
                  <div style={{ color: scan.open_port_count > 0 ? "#d4a500" : "#7fe0b0", fontSize: 18, fontWeight: 800 }}>{scan.open_port_count || 0}</div>
                  <div style={{ color: TV.muted, fontSize: 10 }}>porta(s) aberta(s)</div>
                </div>
              </div>
              {scan.open_port_count > 0 ? (
                <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
                  {(scan.open_ports || []).slice(0, 20).map((port) => (
                    <span key={`${scan.job_id}-${port.host}-${port.port}-${port.protocol}`} style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: TV.text, border: `1px solid ${TV.border}`, borderRadius: 6, padding: "3px 6px" }}>
                      {port.host}:{port.port}/{port.protocol} {port.service || ""}
                    </span>
                  ))}
                </div>
              ) : (
                <div style={{ fontSize: 10.5, color: TV.muted }}>Resultado real: varredura concluída sem portas abertas nos top 100 TCP do alvo.</div>
              )}
              {scan.last_error && <div style={{ fontSize: 10, color: "#d4a500", marginTop: 6 }}>observação: {scan.last_error}</div>}
            </div>
          ))}
        </div>
      </TvPanel>

      <TvPanel title="Prioridades de correção" right={`${actionPriorities.length} ação(ões)`} span={3} style={{ marginBottom: 12 }}>
        <div style={{ display: "grid", gap: 8 }}>
          {actionPriorities.length === 0 && <div style={{ fontSize: 11, color: TV.muted }}>Nenhuma prioridade real extraída dos testes concluídos ainda.</div>}
          {actionPriorities.slice(0, 6).map((item) => {
            const color = item.priority === "P0" ? "#e96363" : item.priority === "P1" ? "#d4a500" : "#7fe0b0";
            return (
              <div key={item.id} style={{ background: TV.surface2, borderRadius: 8, padding: "10px 12px", border: `1px solid ${TV.border}` }}>
                <div style={{ display: "flex", justifyContent: "space-between", gap: 12 }}>
                  <div>
                    <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                      <span style={{ fontSize: 10, fontWeight: 800, color, border: `1px solid ${color}`, borderRadius: 4, padding: "1px 5px" }}>{item.priority}</span>
                      <span style={{ fontSize: 12, fontWeight: 700, color: TV.text }}>{item.title}</span>
                    </div>
                    <div style={{ fontSize: 10.5, color: TV.muted, marginTop: 5 }}>{item.impact}</div>
                    <div style={{ fontSize: 10.5, color: TV.text, marginTop: 6 }}>{item.next_action}</div>
                    <div style={{ fontSize: 9.5, color: TV.muted, marginTop: 6 }}>
                      {item.affected_count} ativo(s) · job #{item.job_id}{(item.source_job_ids || []).length > 1 ? ` · ${item.source_job_ids.length} evidências` : ""} · {item.schedule_name || `agendamento #${item.schedule_id}`} · agente {item.agent_name || `#${item.agent_id}`}
                    </div>
                  </div>
                  <div style={{ minWidth: 260, maxWidth: 360, fontSize: 10, color: TV.muted }}>
                    {(item.affected_targets || []).slice(0, 6).map((target) => (
                      <div key={target} style={{ fontFamily: "var(--font-mono)", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>{target}</div>
                    ))}
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </TvPanel>

      <div style={{
        background: TV.surface, borderRadius: 12,
        border: `1px solid ${activeJobs.length > 0 ? "#d4a500" : TV.border}`,
        padding: "13px 16px", marginBottom: 12,
      }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline", marginBottom: 10 }}>
          <span style={{ fontSize: 12, fontWeight: 700, color: TV.text }}>
            Testes em andamento
            {activeJobs.length > 0 && (
              <span style={{ marginLeft: 8, fontSize: 9, fontWeight: 700, color: "#d4a500" }}>● AO VIVO</span>
            )}
          </span>
          <span style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: TV.muted }}>{activeJobs.length} em execução</span>
        </div>
        {activeJobs.length === 0 ? (
          <div style={{ fontSize: 11, color: TV.muted }}>Nenhum teste em execução no momento.</div>
        ) : (
          <div style={{ display: "grid", gap: 6 }}>
            {activeJobs.map((j) => {
              const agent = agents.find((a) => a.id === j.agent_id);
              return (
                <div key={j.id} style={{ display: "flex", justifyContent: "space-between", alignItems: "center", background: TV.surface2, borderRadius: 8, padding: "8px 10px" }}>
                  <div style={{ fontSize: 11, color: TV.text }}>
                    #{j.id} · {j.technique_key} <span style={{ color: TV.muted }}>({j.risk_tier})</span>
                    {j.target && <span style={{ color: TV.muted }}> · alvo: {j.target}</span>}
                    <span style={{ color: TV.muted }}> · agente: {agent?.label || agent?.os || `#${j.agent_id}`}</span>
                  </div>
                  <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                    {j.simulated ? (
                      <span style={{ fontSize: 9.5, fontWeight: 700, color: "#d4a500", border: "1px solid rgba(212,165,0,0.4)", borderRadius: 4, padding: "1px 5px" }}>SIMULADO</span>
                    ) : j.proof_valid ? (
                      <span style={{ fontSize: 9.5, fontWeight: 700, color: "#7fe0b0", border: "1px solid rgba(127,224,176,0.4)", borderRadius: 4, padding: "1px 5px" }}>VALIDADO</span>
                    ) : (
                      <span style={{ fontSize: 9.5, fontWeight: 700, color: TV.muted, border: `1px solid ${TV.border}`, borderRadius: 4, padding: "1px 5px" }}>REAL · {j.proof_status || "PENDENTE"}</span>
                    )}
                    <span style={{ fontSize: 10, color: TV.muted }}>{j.status}</span>
                    <span style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: "#d4a500" }}>{formatElapsed(j.dispatched_at, now)}</span>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>

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
                  <div style={{ fontSize: 10, color: TV.muted }}>rede: {a.local_network_cidr || "—"}</div>
                </div>
                <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
                  <span style={{ fontSize: 10, fontWeight: 700, color: STATUS_COLOR[a.status] || TV.muted }}>{a.status}</span>
                  <button
                    onClick={() => deleteAgent(a)}
                    style={{ background: "transparent", border: `1px solid ${TV.border}`, color: TV.muted, borderRadius: 6, padding: "3px 7px", fontSize: 10, cursor: "pointer" }}
                  >
                    remover
                  </button>
                </div>
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
              <div key={j.id} style={{ background: TV.surface2, borderRadius: 8, padding: "7px 10px" }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                  <div style={{ fontSize: 11, color: TV.text }}>
                    #{j.id} · {j.technique_key} <span style={{ color: TV.muted }}>({j.risk_tier})</span>
                    {j.target && <span style={{ color: TV.muted }}> · {j.target}</span>}
                  </div>
                  <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                    {j.simulated ? (
                      <span style={{ fontSize: 9.5, fontWeight: 700, color: "#d4a500", border: "1px solid rgba(212,165,0,0.4)", borderRadius: 4, padding: "1px 5px" }}>SIMULADO</span>
                    ) : j.proof_valid ? (
                      <span style={{ fontSize: 9.5, fontWeight: 700, color: "#7fe0b0", border: "1px solid rgba(127,224,176,0.4)", borderRadius: 4, padding: "1px 5px" }}>VALIDADO</span>
                    ) : (
                      <span style={{ fontSize: 9.5, fontWeight: 700, color: TV.muted, border: `1px solid ${TV.border}`, borderRadius: 4, padding: "1px 5px" }}>SEM PROVA</span>
                    )}
                    <span style={{ fontSize: 10, color: j.status === "completed" ? "#7fe0b0" : j.status === "failed" ? "#e96363" : TV.muted }}>{j.status}</span>
                  </div>
                </div>
                {j.last_error && (
                  <div style={{ fontSize: 9.5, color: "#e96363", marginTop: 3 }}>motivo: {j.last_error}</div>
                )}
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

        <TvPanel title="Achados (BAS)" right={`${findings.length} · validado, sem prova ou simulado`} span={2}>
          <div style={{ display: "grid", gap: 6, maxHeight: 220, overflowY: "auto" }}>
            {findings.length === 0 && <div style={{ fontSize: 11, color: TV.muted }}>Nenhuma finding do BAS ainda.</div>}
            {findings.map((f) => (
              <div key={f.id} style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 10, background: TV.surface2, borderRadius: 8, padding: "7px 10px" }}>
                <div style={{ minWidth: 0 }}>
                  <div style={{ fontSize: 11, color: TV.text }}>{f.title}</div>
                  <div style={{ fontFamily: "var(--font-mono)", fontSize: 9.5, color: TV.muted, marginTop: 2, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{f.observation_summary || f.key_findings?.[0] || "sem evidência parseada"}</div>
                </div>
                {f.simulated ? (
                  <span style={{ fontSize: 9.5, fontWeight: 700, color: "#d4a500", border: "1px solid rgba(212,165,0,0.4)", borderRadius: 4, padding: "1px 5px" }}>SIMULADO</span>
                ) : f.proof_valid ? (
                  <span style={{ fontSize: 9.5, fontWeight: 700, color: "#7fe0b0", border: "1px solid rgba(127,224,176,0.4)", borderRadius: 4, padding: "1px 5px" }}>VALIDADO</span>
                ) : (
                  <span style={{ fontSize: 9.5, fontWeight: 700, color: TV.muted, border: `1px solid ${TV.border}`, borderRadius: 4, padding: "1px 5px" }}>SEM PROVA</span>
                )}
              </div>
            ))}
          </div>
        </TvPanel>

        <TvPanel title="Control Matrix" right={`${controlMatrixSummary.controls || 0} controle(s) · ${controlMatrixSummary.cells || 0} célula(s)`} span={3}>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(260px, 1fr))", gap: 12 }}>
            <div style={{ display: "grid", gap: 8 }}>
              {controlMatrixFrameworks.length === 0 && <div style={{ fontSize: 11, color: TV.muted }}>Sem matriz de controles ainda.</div>}
              {controlMatrixFrameworks.map((fw) => (
                <div key={fw.framework} style={{ background: TV.surface2, border: `1px solid ${TV.border}`, borderRadius: 8, padding: "8px 10px" }}>
                  <div style={{ display: "flex", justifyContent: "space-between", gap: 8, marginBottom: 6 }}>
                    <span style={{ fontSize: 11, fontWeight: 700, color: TV.text }}>{fw.label}</span>
                    <span style={{ fontSize: 10, color: TV.muted }}>{fw.tested}/{fw.applicable}</span>
                  </div>
                  <div style={{ height: 6, borderRadius: 3, background: "rgba(255,255,255,0.06)", overflow: "hidden", marginBottom: 7 }}>
                    <div style={{ width: `${fw.coverage_pct || 0}%`, height: "100%", background: fw.coverage_pct >= 60 ? "#7fe0b0" : fw.coverage_pct > 0 ? "#d4a500" : TV.border }} />
                  </div>
                  <div style={{ display: "flex", flexWrap: "wrap", gap: 5 }}>
                    {Object.entries(fw.status_counts || {}).filter(([, count]) => count > 0).map(([status, count]) => (
                      <span key={status} style={{ fontSize: 9.5, color: CONTROL_STATUS_COLOR[status] || TV.muted, border: `1px solid ${TV.border}`, borderRadius: 4, padding: "1px 5px" }}>
                        {CONTROL_STATUS_LABEL[status] || status} {count}
                      </span>
                    ))}
                  </div>
                </div>
              ))}
            </div>
            <div style={{ overflowX: "auto" }}>
              <table style={{ width: "100%", borderCollapse: "collapse", minWidth: 760 }}>
                <thead>
                  <tr>
                    {["Framework", "Controle", "Técnica", "Estado", "Execuções"].map((head) => (
                      <th key={head} style={{ textAlign: "left", fontSize: 9.5, color: TV.label, fontWeight: 700, textTransform: "uppercase", padding: "0 8px 6px", borderBottom: `1px solid ${TV.border}` }}>{head}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {controlMatrixCells.slice(0, 80).map((cell) => (
                    <tr key={`${cell.framework}-${cell.control_id}-${cell.technique_key}`}>
                      <td style={{ fontSize: 10.5, color: TV.text, padding: "7px 8px", borderBottom: `1px solid ${TV.border}` }}>{cell.framework_label}</td>
                      <td style={{ fontSize: 10.5, color: TV.text, padding: "7px 8px", borderBottom: `1px solid ${TV.border}` }}>
                        <div style={{ fontWeight: 700 }}>{cell.control_id}</div>
                        <div style={{ color: TV.muted }}>{cell.control_name}</div>
                      </td>
                      <td style={{ fontSize: 10.5, color: TV.text, padding: "7px 8px", borderBottom: `1px solid ${TV.border}` }}>
                        <div>{cell.technique_name}</div>
                        <div style={{ color: TV.muted, fontFamily: "var(--font-mono)" }}>{cell.technique_key}</div>
                      </td>
                      <td style={{ padding: "7px 8px", borderBottom: `1px solid ${TV.border}` }}>
                        <span style={{ fontSize: 9.5, color: CONTROL_STATUS_COLOR[cell.status] || TV.muted, border: `1px solid ${TV.border}`, borderRadius: 4, padding: "2px 6px", fontWeight: 700 }}>
                          {CONTROL_STATUS_LABEL[cell.status] || cell.status}
                        </span>
                      </td>
                      <td style={{ fontSize: 10.5, color: TV.muted, padding: "7px 8px", borderBottom: `1px solid ${TV.border}` }}>{cell.times_tested || 0}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {controlMatrixCells.length > 80 && <div style={{ fontSize: 10, color: TV.muted, marginTop: 8 }}>Mostrando 80 de {controlMatrixCells.length} células.</div>}
            </div>
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
                    {path.simulated ? "SIMULADO" : path.steps?.every((step) => step.proof_valid) ? "VALIDADO" : "SEM PROVA"}
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
