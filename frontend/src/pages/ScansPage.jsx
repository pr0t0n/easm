import { useEffect, useState, useCallback } from "react";
import client, { getWsBaseUrl } from "../api/client";
import LogTerminal from "../components/LogTerminal";

// ─── Fases (prototype style) ────────────────────────────────────────────────
const FASES_IDS  = [
  "P01","P02","P03","P04","P05","P06","P07","P08","P09","P10","P11",
  "P12","P13","P14","P15","P16","P17","P18","P19","P20","P21","P22",
];
const FASE_NOMES = {
  P01: "Enumeração de subdomínios",   P02: "Descoberta de portas/serviços",
  P03: "Descoberta de endpoints",      P04: "Descoberta de parâmetros",
  P05: "Fingerprint de tecnologia",    P06: "Comportamento HTTP",
  P07: "OSINT e exposição",            P08: "TLS e transporte",
  P09: "Superfície de autenticação",   P10: "Controle de acesso",
  P11: "Validação de entrada",         P12: "Template/Injeção",
  P13: "Headers e roteamento",         P14: "CVEs conhecidas",
  P15: "Paths sensíveis",              P16: "Exposição em nuvem",
  P17: "Contratos de API",             P18: "JS e segredos client-side",
  P19: "Tampering de métodos",         P20: "Lógica de negócio",
  P21: "Leaks e paste intel",          P22: "Evidências e relatório",
};

const LEVEL_MAP = {
  recon: "Recon", asm: "Recon",
  standard: "Padrão", full: "Padrão",
  aggressive: "Agressivo",
  Recon: "Recon", Standard: "Padrão", Aggressive: "Agressivo",
};

const ACTIVE_STATUS    = ["queued", "running", "retrying"];
const STOPPABLE_STATUS = [...ACTIVE_STATUS, "paused"];
const TERMINAL_STATUS  = new Set(["completed", "failed", "cancelled", "stopped"]);

const SCAN_PERFIL = {
  Recon:     { c: "var(--sev-info-text)",  bg: "var(--sev-info-bg)",  bd: "var(--sev-info-border)",  d: "P01-P08 + P18/P21/P22, profundidade baixa" },
  Padrão:    { c: "var(--ink-soft)",        bg: "var(--surface-soft)", bd: "var(--line)",              d: "P01-P22, profundidade média" },
  Agressivo: { c: "var(--sev-high-text)",  bg: "var(--sev-high-bg)",  bd: "var(--sev-high-border)",  d: "P01-P22, profundidade alta" },
};
const CRIT_CSS = {
  Crítica: { c: "var(--sev-critical-text)", bg: "var(--sev-critical-bg)", bd: "var(--sev-critical-border)" },
  Alta:    { c: "var(--sev-high-text)",     bg: "var(--sev-high-bg)",     bd: "var(--sev-high-border)" },
  Média:   { c: "var(--sev-medium-text)",   bg: "var(--sev-medium-bg)",   bd: "var(--sev-medium-border)" },
  Baixa:   { c: "var(--sev-low-text)",      bg: "var(--sev-low-bg)",      bd: "var(--sev-low-border)" },
};
const FASE_CSS = {
  done:    "var(--sev-low-solid)",
  running: "var(--brand-500)",
  partial: "var(--sev-medium-solid)",
  blocked: "var(--sev-critical-solid)",
  pending: "var(--canvas-muted)",
};
const STATUS_CSS = {
  running: { c: "var(--sev-low-text)",      dot: "var(--sev-low-solid)",      t: "Rodando" },
  queued:  { c: "var(--sev-medium-text)",   dot: "var(--sev-medium-solid)",   t: "Na fila" },
  retrying:{ c: "var(--sev-medium-text)",   dot: "var(--sev-medium-solid)",   t: "Retentando" },
  paused:  { c: "var(--sev-medium-text)",   dot: "var(--sev-medium-solid)",   t: "Pausado" },
  blocked: { c: "var(--sev-critical-text)", dot: "var(--sev-critical-solid)", t: "Bloqueado" },
};

// ─── Helpers ──────────────────────────────────────────────────────────────────
function fmtDateSP(value) {
  if (!value) return "—";
  const dt = new Date(value);
  if (Number.isNaN(dt.getTime())) return "—";
  return dt.toLocaleString("pt-BR", { timeZone: "America/Sao_Paulo", day: "2-digit", month: "short", hour: "2-digit", minute: "2-digit" });
}
function fmtDuration(s, e) {
  if (!s) return "—";
  const sec = Math.floor((new Date(e || Date.now()) - new Date(s)) / 1000);
  if (sec < 60) return `${sec}s`;
  const m = Math.floor(sec / 60), h = Math.floor(m / 60);
  return h > 0 ? `${h}h ${String(m % 60).padStart(2,"0")}m` : `${m}m ${String(sec % 60).padStart(2,"0")}s`;
}
function extractPhase(step) {
  if (!step) return null;
  const m = String(step).match(/P(\d+)/i);
  return m ? `P${m[1].padStart(2,"0")}` : null;
}
// compliance_status é a única fonte real do motivo de bloqueio hoje
// (create_scan só seta status="blocked" para auth_failed/tool_health_failed —
// não existe gate de "guardrail/escopo" na criação do scan).
function blockedReasonLabel(scan) {
  const reason = scan.compliance_status;
  if (reason === "auth_failed") return "Bloqueado · autenticação obrigatória falhou";
  if (reason === "tool_health_failed") return "Bloqueado · ferramentas indisponíveis";
  return scan.last_error ? `Bloqueado · ${scan.last_error}` : "Bloqueado";
}
function getPerfil(scan) {
  return LEVEL_MAP[scan.level] || LEVEL_MAP[scan.scan_level] || "Padrão";
}
function getFaseStates(scan) {
  const cur = extractPhase(scan.current_step);
  const curIdx = FASES_IDS.indexOf(cur);
  return FASES_IDS.map((f, i) => {
    if (scan.status === "completed") return "done";
    if (scan.status === "blocked" && f === cur) return "blocked";
    if (scan.status === "blocked" && i > curIdx) return "pending";
    if (i < curIdx) return "done";
    if (f === cur && !TERMINAL_STATUS.has(scan.status) && scan.status !== "paused") return "running";
    if (f === cur && scan.status === "paused") return "partial";
    return "pending";
  });
}

// ─── Atoms ───────────────────────────────────────────────────────────────────
function PerfilBadge({ perfil }) {
  const p = SCAN_PERFIL[perfil] || SCAN_PERFIL.Padrão;
  return (
    <span title={p.d} style={{
      fontSize: 10, fontWeight: 700, color: p.c, background: p.bg,
      border: `1px solid ${p.bd}`, padding: "2px 8px", borderRadius: 999,
      letterSpacing: "0.03em", textTransform: "uppercase",
    }}>{perfil}</span>
  );
}
function CritBadge({ crit }) {
  const c = CRIT_CSS[crit] || CRIT_CSS.Baixa;
  return (
    <span style={{
      fontSize: 10, fontWeight: 700, color: c.c, background: c.bg,
      border: `1px solid ${c.bd}`, padding: "2px 8px", borderRadius: 999, letterSpacing: "0.03em",
    }}>{crit}</span>
  );
}
function StatusDot({ status }) {
  const s = STATUS_CSS[status] || STATUS_CSS.running;
  return (
    <span style={{ display: "inline-flex", alignItems: "center", gap: 5, fontSize: 11, fontWeight: 600, color: s.c }}>
      <span style={{
        width: 7, height: 7, borderRadius: 99, background: s.dot, flexShrink: 0,
        boxShadow: status === "running" ? `0 0 0 3px ${s.dot}33` : "none",
      }} />{s.t}
    </span>
  );
}
function MiniPipeline({ faseStates }) {
  return (
    <div style={{ display: "flex", gap: 3 }}>
      {faseStates.map((st, i) => (
        <div key={i} title={`${FASES_IDS[i]} · ${FASE_NOMES[FASES_IDS[i]]} · ${st}`}
          style={{ flex: 1, height: 6, borderRadius: 99, background: FASE_CSS[st], opacity: st === "pending" ? 0.45 : 1 }} />
      ))}
    </div>
  );
}

// ─── Card de missão ativa ─────────────────────────────────────────────────────
function ActiveScanCard({ scan, onStop, onPause, onResume, onContinue, onDelete, onReport, onClick }) {
  const pct        = scan.mission_progress ?? scan.progress ?? 0;
  const faseStates = getFaseStates(scan);
  const perfil     = getPerfil(scan);
  const curIdx     = faseStates.lastIndexOf("running") >= 0 ? faseStates.lastIndexOf("running") : faseStates.filter(s => s==="done").length;
  const faseLabel  = FASES_IDS[curIdx] ? `${FASES_IDS[curIdx]} · ${FASE_NOMES[FASES_IDS[curIdx]]}` : "—";
  const isBlocked  = scan.status === "blocked";
  const isPaused   = scan.status === "paused";
  const isRunning  = scan.status === "running" || scan.status === "queued" || scan.status === "retrying";
  const isStopped  = scan.status === "stopped" || scan.status === "failed";

  const borderColor = isBlocked ? "var(--sev-critical-solid)"
                    : isPaused  ? "var(--sev-medium-solid)"
                    : "var(--brand-500)";

  const totalAchados = (scan.open_critical||0)+(scan.open_high||0)+(scan.open_medium||0)+(scan.open_low||0);

  return (
    <div className="sk-panel" style={{ padding: "16px 18px", borderTop: `3px solid ${borderColor}`, opacity: isBlocked ? 0.85 : 1, cursor: "pointer" }} onClick={onClick}>
      {/* cabeçalho */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 10 }}>
        <div>
          <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 3 }}>
            <span className="sk-mono" style={{ fontSize: 14, fontWeight: 700 }}>#{scan.id}</span>
            <PerfilBadge perfil={perfil} />
          </div>
          <div className="sk-mono" style={{ fontSize: 12, color: "var(--ink-soft)" }}>{scan.target_query}</div>
        </div>
        <StatusDot status={scan.status} />
      </div>

      {/* pipeline de fases */}
      <MiniPipeline faseStates={faseStates} />

      {/* fase atual + % + ETA */}
      <div style={{ marginTop: 8, marginBottom: 12 }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline", marginBottom: 5 }}>
          <span style={{ fontSize: 12, fontWeight: 600 }}>
            {isBlocked
              ? <span style={{ color: "var(--sev-critical-text)" }}>{blockedReasonLabel(scan)}</span>
              : isPaused
                ? <span style={{ color: "var(--sev-medium-text)" }}>{faseLabel} — pausado</span>
                : <span>{faseLabel}</span>
            }
          </span>
          <div style={{ display: "flex", gap: 12, alignItems: "baseline" }}>
            <span className="sk-mono" style={{ fontSize: 13, fontWeight: 700 }}>{pct}%</span>
            <span className="sk-mono" style={{ fontSize: 10.5, color: "var(--ink-muted)" }}>{fmtDuration(scan.started_at, scan.finished_at)}</span>
          </div>
        </div>
        <div style={{ height: 7, background: "var(--canvas-muted)", borderRadius: 99, overflow: "hidden" }}>
          <div style={{
            width: `${pct}%`, height: "100%", borderRadius: 99, transition: "width 500ms ease",
            background: isBlocked ? "var(--sev-critical-solid)" : isPaused ? "var(--sev-medium-solid)" : "var(--brand-500)",
          }} />
        </div>
        <div className="sk-mono" style={{ fontSize: 9.5, color: "var(--ink-muted)", marginTop: 3 }}>
          iniciado {fmtDateSP(scan.started_at)}
        </div>
      </div>

      {/* KPIs */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 6, marginBottom: 12 }}>
        {[
          ["Achados",     totalAchados,      "var(--ink)"],
          ["Críticos",    scan.open_critical||0, scan.open_critical > 0 ? "var(--sev-critical-text)" : "var(--ink-muted)"],
          ["Altos",       scan.open_high||0,     scan.open_high > 0 ? "var(--sev-high-text)" : "var(--ink-muted)"],
          ["Progresso",   `${pct}%`,         "var(--ink)"],
        ].map(([l, v, c]) => (
          <div key={l} style={{ textAlign: "center", padding: "7px 2px", background: "var(--surface-soft)", borderRadius: 8, border: "1px solid var(--line-soft)" }}>
            <div className="sk-mono" style={{ fontSize: 15, fontWeight: 600, color: c }}>{v}</div>
            <div style={{ fontSize: 8.5, color: "var(--ink-muted)", textTransform: "uppercase", letterSpacing: "0.05em", marginTop: 1 }}>{l}</div>
          </div>
        ))}
      </div>

      {/* controles */}
      <div style={{ display: "flex", gap: 6 }} onClick={(e) => e.stopPropagation()}>
        {isBlocked ? (
          <>
            <button className="sk-btn-ghost" style={{ flex: 1, padding: "7px 0", fontSize: 12, color: "var(--sev-critical-text)", borderColor: "var(--sev-critical-border)" }}
              onClick={() => onStop(scan.id)}>■ Cancelar</button>
          </>
        ) : isPaused ? (
          <>
            <button className="sk-btn-primary" style={{ flex: 1, padding: "7px 0", fontSize: 12 }}
              onClick={() => onResume(scan.id)}>▶ Retomar</button>
            <button className="sk-btn-ghost" style={{ padding: "7px 14px", fontSize: 12, color: "var(--sev-critical-text)", borderColor: "var(--sev-critical-border)" }}
              onClick={() => onStop(scan.id)}>■ Parar</button>
          </>
        ) : isStopped ? (
          <>
            <button className="sk-btn-primary" style={{ flex: 1, padding: "7px 0", fontSize: 12 }}
              onClick={() => onContinue(scan.id)}>▶ Continuar</button>
            <button className="sk-btn-ghost" style={{ padding: "7px 14px", fontSize: 12, color: "var(--sev-critical-text)", borderColor: "var(--sev-critical-border)" }}
              onClick={() => onDelete(scan.id)}>Deletar</button>
          </>
        ) : (
          <>
            <button className="sk-btn-ghost" style={{ padding: "7px 14px", fontSize: 12 }}
              onClick={() => onPause(scan.id)}>⏸ Pausar</button>
            <button className="sk-btn-ghost" style={{ flex: 1, padding: "7px 0", fontSize: 12 }}>Acompanhar</button>
            <button className="sk-btn-ghost" style={{ padding: "7px 14px", fontSize: 12, color: "var(--sev-critical-text)", borderColor: "var(--sev-critical-border)" }}
              onClick={() => onStop(scan.id)}>■ Parar</button>
          </>
        )}
      </div>
    </div>
  );
}

// ─── Compositor de nova missão (inline, como no protótipo) ────────────────────
function NovoScanComposer({ groups, onClose, onCreate, onSchedule, statusMsg }) {
  const [perfil,   setPerfil]   = useState("Padrão");
  const [crit,     setCrit]     = useState("Alta");
  const [janela,   setJanela]   = useState("imediato");
  const [target,   setTarget]   = useState("");
  const [accessGroupId, setAccessGroupId] = useState("");
  const [scopeAuthorizationAttested, setScopeAuthorizationAttested] = useState(false);
  const [authEnabled, setAuthEnabled] = useState(false);
  const [authConfig,  setAuthConfig]  = useState({ type: "bearer", token: "", cookie: "", username: "", password: "", headerName: "X-API-Key", headerValue: "" });
  const [scheduleForm, setScheduleForm] = useState({ frequency: "daily", run_time: "00:00", day_of_week: "monday", day_of_month: 1 });
  const [submitting, setSubmitting] = useState(false);

  const LEVEL_REVERSE = { Recon: "asm", Padrão: "full", Agressivo: "aggressive" };

  useEffect(() => {
    if (!accessGroupId && groups.length === 1) {
      setAccessGroupId(String(groups[0].id));
    }
  }, [accessGroupId, groups]);

  const buildAuth = () => {
    if (!authEnabled) return null;
    if (authConfig.type === "bearer" && authConfig.token) return { type: "bearer", token: authConfig.token };
    if (authConfig.type === "cookie" && authConfig.cookie) return { type: "cookie", cookie: authConfig.cookie };
    if (authConfig.type === "basic"  && authConfig.username) return { type: "basic", username: authConfig.username, password: authConfig.password };
    if (authConfig.type === "header" && authConfig.headerName) return { type: "header", headers: { [authConfig.headerName]: authConfig.headerValue } };
    return null;
  };

  const handleLancar = async () => {
    if (!target.trim()) return;
    setSubmitting(true);
    try {
      const selectedGroup = groups.find((g) => String(g.id) === String(accessGroupId));
      if (janela === "agendar") {
        await onSchedule({ target, accessGroupId, accessGroupName: selectedGroup?.name || "", scheduleForm });
      } else {
        await onCreate({
          target,
          scanLevel: LEVEL_REVERSE[perfil] || "full",
          accessGroupId,
          accessGroupName: selectedGroup?.name || "",
          scopeAuthorizationAttested,
          authPayload: buildAuth(),
        });
      }
    } finally {
      setSubmitting(false);
    }
  };

  useEffect(() => {
    const h = (e) => { if (e.key === "Escape") onClose(); };
    window.addEventListener("keydown", h);
    return () => window.removeEventListener("keydown", h);
  }, [onClose]);

  return (
    <div className="sk-panel" style={{ padding: "18px 22px", marginBottom: 16, border: "1px solid var(--brand-300)", boxShadow: "var(--shadow-elevate, 0 4px 24px rgba(0,0,0,.12))" }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 14 }}>
        <span style={{ fontSize: 14, fontWeight: 700 }}>Nova missão</span>
        <button onClick={onClose} style={{ border: "none", background: "transparent", color: "var(--ink-muted)", fontSize: 18, cursor: "pointer", lineHeight: 1 }}>✕</button>
      </div>

      {statusMsg && (
        <div style={{ borderRadius: 8, padding: "8px 12px", fontSize: 12, marginBottom: 12, background: statusMsg.includes("sucesso") ? "var(--sev-low-bg)" : "var(--sev-medium-bg)", color: statusMsg.includes("sucesso") ? "var(--sev-low-text)" : "var(--sev-medium-text)", border: `1px solid ${statusMsg.includes("sucesso") ? "var(--sev-low-border)" : "var(--sev-medium-border)"}` }}>
          {statusMsg}
        </div>
      )}

      <div style={{ display: "grid", gridTemplateColumns: "1.4fr 1fr 1fr 1fr 1fr auto", gap: 14, alignItems: "end" }}>
        {/* Alvo */}
        <div>
          <label style={{ fontSize: 11, fontWeight: 600, color: "var(--ink-soft)", display: "block", marginBottom: 5 }}>Escopo / alvo</label>
          <input
            className="sk-mono" value={target} onChange={(e) => setTarget(e.target.value)}
            placeholder="*.empresa.com.br"
            style={{ width: "100%", boxSizing: "border-box", fontSize: 12.5, padding: "9px 12px", borderRadius: 8, border: "1px solid var(--line)", fontFamily: "var(--font-mono)", color: "var(--ink)", background: "#fff" }}
          />
          <div style={{ fontSize: 10.5, color: "var(--ink-muted)", marginTop: 4 }}>separe múltiplos alvos com ;</div>
        </div>

        {/* Empresa */}
        <div>
          <label style={{ fontSize: 11, fontWeight: 600, color: "var(--ink-soft)", display: "block", marginBottom: 5 }}>Empresa</label>
          <select
            value={accessGroupId}
            onChange={(e) => setAccessGroupId(e.target.value)}
            style={{ width: "100%", boxSizing: "border-box", fontSize: 12.5, padding: "9px 12px", borderRadius: 8, border: "1px solid var(--line)", color: "var(--ink)", background: "#fff" }}
          >
            <option value="">Selecione</option>
            {groups.map((g) => <option key={g.id} value={g.id}>{g.name}</option>)}
          </select>
          <div style={{ fontSize: 10, color: "var(--ink-muted)", marginTop: 4 }}>limite de visibilidade</div>
        </div>

        {/* Perfil */}
        <div>
          <label style={{ fontSize: 11, fontWeight: 600, color: "var(--ink-soft)", display: "block", marginBottom: 5 }}>Perfil</label>
          <div style={{ display: "flex", gap: 4 }}>
            {Object.keys(SCAN_PERFIL).map((p) => (
              <button key={p} type="button" onClick={() => setPerfil(p)} style={{
                flex: 1, fontSize: 10.5, fontWeight: perfil === p ? 700 : 500, padding: "8px 4px", borderRadius: 8, cursor: "pointer",
                border: `1px solid ${perfil === p ? "var(--brand-500)" : "var(--line)"}`,
                background: perfil === p ? "var(--brand-50)" : "#fff",
                color: perfil === p ? "var(--brand-700)" : "var(--ink-soft)", fontFamily: "var(--font-body)",
              }}>{p}</button>
            ))}
          </div>
          <div style={{ fontSize: 10, color: "var(--ink-muted)", marginTop: 4 }}>{SCAN_PERFIL[perfil].d}</div>
        </div>

        {/* Criticidade */}
        <div>
          <label style={{ fontSize: 11, fontWeight: 600, color: "var(--ink-soft)", display: "block", marginBottom: 5 }}>Criticidade</label>
          <div style={{ display: "flex", gap: 4 }}>
            {["Crítica","Alta","Média","Baixa"].map((c) => (
              <button key={c} type="button" onClick={() => setCrit(c)} style={{
                flex: 1, fontSize: 10, fontWeight: crit === c ? 700 : 500, padding: "8px 2px", borderRadius: 8, cursor: "pointer",
                border: `1px solid ${crit === c ? CRIT_CSS[c].bd : "var(--line)"}`,
                background: crit === c ? CRIT_CSS[c].bg : "#fff",
                color: crit === c ? CRIT_CSS[c].c : "var(--ink-soft)", fontFamily: "var(--font-body)",
              }}>{c}</button>
            ))}
          </div>
          <div style={{ fontSize: 10, color: "var(--ink-muted)", marginTop: 4 }}>define posição na fila</div>
        </div>

        {/* Janela */}
        <div>
          <label style={{ fontSize: 11, fontWeight: 600, color: "var(--ink-soft)", display: "block", marginBottom: 5 }}>Janela</label>
          <div style={{ display: "flex", gap: 4 }}>
            {[["imediato","Agora"],["janela","22h–04h"],["agendar","Agendar"]].map(([v,l]) => (
              <button key={v} type="button" onClick={() => setJanela(v)} style={{
                flex: 1, fontSize: 10.5, fontWeight: janela === v ? 700 : 500, padding: "8px 4px", borderRadius: 8, cursor: "pointer",
                border: `1px solid ${janela === v ? "var(--brand-500)" : "var(--line)"}`,
                background: janela === v ? "var(--brand-50)" : "#fff",
                color: janela === v ? "var(--brand-700)" : "var(--ink-soft)", fontFamily: "var(--font-body)",
              }}>{l}</button>
            ))}
          </div>
          <div style={{ fontSize: 10, color: "var(--ink-muted)", marginTop: 4 }}>guardrails aplicam automaticamente</div>
        </div>

        <button className="sk-btn-primary" style={{ padding: "10px 22px", whiteSpace: "nowrap" }} disabled={submitting || !target.trim() || !accessGroupId} onClick={handleLancar}>
          {submitting ? "Lançando…" : "Lançar"}
        </button>
      </div>

      {/* Autenticação (expansível) */}
      <div style={{ marginTop: 12, paddingTop: 12, borderTop: "1px solid var(--line-soft)" }}>
        <label style={{
          marginBottom: 12,
          display: "grid",
          gridTemplateColumns: "18px minmax(0, 1fr)",
          gap: 9,
          alignItems: "start",
          cursor: "pointer",
          fontSize: 12,
          color: "var(--ink-soft)",
          lineHeight: 1.45,
        }}>
          <input
            type="checkbox"
            checked={scopeAuthorizationAttested}
            onChange={(e) => setScopeAuthorizationAttested(e.target.checked)}
            style={{ marginTop: 2 }}
          />
          <span>
            <strong style={{ color: "var(--ink)" }}>Eu autorizo a execução deste scan no escopo informado.</strong>
            {" "}Declaro que tenho permissão para testar os alvos públicos listados. Alvos locais/teste continuam liberados para validação controlada.
          </span>
        </label>
        <label style={{ display: "inline-flex", alignItems: "center", gap: 8, cursor: "pointer", fontSize: 12, color: "var(--ink-soft)" }}>
          <input type="checkbox" checked={authEnabled} onChange={(e) => setAuthEnabled(e.target.checked)} />
          Autenticação no scanner
        </label>
        {authEnabled && (
          <div style={{ marginTop: 10, display: "grid", gridTemplateColumns: "160px 1fr 1fr", gap: 10, alignItems: "end" }}>
            <select value={authConfig.type} onChange={(e) => setAuthConfig({ ...authConfig, type: e.target.value })} style={{ fontSize: 12, padding: "8px 10px", borderRadius: 8, border: "1px solid var(--line)", background: "#fff" }}>
              <option value="bearer">Bearer Token</option>
              <option value="cookie">Cookie</option>
              <option value="basic">Basic Auth</option>
              <option value="header">Header</option>
            </select>
            {authConfig.type === "bearer" && <input placeholder="eyJhbGc…" value={authConfig.token} onChange={(e) => setAuthConfig({ ...authConfig, token: e.target.value })} style={{ fontSize: 12, padding: "8px 10px", borderRadius: 8, border: "1px solid var(--line)", background: "#fff", fontFamily: "var(--font-mono)" }} />}
            {authConfig.type === "cookie" && <input placeholder="session=abc123" value={authConfig.cookie} onChange={(e) => setAuthConfig({ ...authConfig, cookie: e.target.value })} style={{ fontSize: 12, padding: "8px 10px", borderRadius: 8, border: "1px solid var(--line)", background: "#fff", fontFamily: "var(--font-mono)" }} />}
            {authConfig.type === "basic" && <>
              <input placeholder="username" value={authConfig.username} onChange={(e) => setAuthConfig({ ...authConfig, username: e.target.value })} style={{ fontSize: 12, padding: "8px 10px", borderRadius: 8, border: "1px solid var(--line)", background: "#fff" }} />
              <input type="password" placeholder="password" value={authConfig.password} onChange={(e) => setAuthConfig({ ...authConfig, password: e.target.value })} style={{ fontSize: 12, padding: "8px 10px", borderRadius: 8, border: "1px solid var(--line)", background: "#fff" }} />
            </>}
            {authConfig.type === "header" && <>
              <input placeholder="X-API-Key" value={authConfig.headerName} onChange={(e) => setAuthConfig({ ...authConfig, headerName: e.target.value })} style={{ fontSize: 12, padding: "8px 10px", borderRadius: 8, border: "1px solid var(--line)", background: "#fff", fontFamily: "var(--font-mono)" }} />
              <input placeholder="valor" value={authConfig.headerValue} onChange={(e) => setAuthConfig({ ...authConfig, headerValue: e.target.value })} style={{ fontSize: 12, padding: "8px 10px", borderRadius: 8, border: "1px solid var(--line)", background: "#fff", fontFamily: "var(--font-mono)" }} />
            </>}
          </div>
        )}
        {janela === "agendar" && (
          <div style={{ marginTop: 10, display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 10 }}>
            <div>
              <label style={{ fontSize: 11, fontWeight: 600, color: "var(--ink-soft)", display: "block", marginBottom: 5 }}>Frequência</label>
              <select value={scheduleForm.frequency} onChange={(e) => setScheduleForm({ ...scheduleForm, frequency: e.target.value })} style={{ width: "100%", fontSize: 12, padding: "8px 10px", borderRadius: 8, border: "1px solid var(--line)", background: "#fff" }}>
                <option value="daily">Diário</option>
                <option value="weekly">Semanal</option>
                <option value="monthly">Mensal</option>
              </select>
            </div>
            <div>
              <label style={{ fontSize: 11, fontWeight: 600, color: "var(--ink-soft)", display: "block", marginBottom: 5 }}>Horário</label>
              <input type="time" value={scheduleForm.run_time} onChange={(e) => setScheduleForm({ ...scheduleForm, run_time: e.target.value })} style={{ width: "100%", fontSize: 12, padding: "8px 10px", borderRadius: 8, border: "1px solid var(--line)", background: "#fff", boxSizing: "border-box" }} />
            </div>
            {scheduleForm.frequency === "weekly" && (
              <div>
                <label style={{ fontSize: 11, fontWeight: 600, color: "var(--ink-soft)", display: "block", marginBottom: 5 }}>Dia da semana</label>
                <select value={scheduleForm.day_of_week} onChange={(e) => setScheduleForm({ ...scheduleForm, day_of_week: e.target.value })} style={{ width: "100%", fontSize: 12, padding: "8px 10px", borderRadius: 8, border: "1px solid var(--line)", background: "#fff" }}>
                  {["monday","tuesday","wednesday","thursday","friday","saturday","sunday"].map((d) => <option key={d} value={d}>{d}</option>)}
                </select>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

function QualityPanel({ quality }) {
  if (!quality) {
    return (
      <div style={{ border: "1px solid var(--line)", borderRadius: 8, padding: "12px 14px", marginBottom: 14, background: "var(--surface-soft)" }}>
        <div className="sk-eyebrow" style={{ marginBottom: 6 }}>Qualidade do teste</div>
        <div style={{ fontSize: 12, color: "var(--ink-muted)" }}>Calculando cobertura, evidências e validação…</div>
      </div>
    );
  }

  const score = Math.max(0, Math.min(100, Number(quality.score || 0)));
  const gradeColor = score >= 85 ? "var(--sev-low-solid)"
    : score >= 70 ? "var(--brand-500)"
    : score >= 55 ? "var(--sev-medium-solid)"
    : "var(--sev-critical-solid)";
  const components = Object.entries(quality.components || {});
  const gaps = Array.isArray(quality.gaps) ? quality.gaps : [];
  const gate = quality.quality_gate || {};
  const runtime = quality.runtime_visibility || {};
  const gateRuntime = runtime.quality_gate || {};
  const p21 = runtime.p21_validation || {};
  const agentRuntime = runtime.agent_runtime || {};
  const gateActions = Array.isArray(gateRuntime.last_actions) ? gateRuntime.last_actions : [];
  const gateHistory = Array.isArray(gateRuntime.history) ? gateRuntime.history : [];
  const fallbackItems = Array.isArray(gateRuntime.fallback_items) ? gateRuntime.fallback_items : [];
  const p21Recent = Array.isArray(p21.recent) ? p21.recent : [];
  const llmRecent = Array.isArray(agentRuntime.recent_llm_reasoning) ? agentRuntime.recent_llm_reasoning : [];
  const mcpRecent = Array.isArray(agentRuntime.recent_mcp_contracts) ? agentRuntime.recent_mcp_contracts : [];
  const agentRecent = Array.isArray(agentRuntime.recent_agent_executions) ? agentRuntime.recent_agent_executions : [];
  const gateStatus = gate.status ? String(gate.status).replace(/_/g, " ") : "";

  return (
    <div style={{ border: "1px solid var(--line)", borderRadius: 8, padding: "13px 14px", marginBottom: 14, background: "var(--surface)" }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline", gap: 10, marginBottom: 8 }}>
        <div>
          <div className="sk-eyebrow" style={{ marginBottom: 3 }}>Qualidade do teste</div>
          <div style={{ fontSize: 12, color: "var(--ink-muted)" }}>
            {quality.profile?.label || "Perfil"} · profundidade {quality.profile?.depth || "—"}
          </div>
        </div>
        <div style={{ textAlign: "right" }}>
          <div className="sk-mono" style={{ fontSize: 24, lineHeight: 1, fontWeight: 800, color: gradeColor }}>{quality.grade || "—"}</div>
          <div className="sk-mono" style={{ fontSize: 11, color: "var(--ink-soft)", marginTop: 2 }}>{score.toFixed(1)}%</div>
        </div>
      </div>

      <div style={{ height: 7, borderRadius: 99, background: "var(--canvas-muted)", overflow: "hidden", marginBottom: 10 }}>
        <div style={{ width: `${score}%`, height: "100%", background: gradeColor, borderRadius: 99 }} />
      </div>

      {gateStatus && (
        <div style={{
          border: "1px solid var(--line-soft)", borderRadius: 8, padding: "7px 9px",
          marginBottom: 10, background: gate.status === "remediation_scheduled" ? "var(--sev-medium-bg)" : "var(--surface-soft)",
          color: gate.status === "remediation_scheduled" ? "var(--sev-medium-text)" : "var(--ink-soft)",
          fontSize: 11.5, lineHeight: 1.4,
        }}>
          Quality Gate: <strong>{gateStatus}</strong>
          {gate.rounds ? ` · rodada ${gate.rounds}` : ""}
        </div>
      )}

      {(gateActions.length > 0 || fallbackItems.length > 0 || gateHistory.length > 0) && (
        <div style={{ border: "1px solid var(--line-soft)", borderRadius: 8, padding: "9px 10px", marginBottom: 10, background: "var(--surface-soft)" }}>
          <div style={{ fontSize: 11, fontWeight: 800, color: "var(--ink-soft)", marginBottom: 7 }}>Ações do Quality Gate</div>
          {gateActions.length > 0 && (
            <div style={{ display: "grid", gap: 5, marginBottom: fallbackItems.length ? 8 : 0 }}>
              {gateActions.slice(-4).map((action, idx) => (
                <div key={`gate-action-${idx}`} style={{ display: "flex", justifyContent: "space-between", gap: 8, fontSize: 11.5, color: "var(--ink-muted)" }}>
                  <span style={{ fontWeight: 700, color: "var(--ink)" }}>{String(action.type || "ação").replace(/_/g, " ")}</span>
                  <span className="sk-mono">
                    {action.scheduled != null ? `${action.scheduled} agendado(s)` : action.requeued != null ? `${action.requeued} requeue` : ""}
                  </span>
                </div>
              ))}
            </div>
          )}
          {fallbackItems.length > 0 && (
            <div style={{ display: "grid", gap: 5 }}>
              {fallbackItems.slice(0, 4).map((item) => (
                <div key={`fallback-${item.id}`} style={{ fontSize: 11.5, color: "var(--ink-muted)", lineHeight: 1.35 }}>
                  <span className="sk-mono" style={{ color: "var(--ink)", fontWeight: 700 }}>{item.phase_id}</span>{" "}
                  {item.from || "tool"} → <strong style={{ color: "var(--ink)" }}>{item.to}</strong>
                  <span className="sk-mono" style={{ marginLeft: 6 }}>{item.status}</span>
                </div>
              ))}
            </div>
          )}
          {gateHistory.length > 0 && (
            <div style={{ marginTop: 8, display: "flex", flexWrap: "wrap", gap: 5 }}>
              {gateHistory.slice(-4).map((row, idx) => (
                <span key={`gate-history-${idx}`} className="sk-mono" style={{ fontSize: 10.5, color: "var(--ink-soft)", border: "1px solid var(--line)", borderRadius: 6, padding: "2px 5px", background: "var(--surface)" }}>
                  r{row.round}: {Number(row.score || 0).toFixed(0)}% {row.grade || ""}
                </span>
              ))}
            </div>
          )}
        </div>
      )}

      <div style={{ display: "grid", gridTemplateColumns: "repeat(2, minmax(0, 1fr))", gap: 8, marginBottom: 10 }}>
        <div style={{ border: "1px solid var(--line-soft)", borderRadius: 8, padding: "8px 9px", background: "var(--surface-soft)" }}>
          <div style={{ fontSize: 10.5, color: "var(--ink-muted)", textTransform: "uppercase", letterSpacing: "0.04em" }}>P21 validação</div>
          <div className="sk-mono" style={{ fontSize: 16, fontWeight: 800, color: "var(--ink)", marginTop: 3 }}>{p21.total || 0}</div>
          <div style={{ fontSize: 11, color: "var(--ink-muted)", marginTop: 2 }}>
            {p21.confirmed || 0} confirmados · {p21.refuted || 0} refutados · {p21.artifacts || 0} artefatos
          </div>
        </div>
        <div style={{ border: "1px solid var(--line-soft)", borderRadius: 8, padding: "8px 9px", background: "var(--surface-soft)" }}>
          <div style={{ fontSize: 10.5, color: "var(--ink-muted)", textTransform: "uppercase", letterSpacing: "0.04em" }}>Agente / MCP / LLM</div>
          <div className="sk-mono" style={{ fontSize: 16, fontWeight: 800, color: "var(--ink)", marginTop: 3 }}>{agentRuntime.llm_real_count || 0}/{agentRuntime.llm_reasoning_count || 0}</div>
          <div style={{ fontSize: 11, color: "var(--ink-muted)", marginTop: 2 }}>
            {agentRuntime.mcp_contract_count || 0} MCP · {agentRuntime.agent_success_count || 0} agentes · {agentRuntime.llm_fallback_count || 0} fallback
          </div>
        </div>
      </div>

      {(p21Recent.length > 0 || llmRecent.length > 0 || mcpRecent.length > 0 || agentRecent.length > 0) && (
        <div style={{ border: "1px solid var(--line-soft)", borderRadius: 8, padding: "9px 10px", marginBottom: 10, background: "var(--surface)" }}>
          {p21Recent.length > 0 && (
            <div style={{ marginBottom: llmRecent.length || mcpRecent.length ? 8 : 0 }}>
              <div style={{ fontSize: 11, fontWeight: 800, color: "var(--ink-soft)", marginBottom: 5 }}>Últimas validações P21</div>
              {p21Recent.slice(0, 3).map((row) => (
                <div key={`p21-${row.id}`} style={{ fontSize: 11.5, color: "var(--ink-muted)", lineHeight: 1.35 }}>
                  <span className="sk-mono" style={{ color: "var(--ink)", fontWeight: 700 }}>#{row.finding_id}</span>{" "}
                  {row.validator || "validator"} · <strong style={{ color: row.result === "confirmed" ? "var(--sev-low-text)" : "var(--sev-medium-text)" }}>{row.result}</strong>
                </div>
              ))}
            </div>
          )}
          {(llmRecent.length > 0 || mcpRecent.length > 0) && (
            <div>
              <div style={{ fontSize: 11, fontWeight: 800, color: "var(--ink-soft)", marginBottom: 5 }}>Decisão IA / MCP recente</div>
              {llmRecent.slice(-2).map((row, idx) => (
                <div key={`llm-${idx}`} style={{ fontSize: 11.5, color: "var(--ink-muted)", lineHeight: 1.35 }}>
                  LLM: <strong style={{ color: "var(--ink)" }}>{row.execution_decision || row.decision || row.action || "decisão registrada"}</strong>
                  {row.model && <span className="sk-mono" style={{ marginLeft: 6 }}>{row.model}</span>}
                </div>
              ))}
              {mcpRecent.slice(-2).map((row, idx) => (
                <div key={`mcp-${idx}`} style={{ fontSize: 11.5, color: "var(--ink-muted)", lineHeight: 1.35 }}>
                  MCP: <strong style={{ color: "var(--ink)" }}>{row.adapter || row.tool || row.skill_id || "contrato registrado"}</strong>
                </div>
              ))}
            </div>
          )}
          {agentRecent.length > 0 && (
            <div style={{ marginTop: 8 }}>
              <div style={{ fontSize: 11, fontWeight: 800, color: "var(--ink-soft)", marginBottom: 5 }}>Agentes executados</div>
              {agentRecent.slice(-3).map((row, idx) => (
                <div key={`agent-${idx}`} style={{ fontSize: 11.5, color: "var(--ink-muted)", lineHeight: 1.35 }}>
                  {row.phase_id}: <strong style={{ color: "var(--ink)" }}>{row.name || row.agent_id || "agent"}</strong>{" "}
                  <span className="sk-mono">{row.status}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      <div style={{ display: "grid", gridTemplateColumns: "repeat(2, minmax(0, 1fr))", gap: 8, marginBottom: gaps.length ? 12 : 0 }}>
        {components.map(([key, item]) => (
          <div key={key} style={{ border: "1px solid var(--line-soft)", borderRadius: 8, padding: "8px 9px", background: "var(--surface-soft)" }}>
            <div style={{ display: "flex", justifyContent: "space-between", gap: 6, alignItems: "baseline" }}>
              <span style={{ fontSize: 10.5, color: "var(--ink-muted)", textTransform: "uppercase", letterSpacing: "0.04em" }}>
                {key.replace(/_/g, " ")}
              </span>
              <b className="sk-mono" style={{ fontSize: 12, color: "var(--ink)" }}>{Number(item.score || 0).toFixed(0)}%</b>
            </div>
            <div style={{ height: 4, borderRadius: 99, background: "var(--canvas-muted)", overflow: "hidden", marginTop: 6 }}>
              <div style={{ width: `${Math.max(0, Math.min(100, Number(item.score || 0)))}%`, height: "100%", background: Number(item.score || 0) >= 70 ? "var(--sev-low-solid)" : "var(--sev-medium-solid)" }} />
            </div>
          </div>
        ))}
      </div>

      {gaps.length > 0 && (
        <div>
          <div style={{ fontSize: 11, fontWeight: 700, color: "var(--ink-soft)", marginBottom: 6 }}>Gaps principais</div>
          <div style={{ display: "grid", gap: 6 }}>
            {gaps.slice(0, 4).map((gap, idx) => (
              <div key={`${gap.area}-${idx}`} style={{ borderLeft: `3px solid ${gap.severity === "high" ? "var(--sev-critical-solid)" : gap.severity === "medium" ? "var(--sev-medium-solid)" : "var(--line)"}`, paddingLeft: 8 }}>
                <div style={{ fontSize: 12, fontWeight: 700, color: "var(--ink)" }}>{gap.title}</div>
                <div style={{ fontSize: 11.5, color: "var(--ink-muted)", lineHeight: 1.45 }}>{gap.action}</div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

// ─── Painel de detalhe lateral ────────────────────────────────────────────────
function DetailPanel({ scan, logs, onClose }) {
  const [phases, setPhases] = useState([]);
  const [breakdown, setBreakdown] = useState(null);
  const [quality, setQuality] = useState(null);
  const [progress, setProgress] = useState(scan?.mission_progress ?? 0);

  useEffect(() => {
    if (!scan?.id) return;
    let cancelled = false;
    setQuality(null);
    const load = async () => {
      try {
        const { data } = await client.get(`/api/scans/${scan.id}/phase-monitor`, { _skipToast: true });
        if (cancelled) return;
        if (Array.isArray(data?.phases)) setPhases(data.phases);
        if (data?.mission_progress != null) setProgress(data.mission_progress);
      } catch { /* silencioso */ }
      try {
        const { data } = await client.get(`/api/scans/${scan.id}/phase-breakdown`, { _skipToast: true });
        if (!cancelled && data?.phases) setBreakdown(data);
      } catch { /* silencioso */ }
      try {
        const { data } = await client.get(`/api/scans/${scan.id}/quality`, { _skipToast: true });
        if (!cancelled) setQuality(data || null);
      } catch { /* silencioso */ }
    };
    load();
    const isLive = ["queued","running","retrying"].includes(scan.status);
    const t = isLive ? setInterval(load, 5000) : null;
    return () => { cancelled = true; if (t) clearInterval(t); };
  }, [scan?.id, scan?.status]);

  if (!scan) return null;

  const pct = Math.max(0, Math.min(100, Number(progress || 0)));
  const isLive = ["queued","running","retrying"].includes(scan.status);

  const STATUS_BAR = {
    executed:                     "var(--sev-low-solid)",
    partial_coverage:             "var(--sev-medium-solid)",
    attempted_failed:             "var(--sev-critical-solid)",
    node_completed_tools_skipped: "var(--sev-info-solid)",
    no_tools_installed:           "var(--line)",
    node_completed_no_phase_tools:"var(--sev-high-solid)",
    node_visited_no_tools:        "var(--sev-info-solid)",
    pending:                      "var(--canvas-muted)",
    skipped:                      "var(--canvas-muted)",
  };
  const STATUS_LABEL = {
    executed: "OK", partial_coverage: "parcial", attempted_failed: "falhou",
    node_completed_tools_skipped: "pulada", no_tools_installed: "sem tool",
    node_visited_no_tools: "visitada", pending: "—", skipped: "—",
  };

  // Usa breakdown detalhado se disponível, senão usa phase-monitor
  const rows = breakdown?.phases?.length
    ? breakdown.phases.map((p) => ({
        id:     p.phase_id,
        label:  p.phase_id,
        status: p.status,
        pct:    p.pct ?? 0,
        ok:     p.completed ?? 0,
        fail:   (p.failed ?? 0) + (p.timeout ?? 0),
        total:  p.total ?? 0,
      }))
    : phases.slice(0, 22).map((p) => ({
        id:    p.id,
        label: p.id,
        status: p.status,
        pct:   p.status === "executed" ? 100 : p.status === "pending" || p.status === "skipped" ? 0 : 50,
        ok:    0, fail: 0, total: 0,
      }));

  return (
    /* overlay semitransparente */
    <div
      onClick={(e) => { if (e.target === e.currentTarget) onClose(); }}
      style={{ position: "fixed", inset: 0, zIndex: 100, background: "rgba(0,0,0,0.28)", display: "flex", justifyContent: "flex-end" }}
    >
      {/* drawer */}
      <div style={{
        width: "min(480px, 92vw)", height: "100vh", background: "var(--bg-main)",
        borderLeft: "1px solid var(--line)", display: "flex", flexDirection: "column",
        boxShadow: "-4px 0 24px rgba(0,0,0,.14)",
      }}>
        {/* cabeçalho */}
        <div style={{ padding: "18px 20px 14px", borderBottom: "1px solid var(--line-soft)", flexShrink: 0 }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 10 }}>
            <div>
              <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 4 }}>
                <span className="sk-mono" style={{ fontSize: 15, fontWeight: 700 }}>#{scan.id}</span>
                <StatusDot status={scan.status} />
              </div>
              <div className="sk-mono" style={{ fontSize: 11.5, color: "var(--ink-soft)" }}>{scan.target_query}</div>
            </div>
            <button onClick={onClose} style={{ border: "none", background: "transparent", fontSize: 18, cursor: "pointer", color: "var(--ink-muted)", padding: "0 4px", lineHeight: 1 }}>✕</button>
          </div>
          {/* barra de progresso */}
          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <div style={{ flex: 1, height: 7, borderRadius: 99, background: "var(--canvas-muted)", overflow: "hidden" }}>
              <div style={{ width: `${pct}%`, height: "100%", background: isLive ? "var(--brand-500)" : "var(--sev-low-solid)", borderRadius: 99, transition: "width .5s" }} />
            </div>
            <span className="sk-mono" style={{ fontSize: 13, fontWeight: 700, flexShrink: 0 }}>{pct}%</span>
          </div>
        </div>

        {/* fases */}
        <div style={{ flex: 1, overflowY: "auto", padding: "14px 20px" }}>
          <QualityPanel quality={quality} />

          {rows.length === 0 ? (
            <div style={{ textAlign: "center", color: "var(--ink-muted)", fontSize: 12, padding: "32px 0" }}>Aguardando dados das fases…</div>
          ) : (
            <div style={{ display: "flex", flexDirection: "column", gap: 0 }}>
              {rows.map((r) => {
                const bar = STATUS_BAR[r.status] || "var(--canvas-muted)";
                const lbl = STATUS_LABEL[r.status] ?? r.status;
                const hasPct = r.total > 0;
                return (
                  <div key={r.id} style={{ display: "grid", gridTemplateColumns: "36px 1fr 40px 56px", gap: 8, alignItems: "center", padding: "5px 0", borderBottom: "1px solid var(--line-soft)" }}>
                    {/* id */}
                    <span className="sk-mono" style={{ fontSize: 9.5, fontWeight: 700, color: bar === "var(--canvas-muted)" ? "var(--ink-muted)" : "var(--ink)", background: "var(--surface-soft)", border: "1px solid var(--line)", borderRadius: 4, padding: "2px 3px", textAlign: "center" }}>{r.label}</span>
                    {/* barra */}
                    <div style={{ height: 5, borderRadius: 99, background: "var(--canvas-muted)", overflow: "hidden" }}>
                      <div style={{ width: `${hasPct ? r.pct : r.status === "executed" ? 100 : r.status === "pending" || r.status === "skipped" ? 0 : 45}%`, height: "100%", background: bar, borderRadius: 99, transition: "width .5s" }} />
                    </div>
                    {/* % */}
                    <span className="sk-mono" style={{ fontSize: 9.5, color: "var(--ink-muted)", textAlign: "right" }}>
                      {hasPct ? `${r.pct}%` : ""}
                    </span>
                    {/* status */}
                    <span style={{ fontSize: 9.5, fontWeight: 700, textAlign: "right", color: bar === "var(--canvas-muted)" ? "var(--ink-muted)" : "var(--ink-soft)" }}>{lbl}</span>
                  </div>
                );
              })}
            </div>
          )}

          {/* logs */}
          {logs.length > 0 && (
            <div style={{ marginTop: 16 }}>
              <div className="sk-eyebrow" style={{ marginBottom: 8 }}>Logs recentes</div>
              <div style={{ border: "1px solid var(--line)", borderRadius: 8, overflow: "hidden" }}>
                <LogTerminal logs={logs} />
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// ─── Modal de edição de agendamento ──────────────────────────────────────────
function EditScheduleModal({ schedule, groups, onSave, onClose }) {
  const [form, setForm] = useState({
    targets_text:    schedule.targets_text || schedule.target_query || "",
    scan_type:       schedule.scan_type   || schedule.level        || "full",
    access_group_id: schedule.access_group_id ?? "",
    frequency:       schedule.frequency   || "daily",
    run_time:        schedule.run_time    || "00:00",
    day_of_week:     schedule.day_of_week || "monday",
    day_of_month:    schedule.day_of_month || 1,
    enabled:         schedule.enabled !== false,
  });

  const set = (k, v) => setForm((f) => ({ ...f, [k]: v }));

  const handleGroupChange = (e) => {
    const id = e.target.value;
    const g  = groups.find((g) => String(g.id) === String(id));
    set("access_group_id",   id);
    set("access_group_name", g?.name || "");
  };

  const handleSave = () => {
    if (!form.access_group_id) return;
    const payload = {
      targets_text: form.targets_text.trim(),
      scan_type:    form.scan_type,
      frequency:    form.frequency,
      run_time:     form.run_time,
      enabled:      form.enabled,
    };
    if (form.frequency === "weekly")  payload.day_of_week  = form.day_of_week;
    if (form.frequency === "monthly") payload.day_of_month = Number(form.day_of_month);
    if (form.access_group_id !== "" && form.access_group_id !== null) {
      payload.access_group_id = Number(form.access_group_id);
    }
    onSave(payload);
  };

  const inputStyle = { width: "100%", boxSizing: "border-box", fontSize: 12, padding: "8px 10px", borderRadius: 8, border: "1px solid var(--line)", background: "#fff", fontFamily: "var(--font-body)" };
  const labelStyle = { fontSize: 11, fontWeight: 600, color: "var(--ink-soft)", display: "block", marginBottom: 5 };

  return (
    <div style={{ position: "fixed", inset: 0, zIndex: 200, background: "rgba(0,0,0,0.35)", display: "grid", placeItems: "center", padding: 24 }}
      onClick={(e) => { if (e.target === e.currentTarget) onClose(); }}>
      <div className="sk-panel" style={{ width: "100%", maxWidth: 540, padding: "22px 24px", boxShadow: "0 8px 40px rgba(0,0,0,.22)" }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 18 }}>
          <div>
            <div style={{ fontSize: 14, fontWeight: 700 }}>Editar agendamento <span className="sk-mono" style={{ fontSize: 12, color: "var(--ink-muted)" }}>#{schedule.id}</span></div>
            {schedule.access_group_id && (
              <div style={{ fontSize: 11, color: "var(--ink-muted)", marginTop: 2 }}>
                Grupo: {groups.find((g) => Number(g.id) === Number(schedule.access_group_id))?.name || `#${schedule.access_group_id}`}
              </div>
            )}
          </div>
          <button onClick={onClose} style={{ border: "none", background: "transparent", color: "var(--ink-muted)", fontSize: 18, cursor: "pointer" }}>✕</button>
        </div>

        <div style={{ display: "grid", gap: 14 }}>
          {/* Alvo */}
          <div>
            <label style={labelStyle}>Escopo / alvo</label>
            <input className="sk-mono" value={form.targets_text} onChange={(e) => set("targets_text", e.target.value)} style={{ ...inputStyle, fontFamily: "var(--font-mono)" }} />
          </div>

          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 14 }}>
            {/* Grupo */}
            <div>
              <label style={labelStyle}>Grupo de acesso</label>
              <select value={form.access_group_id} onChange={handleGroupChange} style={inputStyle}>
                <option value="">Selecione a empresa</option>
                {groups.map((g) => <option key={g.id} value={g.id}>{g.name}</option>)}
              </select>
            </div>

            {/* Perfil */}
            <div>
              <label style={labelStyle}>Perfil</label>
              <select value={form.scan_type} onChange={(e) => set("scan_type", e.target.value)} style={inputStyle}>
                <option value="asm">Recon</option>
                <option value="full">Padrão</option>
                <option value="aggressive">Agressivo</option>
              </select>
            </div>

            {/* Frequência */}
            <div>
              <label style={labelStyle}>Frequência</label>
              <select value={form.frequency} onChange={(e) => set("frequency", e.target.value)} style={inputStyle}>
                {["daily","weekly","monthly","once"].map((f) => <option key={f} value={f}>{f}</option>)}
              </select>
            </div>

            {/* Horário */}
            <div>
              <label style={labelStyle}>Horário (HH:MM)</label>
              <input type="time" value={form.run_time} onChange={(e) => set("run_time", e.target.value)} style={inputStyle} />
            </div>

            {/* Dia da semana — weekly */}
            {form.frequency === "weekly" && (
              <div>
                <label style={labelStyle}>Dia da semana</label>
                <select value={form.day_of_week} onChange={(e) => set("day_of_week", e.target.value)} style={inputStyle}>
                  {["monday","tuesday","wednesday","thursday","friday","saturday","sunday"].map((d) => <option key={d} value={d}>{d}</option>)}
                </select>
              </div>
            )}

            {/* Dia do mês — monthly */}
            {form.frequency === "monthly" && (
              <div>
                <label style={labelStyle}>Dia do mês</label>
                <input type="number" min={1} max={28} value={form.day_of_month} onChange={(e) => set("day_of_month", e.target.value)} style={inputStyle} />
              </div>
            )}
          </div>

          {/* Ativo */}
          <label style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 12.5, fontWeight: 500, cursor: "pointer" }}>
            <input type="checkbox" checked={form.enabled} onChange={(e) => set("enabled", e.target.checked)}
              style={{ width: 15, height: 15, cursor: "pointer" }} />
            Agendamento ativo
          </label>
        </div>

        <div style={{ display: "flex", gap: 8, marginTop: 20, justifyContent: "flex-end" }}>
          <button className="sk-btn-ghost" onClick={onClose} style={{ padding: "8px 18px", fontSize: 12.5 }}>Cancelar</button>
          <button className="sk-btn-primary" onClick={handleSave} style={{ padding: "8px 22px", fontSize: 12.5 }}>Salvar</button>
        </div>
      </div>
    </div>
  );
}

// ─── Main page ────────────────────────────────────────────────────────────────
export default function ScansPage() {
  const [scans,     setScans]     = useState([]);
  const [schedules, setSchedules] = useState([]);
  const [groups,    setGroups]    = useState([]);
  const [composer,  setComposer]  = useState(false);
  const [statusMsg, setStatusMsg] = useState("");
  const [selected,  setSelected]  = useState(null);
  const [logs,      setLogs]      = useState([]);
  const [scanStatus, setScanStatus] = useState({});
  const [filaOrder,    setFilaOrder]    = useState([]);
  const [editSchedule, setEditSchedule] = useState(null); // schedule being edited

  // Split scans by lifecycle
  const activeScans   = scans.filter((s) => [...ACTIVE_STATUS, "paused", "blocked", "stopped", "failed"].includes(s.status));
  const terminalScans = scans.filter((s) => ["completed", "cancelled"].includes(s.status));
  const runningCount  = scans.filter((s) => ACTIVE_STATUS.includes(s.status)).length;
  const blockedCount  = scans.filter((s) => s.status === "blocked").length;

  // ── API calls ─────────────────────────────────────────────────────────────
  const loadScans = useCallback(async () => {
    try {
      const { data } = await client.get("/api/scans");
      setScans(Array.isArray(data) ? data : []);
    } catch { /* silencioso */ }
  }, []);

  const loadSchedules = useCallback(async () => {
    try {
      const { data } = await client.get("/api/schedules");
      const list = Array.isArray(data) ? data : [];
      setSchedules(list);
      setFilaOrder(list.map((s) => s.id));
    } catch { /* silencioso */ }
  }, []);

  const loadGroups = useCallback(async () => {
    try {
      const { data } = await client.get("/api/access-groups");
      setGroups(Array.isArray(data) ? data : []);
    } catch { /* silencioso */ }
  }, []);

  useEffect(() => {
    loadScans(); loadSchedules(); loadGroups();
    const id = setInterval(loadScans, 3000);
    return () => clearInterval(id);
  }, [loadScans, loadSchedules, loadGroups]);

  // ── WebSocket logs ────────────────────────────────────────────────────────
  useEffect(() => {
    if (!selected) { setLogs([]); return; }
    const wsBase = getWsBaseUrl();
    let ws, retries = 0, timer;
    const connect = () => {
      ws = new WebSocket(`${wsBase}/ws/scans/${selected.id}/logs`);
      ws.onmessage = (e) => {
        try { const msg = JSON.parse(e.data); setLogs((prev) => [...prev.slice(-999), msg]); } catch { /* skip */ }
      };
      ws.onerror = () => ws.close();
      ws.onclose = () => {
        if (retries < 5) { retries++; timer = setTimeout(connect, Math.min(1000 * retries, 8000)); }
      };
    };
    connect();
    return () => { clearTimeout(timer); ws?.close(); };
  }, [selected?.id]);

  // ── Handlers ──────────────────────────────────────────────────────────────
  const showMsg = (m) => { setStatusMsg(m); setTimeout(() => setStatusMsg(""), 4000); };

  const createScan = async ({ target, scanLevel, accessGroupId, accessGroupName, scopeAuthorizationAttested, authPayload }) => {
    const targets = String(target).split(";").map((t) => t.trim()).filter(Boolean);
    for (const tgt of targets) {
      const payload = { target_query: tgt, scan_level: scanLevel || "full" };
      if (accessGroupId)   payload.access_group_id   = Number(accessGroupId);
      if (accessGroupName) payload.access_group_name = accessGroupName;
      payload.scope_authorization_attested = Boolean(scopeAuthorizationAttested);
      if (authPayload)     payload.auth_config        = authPayload;
      await client.post("/api/scans", payload);
    }
    showMsg("Missão lançada com sucesso!");
    setComposer(false);
    loadScans();
  };

  const createSchedule = async ({ target, accessGroupId, accessGroupName, scheduleForm }) => {
    const payload = { targets_text: target.trim(), ...scheduleForm };
    if (accessGroupId)   payload.access_group_id   = Number(accessGroupId);
    if (accessGroupName) payload.access_group_name = accessGroupName;
    await client.post("/api/schedules", payload);
    showMsg("Agendamento criado com sucesso!");
    setComposer(false);
    loadSchedules();
  };

  const deleteSchedule = async (id) => {
    await client.delete(`/api/schedules/${id}`);
    loadSchedules();
  };

  const updateSchedule = async (id, payload) => {
    await client.patch(`/api/schedules/${id}`, payload);
    setEditSchedule(null);
    showMsg("Agendamento atualizado!");
    loadSchedules();
  };

  const runScheduleNow = async (id) => {
    await client.post(`/api/schedules/${id}/run-now`);
    loadScans();
  };

  const stopScan = async (id) => {
    await client.post(`/api/scans/${id}/stop`);
    loadScans();
  };

  const pauseScan = async (id) => {
    await client.post(`/api/scans/${id}/pause`);
    loadScans();
  };

  const resumeScan = async (id) => {
    await client.post(`/api/scans/${id}/resume`);
    loadScans();
  };

  const removeScan = async (id) => {
    await client.delete(`/api/scans/${id}`);
    if (selected?.id === id) setSelected(null);
    loadScans();
  };

  const removeReport = async (id) => {
    await client.delete(`/api/scans/${id}/report`);
    loadScans();
  };

  const moverPrioridade = (id, dir) => {
    setFilaOrder((prev) => {
      const arr = [...prev];
      const i = arr.indexOf(id);
      const j = i + dir;
      if (j < 0 || j >= arr.length) return arr;
      [arr[i], arr[j]] = [arr[j], arr[i]];
      return arr;
    });
  };

  const sortedSchedules = filaOrder.length
    ? filaOrder.map((id) => schedules.find((s) => s.id === id)).filter(Boolean)
    : schedules;

  return (
    <div style={{ padding: "26px 32px 48px" }}>
      {/* ── Cabeçalho ── */}
      <div style={{ display: "flex", alignItems: "flex-end", justifyContent: "space-between", gap: 16, marginBottom: 18 }}>
        <div>
          <div className="sk-eyebrow" style={{ marginBottom: 4 }}>Orquestração de scans · RedTeam</div>
          <h2 style={{ margin: 0, fontSize: 21, fontWeight: 700, letterSpacing: "-0.02em" }}>Missões</h2>
        </div>
        <button className="sk-btn-primary" onClick={() => setComposer(true)}>+ Nova missão</button>
      </div>

      {/* ── Compositor inline ── */}
      {composer && (
        <NovoScanComposer
          groups={groups}
          statusMsg={statusMsg}
          onClose={() => { setComposer(false); setStatusMsg(""); }}
          onCreate={createScan}
          onSchedule={createSchedule}
        />
      )}

      {/* ── Scans ativos ── */}
      {activeScans.length > 0 && (
        <div style={{ marginBottom: 28 }}>
          <div className="sk-eyebrow" style={{ marginBottom: 10 }}>
            Em execução · {runningCount} rodando{blockedCount > 0 ? ` · ${blockedCount} bloqueada` : ""}
            {" "}· <span style={{ color: "var(--sev-medium-text)", fontStyle: "normal" }}>Pause/Stop habilitados por missão</span>
          </div>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(3, minmax(0, 1fr))", gap: 14 }}>
            {activeScans.map((s) => (
              <ActiveScanCard
                key={s.id} scan={s}
                onStop={stopScan} onPause={pauseScan} onResume={resumeScan}
                onContinue={resumeScan} onDelete={removeScan} onReport={removeReport}
                onClick={() => setSelected(selected?.id === s.id ? null : s)}
              />
            ))}
          </div>
          {selected && !TERMINAL_STATUS.has(selected.status) && (
            <DetailPanel scan={selected} logs={logs} onClose={() => setSelected(null)} />
          )}
        </div>
      )}

      {/* ── Modal de edição de schedule ── */}
      {editSchedule && (
        <EditScheduleModal
          schedule={editSchedule}
          groups={groups}
          onSave={(payload) => updateSchedule(editSchedule.id, payload)}
          onClose={() => setEditSchedule(null)}
        />
      )}

      {/* ── Fila + Histórico ── */}
      {/* minmax(0,…) impede o blowout do grid (1fr=minmax(auto,1fr) cresce além
          do container quando o conteúdo é largo → cortava a parte direita). */}
      <div style={{ display: "grid", gridTemplateColumns: "minmax(0, 1fr) minmax(0, 1.5fr)", gap: 16, marginBottom: 28 }}>
        {/* Fila priorizada */}
        <div>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 10 }}>
            <div className="sk-eyebrow">Fila · ordem de execução</div>
            <span style={{ fontSize: 10.5, color: "var(--ink-muted)" }}>↑↓ reordena · clique ✎ para editar</span>
          </div>
          <div className="sk-panel" style={{ overflow: "hidden" }}>
            {sortedSchedules.length === 0 ? (
              <div style={{ padding: "32px 16px", textAlign: "center", color: "var(--ink-muted)", fontSize: 13 }}>
                Nenhum scan agendado
              </div>
            ) : sortedSchedules.map((f, i) => (
              <div key={f.id} style={{ display: "flex", gap: 8, padding: "11px 16px", borderBottom: i < sortedSchedules.length - 1 ? "1px solid var(--line-soft)" : "none", alignItems: "center" }}>
                {/* nº */}
                <span className="sk-mono" style={{ fontSize: 15, fontWeight: 700, color: i === 0 ? "var(--brand-600)" : "var(--ink-muted)", width: 22, flexShrink: 0, textAlign: "center" }}>{i + 1}</span>
                {/* info */}
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 3, flexWrap: "wrap" }}>
                    <span className="sk-mono" style={{ fontSize: 12, fontWeight: 700 }}>#{f.id}</span>
                    {/* grupo — destaque primário */}
                    {(() => {
                      const gName = groups.find((g) => Number(g.id) === Number(f.access_group_id))?.name
                        || (f.access_group_id ? `grupo #${f.access_group_id}` : null);
                      return gName ? (
                        <span style={{ fontSize: 10, fontWeight: 700, color: "var(--sev-info-text)", background: "var(--sev-info-bg)", border: "1px solid var(--sev-info-border)", padding: "2px 7px", borderRadius: 99 }}>
                          {gName}
                        </span>
                      ) : (
                        <span style={{ fontSize: 10, fontWeight: 600, color: "var(--sev-critical-text)" }}>empresa não definida</span>
                      );
                    })()}
                    <PerfilBadge perfil={LEVEL_MAP[f.scan_type] || LEVEL_MAP[f.level] || "Padrão"} />
                    {f.enabled === false && (
                      <span style={{ fontSize: 9.5, fontWeight: 700, color: "var(--sev-medium-text)", background: "var(--sev-medium-bg)", border: "1px solid var(--sev-medium-border)", padding: "1px 6px", borderRadius: 99 }}>PAUSADO</span>
                    )}
                  </div>
                  <div className="sk-mono" style={{ fontSize: 11, color: "var(--ink-soft)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{f.targets_text || f.target_query}</div>
                  <div style={{ fontSize: 10, color: "var(--ink-muted)", marginTop: 2 }}>
                    {f.frequency}{f.run_time ? ` · ${f.run_time}` : ""}{f.day_of_week ? ` · ${f.day_of_week}` : ""}
                  </div>
                </div>
                {/* reordenar */}
                <div style={{ display: "flex", flexDirection: "column", gap: 2, flexShrink: 0 }}>
                  <button onClick={() => moverPrioridade(f.id, -1)} disabled={i === 0} style={{ width: 20, height: 18, border: "1px solid var(--line)", borderRadius: 4, background: "#fff", cursor: i === 0 ? "default" : "pointer", color: i === 0 ? "var(--line)" : "var(--ink-soft)", fontSize: 9, display: "grid", placeItems: "center" }}>↑</button>
                  <button onClick={() => moverPrioridade(f.id, 1)} disabled={i === sortedSchedules.length - 1} style={{ width: 20, height: 18, border: "1px solid var(--line)", borderRadius: 4, background: "#fff", cursor: i === sortedSchedules.length - 1 ? "default" : "pointer", color: i === sortedSchedules.length - 1 ? "var(--line)" : "var(--ink-soft)", fontSize: 9, display: "grid", placeItems: "center" }}>↓</button>
                </div>
                {/* ações — flexShrink:0 garante que nunca são cortadas (o texto do alvo encolhe) */}
                <button onClick={() => setEditSchedule(f)} title="Editar" style={{ flexShrink: 0, fontSize: 11, padding: "4px 7px", borderRadius: 6, border: "1px solid var(--line)", background: "#fff", color: "var(--ink-soft)", cursor: "pointer" }}>✎</button>
                <button onClick={() => runScheduleNow(f.id)} title="Executar agora" style={{ flexShrink: 0, fontSize: 10, fontWeight: 700, padding: "4px 8px", borderRadius: 6, border: "1px solid var(--brand-300)", background: "var(--brand-50)", color: "var(--brand-700)", cursor: "pointer" }}>▶</button>
                <button onClick={() => deleteSchedule(f.id)} title="Excluir" style={{ flexShrink: 0, fontSize: 10, fontWeight: 700, padding: "4px 8px", borderRadius: 6, border: "1px solid var(--sev-critical-border)", background: "var(--sev-critical-bg)", color: "var(--sev-critical-text)", cursor: "pointer" }}>✕</button>
              </div>
            ))}
          </div>
        </div>

        {/* Histórico */}
        <div>
          <div className="sk-eyebrow" style={{ marginBottom: 10 }}>Histórico · missões concluídas</div>
          <div className="sk-panel" style={{ overflow: "hidden" }}>
            {terminalScans.length === 0 ? (
              <div style={{ padding: "32px 16px", textAlign: "center", color: "var(--ink-muted)", fontSize: 13 }}>
                Nenhuma missão concluída ainda
              </div>
            ) : (
              <table style={{ width: "100%", borderCollapse: "collapse" }}>
                <thead>
                  <tr style={{ background: "var(--surface-soft)" }}>
                    <th className="sk-th" style={{ paddingLeft: 16 }}>Missão</th>
                    <th className="sk-th">Perfil</th>
                    <th className="sk-th">Concluída</th>
                    <th className="sk-th" style={{ textAlign: "right" }}>Dur.</th>
                    <th className="sk-th" style={{ textAlign: "right" }}>C</th>
                    <th className="sk-th" style={{ textAlign: "right" }}>A</th>
                    <th className="sk-th" style={{ textAlign: "right" }}>M</th>
                    <th className="sk-th" style={{ textAlign: "right" }}>B</th>
                    <th className="sk-th" style={{ textAlign: "right", paddingRight: 16 }}></th>
                  </tr>
                </thead>
                <tbody>
                  {terminalScans.map((h) => (
                    <tr key={h.id}
                      onMouseEnter={(e) => e.currentTarget.style.background = "var(--surface-soft)"}
                      onMouseLeave={(e) => e.currentTarget.style.background = "transparent"}
                      onClick={() => setSelected(selected?.id === h.id ? null : h)}
                      style={{ cursor: "pointer" }}>
                      <td className="sk-td" style={{ paddingLeft: 16 }}>
                        <span className="sk-mono" style={{ fontWeight: 700 }}>#{h.id}</span>
                        <span className="sk-mono" style={{ fontSize: 11, color: "var(--ink-muted)", marginLeft: 8 }}>{String(h.target_query||"").slice(0,30)}</span>
                      </td>
                      <td className="sk-td"><PerfilBadge perfil={getPerfil(h)} /></td>
                      <td className="sk-td sk-mono" style={{ fontSize: 11, color: "var(--ink-muted)" }}>{fmtDateSP(h.finished_at || h.updated_at)}</td>
                      <td className="sk-td sk-mono" style={{ textAlign: "right" }}>{fmtDuration(h.started_at, h.finished_at)}</td>
                      <td className="sk-td sk-mono" style={{ textAlign: "right", fontWeight: 700, color: h.open_critical > 0 ? "var(--sev-critical-text)" : "var(--ink-muted)" }}>{h.open_critical||0}</td>
                      <td className="sk-td sk-mono" style={{ textAlign: "right", fontWeight: 700, color: h.open_high > 0 ? "var(--sev-high-text)" : "var(--ink-muted)" }}>{h.open_high||0}</td>
                      <td className="sk-td sk-mono" style={{ textAlign: "right", color: "var(--ink-muted)" }}>{h.open_medium||0}</td>
                      <td className="sk-td sk-mono" style={{ textAlign: "right", color: "var(--ink-muted)" }}>{h.open_low||0}</td>
                      <td className="sk-td" style={{ textAlign: "right", paddingRight: 16 }}>
                        <button
                          title="Excluir missão (remove scan, vulnerabilidades e ativos da superfície de ataque)"
                          onClick={(e) => {
                            e.stopPropagation();
                            if (window.confirm(
                              `Excluir a missão #${h.id} (${String(h.target_query||"").slice(0,40)})?\n\n` +
                              `Isto remove permanentemente:\n` +
                              `• o scan e seu histórico\n` +
                              `• as vulnerabilidades encontradas\n` +
                              `• os ativos/alvos na Superfície de ataque deste scan\n\n` +
                              `Esta ação não pode ser desfeita.`
                            )) {
                              removeScan(h.id);
                            }
                          }}
                          style={{
                            flexShrink: 0, fontSize: 10, fontWeight: 700, padding: "4px 9px",
                            borderRadius: 6, border: "1px solid var(--sev-critical-border)",
                            background: "var(--sev-critical-bg)", color: "var(--sev-critical-text)",
                            cursor: "pointer",
                          }}>
                          Excluir
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
          <div style={{ marginTop: 8, fontSize: 11, color: "var(--ink-muted)", lineHeight: 1.55 }}>
            C = Crítico · A = Alto · M = Médio · B = Baixo · clique numa linha para ver detalhes
          </div>
          {selected && TERMINAL_STATUS.has(selected.status) && (
            <DetailPanel scan={selected} logs={logs} onClose={() => setSelected(null)} />
          )}
        </div>
      </div>

      {/* ── Estado vazio ── */}
      {scans.length === 0 && !composer && (
        <div style={{ textAlign: "center", padding: "64px 0", color: "var(--ink-muted)" }}>
          <div style={{ fontSize: 32, marginBottom: 12 }}>🎯</div>
          <div style={{ fontSize: 16, fontWeight: 600, marginBottom: 8 }}>Nenhuma missão ativa</div>
          <div style={{ fontSize: 13, marginBottom: 20 }}>Lance o primeiro scan para começar.</div>
          <button className="sk-btn-primary" onClick={() => setComposer(true)}>+ Nova missão</button>
        </div>
      )}
    </div>
  );
}
