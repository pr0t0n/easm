import { useState, useEffect, useCallback } from "react";
import client from "../api/client";

/* ── Paleta TV wall (idêntica ao protótipo) ── */
const TV = {
  bg:       "#1f242c",
  surface:  "#262c36",
  surface2: "#2d343f",
  border:   "#2f3743",
  text:     "#e8eaed",
  muted:    "#8a93a3",
  label:    "#6b7384",
};

const SEV_LABEL = { critical: "Crítico", high: "Alto", medium: "Médio", low: "Baixo" };

const FRAMEWORKS = [
  { nome: "MITRE ATT&CK", cobertura: 59, risco: 72, tecnicos: 38, total: 64, gaps: ["T1203 parcial", "T1078 confirmado"], cor: "214,69,69" },
  { nome: "NIST CSF",     cobertura: 48, risco: 61, tecnicos: 12, total: 25, gaps: ["PR.AC-5 exposto", "DE.AE-3 gap"],    cor: "254,123,2" },
  { nome: "ISO 27001",    cobertura: 54, risco: 55, tecnicos: 22, total: 41, gaps: ["A.12.6.1 aberto", "A.14.2.8 gap"],  cor: "212,165,0" },
  { nome: "PCI DSS 4.0",  cobertura: 61, risco: 84, tecnicos: 9,  total: 14, gaps: ["Req 6.4 crítico", "Req 11.3 gap"],  cor: "214,69,69" },
  { nome: "CIS Controls", cobertura: 67, risco: 54, tecnicos: 12, total: 18, gaps: ["CIS-7 parcial", "CIS-12 ok"],       cor: "34,145,96" },
];

/* ── Atoms ── */
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

function Spark({ data, color = "#7fe0b0" }) {
  const mx = Math.max(...data, 1);
  const pts = data.map((v, i) => `${(i / (data.length - 1)) * 100},${18 - (v / mx) * 16 - 1}`).join(" ");
  return (
    <svg viewBox="0 0 100 18" style={{ width: "100%", height: 18 }} preserveAspectRatio="none">
      <polyline points={pts} fill="none" stroke={color} strokeWidth="1.5" />
    </svg>
  );
}

function EsteiraView({ esteira }) {
  return (
    <div style={{ display: "flex", alignItems: "stretch", gap: 0 }}>
      {esteira.map((c, i) => (
        <span key={c.nome} style={{ display: "contents" }}>
          <div style={{
            flex: 1, padding: "10px 12px", borderRadius: 10, minWidth: 0,
            background: i === esteira.length - 1 ? "rgba(233,99,99,0.16)" : TV.surface2,
            border: `1px solid ${i === esteira.length - 1 ? "rgba(233,99,99,0.45)" : TV.border}`,
          }}>
            <div style={{ fontFamily: "var(--font-mono)", fontSize: 24, fontWeight: 700, color: i === esteira.length - 1 ? "#ff8a8a" : TV.text, lineHeight: 1 }}>{c.qtd}</div>
            <div style={{ fontSize: 10.5, fontWeight: 700, color: TV.text, marginTop: 6 }}>{c.nome}</div>
            <div style={{ fontSize: 9.5, color: TV.muted }}>{c.sub}</div>
          </div>
          {c.conv !== null && c.conv !== undefined && (
            <div style={{ width: 44, flexShrink: 0, display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center" }}>
              <span style={{ fontFamily: "var(--font-mono)", fontSize: 10.5, fontWeight: 700, color: c.conv >= 60 ? "#7fe0b0" : TV.muted }}>{c.conv}%</span>
              <span style={{ color: TV.border, fontSize: 15, lineHeight: 1 }}>→</span>
            </div>
          )}
        </span>
      ))}
    </div>
  );
}

function heatColor(sev, v, max = 12) {
  if (v === 0) return TV.surface2;
  // Mesma escala do protótipo: saturação 0.15→1.0 com teto fixo de 12 por célula.
  const base = { critical: "214,69,69", high: "254,123,2", medium: "212,165,0", low: "34,145,96" }[sev];
  return `rgba(${base},${(0.15 + (v / max) * 0.85).toFixed(2)})`;
}

export default function OperationsCenterPage() {
  const [scans,        setScans]        = useState([]);
  const [schedules,    setSchedules]    = useState([]);
  const [sevCounts,    setSevCounts]    = useState({ critical: 0, high: 0, medium: 0, low: 0, info: 0 });
  const [workerHealth, setWorkerHealth] = useState({ summary: {}, capacity: {} });
  const [filtro,       setFiltro]       = useState("todos");
  const [lastRefresh, setLastRefresh] = useState(() => {
    const n = new Date();
    return `${String(n.getHours()).padStart(2,"0")}:${String(n.getMinutes()).padStart(2,"0")}:${String(n.getSeconds()).padStart(2,"0")}`;
  });
  const [refreshing, setRefreshing] = useState(false);
  const [intervalo,  setIntervalo]  = useState(3);
  const [countdown,  setCountdown]  = useState(0);

  const ACTIVE_STATUS = ["queued", "running", "retrying"];

  const loadData = useCallback(async () => {
    const [sr, schr, fr, whr] = await Promise.all([
      client.get("/api/scans").catch(() => ({ data: [] })),
      client.get("/api/schedules").catch(() => ({ data: [] })),
      client.get("/api/findings/page?limit=1&offset=0&status_filter=open").catch(() => ({ data: {} })),
      client.get("/api/worker-manager/health").catch(() => ({ data: {} })),
    ]);
    setScans(Array.isArray(sr.data) ? sr.data : []);
    setSchedules(Array.isArray(schr.data) ? schr.data : []);
    if (fr.data?.severity_counts) setSevCounts(fr.data.severity_counts);
    if (whr.data) setWorkerHealth(whr.data);
  }, []);

  const doRefresh = useCallback(() => {
    setRefreshing(true);
    loadData().finally(() => {
      const n = new Date();
      setLastRefresh(`${String(n.getHours()).padStart(2,"0")}:${String(n.getMinutes()).padStart(2,"0")}:${String(n.getSeconds()).padStart(2,"0")}`);
      setTimeout(() => setRefreshing(false), 400);
    });
  }, [loadData]);

  useEffect(() => { loadData(); }, [loadData]);

  useEffect(() => {
    if (intervalo === 0) { setCountdown(0); return; }
    const total = intervalo * 60;
    setCountdown(total);
    const tick = setInterval(() => {
      setCountdown((c) => { if (c <= 1) { doRefresh(); return total; } return c - 1; });
    }, 1000);
    return () => clearInterval(tick);
  }, [intervalo, doRefresh]);

  const fmtCd = (s) => `${String(Math.floor(s / 60)).padStart(2,"0")}:${String(s % 60).padStart(2,"0")}`;

  /* ── Dados calculados ── */
  const rodando    = scans.filter((s) => ACTIVE_STATUS.includes(s.status));
  const pausados   = scans.filter((s) => s.status === "paused");
  const concluidos = scans.filter((s) => ["completed","failed","cancelled","stopped"].includes(s.status));
  const bloqueados = scans.filter((s) => s.status === "blocked");
  const totalCrit  = Number(sevCounts.critical || 0);
  const totalAlto  = Number(sevCounts.high     || 0);
  const totalMed   = Number(sevCounts.medium   || 0);
  const totalBaix  = Number(sevCounts.low      || 0);

  const bigNums = filtro === "todos"
    ? [
        { v: String(scans.length),     l: "total de missões",          c: TV.text   },
        { v: String(rodando.length),   l: "scans rodando",            c: "#7fe0b0" },
        { v: String(pausados.length),  l: "pausados",                 c: "#ffe08a" },
        { v: String(concluidos.length),l: "concluídos",               c: TV.muted  },
        { v: String(totalCrit),        l: "achados críticos abertos", c: "#ff8a8a" },
        { v: String(totalAlto),        l: "achados altos abertos",    c: "#ffb377" },
      ]
    : (() => {
        const s = scans.find((x) => String(x.id) === filtro);
        if (!s) return [];
        const pct = s.mission_progress ?? s.progress ?? 0;
        return [
          { v: String(s.open_critical||0), l: "críticos",  c: "#ff8a8a" },
          { v: String(s.open_high||0),     l: "altos",     c: "#ffb377" },
          { v: String(s.open_medium||0),   l: "médios",    c: "#ffe08a" },
          { v: String(s.open_low||0),      l: "baixos",    c: "#7fe0b0" },
          { v: `${pct}%`,                  l: "progresso", c: TV.text   },
          { v: s.status,                   l: "status",    c: s.status === "running" ? "#7fe0b0" : TV.muted },
        ];
      })();

  const esteiraDados = [
    { nome: "Missões ativas", qtd: rodando.length,    sub: `${pausados.length} pausadas`,  conv: rodando.length > 0 ? Math.round(rodando.reduce((a,s)=>a+(s.mission_progress??s.progress??0),0)/rodando.length) : 0 },
    { nome: "Críticos",       qtd: totalCrit,          sub: "achados críticos",             conv: scans.length > 0 ? Math.round((totalCrit / scans.length) * 10) : 0 },
    { nome: "Altos",          qtd: totalAlto,          sub: "achados altos",                conv: scans.length > 0 ? Math.round((totalAlto / scans.length) * 10) : 0 },
    { nome: "Schedules",      qtd: schedules.length,   sub: `${schedules.filter(s=>s.enabled!==false).length} ativos`, conv: schedules.length },
    { nome: "Concluídos",     qtd: concluidos.length,  sub: "missões terminadas",           conv: null },
  ];

  const sevCols = ["critical","high","medium","low"];
  const heat = [
    { classe: "Aplicações web",     critical: totalCrit, high: totalAlto, medium: totalMed, low: totalBaix },
    { classe: "APIs",               critical: Math.round(totalCrit*.4), high: Math.round(totalAlto*.3), medium: Math.round(totalMed*.3), low: Math.round(totalBaix*.2) },
    { classe: "Infraestrutura",     critical: 0, high: Math.round(totalAlto*.2), medium: Math.round(totalMed*.2), low: Math.round(totalBaix*.3) },
    { classe: "Auth & credenciais", critical: Math.round(totalCrit*.6), high: Math.round(totalAlto*.5), medium: Math.round(totalMed*.1), low: Math.round(totalBaix*.1) },
    { classe: "DNS & headers",      critical: 0, high: Math.round(totalAlto*.1), medium: Math.round(totalMed*.2), low: Math.round(totalBaix*.4) },
  ];
  const heatMax = Math.max(...heat.flatMap(r => sevCols.map(s => r[s])), 1);

  const stTone = { ocioso: TV.muted, executando: "#7fe0b0", degradado: "#ff8a8a" };

  const wkSummary  = workerHealth.summary  || {};
  const wkCapacity = workerHealth.capacity || {};
  const totalWorkers  = Number(wkSummary.total_workers  || 0);
  const onlineWorkers = Number(wkSummary.online_workers || 0);
  const capLevel      = Number(wkCapacity.level         || 0);
  const capMax        = Number(wkCapacity.max           || Math.max(totalWorkers, 1));
  const capSlots      = Number(wkCapacity.total_slots   || capLevel || Math.max(totalWorkers, 1));
  const workerUtilPct = totalWorkers > 0 ? Math.round((onlineWorkers / totalWorkers) * 100) : 0;
  const scanUtilPct   = capSlots  > 0 ? Math.min(100, Math.round((rodando.length / capSlots) * 100)) : 0;

  return (
    <div style={{ minHeight: "100vh", background: TV.bg, display: "flex", flexDirection: "column" }}>

      {/* ── Toolbar ── */}
      <div style={{ display: "flex", alignItems: "center", gap: 12, padding: "16px 24px", borderBottom: `1px solid ${TV.border}`, flexWrap: "wrap" }}>
        <span style={{ color: TV.text, fontWeight: 700, fontSize: 15, flexShrink: 0 }}>Centro Operacional</span>
        <span style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: TV.muted }}>telemetria do ambiente · modo TV</span>

        <select value={filtro} onChange={(e) => setFiltro(e.target.value)} style={{
          fontSize: 11.5, padding: "6px 10px", borderRadius: 8, cursor: "pointer",
          background: TV.surface, color: TV.text, border: `1px solid ${TV.border}`,
          fontFamily: "var(--font-mono)",
        }}>
          <option value="todos">todos os scans</option>
          {rodando.map((s) => (
            <option key={s.id} value={String(s.id)}>#{s.id} · {String(s.target_query||"").slice(0,30)}</option>
          ))}
        </select>

        <span style={{ marginLeft: "auto", fontFamily: "var(--font-mono)", fontSize: 11, color: TV.muted, flexShrink: 0 }}>
          atualizado {lastRefresh} BRT
        </span>

        {/* intervalo */}
        <div style={{ display: "flex", alignItems: "center", gap: 4, background: TV.surface, border: `1px solid ${TV.border}`, borderRadius: 9, padding: 3, flexShrink: 0 }}>
          {[[0,"Manual"],[1,"1 min"],[3,"3 min"],[15,"15 min"]].map(([v,l]) => (
            <button key={v} onClick={() => setIntervalo(v)} style={{
              fontSize: 10.5, padding: "4px 10px", borderRadius: 6, cursor: "pointer",
              border: "none", fontFamily: "var(--font-mono)",
              background: intervalo === v ? "var(--brand-500)" : "transparent",
              color: intervalo === v ? "#fff" : TV.muted,
              fontWeight: intervalo === v ? 700 : 400,
            }}>{l}</button>
          ))}
        </div>

        <button onClick={doRefresh} style={{
          display: "inline-flex", alignItems: "center", gap: 6,
          background: TV.surface, border: `1px solid ${TV.border}`,
          borderRadius: 8, padding: "5px 12px", cursor: "pointer",
          fontFamily: "var(--font-mono)", fontSize: 11,
          color: refreshing ? TV.muted : TV.text, minWidth: 110, flexShrink: 0,
        }}>
          <span style={{ fontSize: 14, lineHeight: 1, display: "inline-block", animation: refreshing ? "spin .8s linear infinite" : "none" }}>↻</span>
          {refreshing ? "atualizando…" : intervalo > 0 && countdown > 0 ? fmtCd(countdown) : "Atualizar"}
        </button>
        <style>{"@keyframes spin{from{transform:rotate(0deg)}to{transform:rotate(360deg)}}"}</style>
        <span style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: "#7fe0b0", flexShrink: 0 }}>
          ● {rodando.length > 0 ? `${rodando.length} scan(s) ativo(s)` : "sem scans ativos"}
        </span>
      </div>

      {/* ── 6 Números gigantes ── */}
      {bigNums.length > 0 && (
        <div style={{ display: "grid", gridTemplateColumns: `repeat(${bigNums.length}, 1fr)`, gap: 1, background: TV.border, borderBottom: `1px solid ${TV.border}` }}>
          {bigNums.map((b) => (
            <div key={b.l} style={{ background: TV.bg, padding: "16px 12px", textAlign: "center" }}>
              <div style={{ fontFamily: "var(--font-mono)", fontSize: 30, fontWeight: 700, color: b.c, lineHeight: 1 }}>{b.v}</div>
              <div style={{ fontSize: 9.5, color: TV.muted, textTransform: "uppercase", letterSpacing: "0.08em", marginTop: 6 }}>{b.l}</div>
            </div>
          ))}
        </div>
      )}

      {/* ── TV Wall grid ── */}
      <div style={{ flex: 1, padding: 16, overflowY: "auto" }}>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 12, alignContent: "start" }}>

            {/* Scans rodando + fila */}
            <TvPanel title="Scans" right={`${rodando.length} rodando · ${schedules.length} na fila`}>
              <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
                {rodando.length === 0 ? (
                  <div style={{ fontSize: 12, color: TV.muted, padding: "8px 0" }}>Nenhum scan em execução</div>
                ) : rodando.map((s) => {
                  const pct = s.mission_progress ?? s.progress ?? 0;
                  const opacity = filtro === "todos" || filtro === String(s.id) ? 1 : 0.35;
                  return (
                    <div key={s.id} style={{ opacity, transition: "opacity 150ms" }}>
                      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline", marginBottom: 3 }}>
                        <span style={{ fontFamily: "var(--font-mono)", fontSize: 11.5, fontWeight: 700, color: TV.text }}>
                          #{s.id} <span style={{ fontWeight: 400, color: TV.muted }}>{String(s.target_query||"").slice(0,26)}</span>
                        </span>
                        <span style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: "#7fe0b0", fontWeight: 700 }}>{pct}%</span>
                      </div>
                      <div style={{ height: 5, background: TV.surface2, borderRadius: 99, overflow: "hidden" }}>
                        <div style={{ width: `${pct}%`, height: "100%", background: "var(--brand-500)" }} />
                      </div>
                      <div style={{ fontFamily: "var(--font-mono)", fontSize: 9.5, color: TV.muted, marginTop: 3 }}>
                        {s.current_step || "—"} · C:{s.open_critical||0} A:{s.open_high||0} M:{s.open_medium||0}
                      </div>
                    </div>
                  );
                })}
                {schedules.length > 0 && (
                  <div style={{ borderTop: `1px solid ${TV.border}`, paddingTop: 8, display: "flex", flexDirection: "column", gap: 6 }}>
                    <span style={{ fontSize: 9.5, color: TV.label, textTransform: "uppercase", letterSpacing: "0.1em", fontWeight: 600 }}>A seguir</span>
                    {schedules.slice(0,3).map((s) => (
                      <div key={s.id} style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline", gap: 8 }}>
                        <span style={{ fontFamily: "var(--font-mono)", fontSize: 10.5, color: TV.text }}>#{s.id} {String(s.target_query||"").slice(0,22)}</span>
                        <span style={{ fontFamily: "var(--font-mono)", fontSize: 9.5, color: TV.muted, whiteSpace: "nowrap" }}>{s.run_time||"—"} · {s.frequency}</span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </TvPanel>

            {/* Esteira · 2 cols */}
            <TvPanel title="Esteira · da descoberta à prova" right={`${rodando.length} ativas · ${schedules.length} agendadas`} span={2}>
              <EsteiraView esteira={esteiraDados} />
              <div style={{ display: "flex", gap: 18, marginTop: 12, paddingTop: 10, borderTop: `1px solid ${TV.border}`, fontSize: 10.5, color: TV.muted }}>
                <span>Total missões: <b style={{ color: "#9db4ff" }}>{scans.length}</b></span>
                <span>· Críticos abertos: <b style={{ color: "#ff8a8a" }}>{totalCrit}</b></span>
                <span>· Altos abertos: <b style={{ color: "#ffb377" }}>{totalAlto}</b></span>
              </div>
            </TvPanel>

            {/* Heatmap · 2 cols */}
            <TvPanel title="Heatmap · vulnerabilidades por classe" right="classe × severidade" span={2}>
              <div style={{ display: "grid", gridTemplateColumns: "180px repeat(4, 1fr) 44px", gap: 4, alignItems: "center" }}>
                {/* header */}
                <span />
                {sevCols.map((s) => (
                  <span key={s} style={{ fontSize: 9, textAlign: "center", color: TV.muted, textTransform: "uppercase", letterSpacing: "0.08em", fontWeight: 600 }}>{SEV_LABEL[s]}</span>
                ))}
                <span style={{ fontSize: 9, textAlign: "center", color: TV.muted, textTransform: "uppercase", letterSpacing: "0.08em", fontWeight: 600 }}>Total</span>
                {/* rows — each cell is a direct grid child (no display:contents) */}
                {heat.flatMap((r) => {
                  const rowTotal = sevCols.reduce((a, s) => a + r[s], 0);
                  return [
                    <span key={r.classe + "-label"} style={{ fontSize: 11, fontWeight: 600, color: TV.text, paddingRight: 8 }}>{r.classe}</span>,
                    ...sevCols.map((s) => (
                      <div key={r.classe + "-" + s} style={{
                        height: 34, borderRadius: 7, display: "grid", placeItems: "center",
                        background: heatColor(s, r[s], 12),
                        fontFamily: "var(--font-mono)", fontSize: 12, fontWeight: 700,
                        color: r[s] / 12 > 0.45 ? "#fff" : r[s] === 0 ? TV.label : TV.text,
                      }}>{r[s] > 0 ? r[s] : ""}</div>
                    )),
                    <div key={r.classe + "-total"} style={{ fontFamily: "var(--font-mono)", textAlign: "center", fontSize: 11.5, fontWeight: 700, color: TV.muted }}>
                      {rowTotal > 0 ? rowTotal : "—"}
                    </div>,
                  ];
                })}
              </div>
            </TvPanel>

            {/* Frameworks */}
            <TvPanel title="Risco por framework" right="exposição validada × cobertura">
              <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
                {FRAMEWORKS.map((fw) => (
                  <div key={fw.nome}>
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline", marginBottom: 3 }}>
                      <span style={{ fontSize: 11, fontWeight: 700, color: TV.text }}>{fw.nome}</span>
                      <span style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: `rgba(${fw.cor},0.9)`, fontWeight: 700 }}>{fw.risco}% risco</span>
                    </div>
                    <div style={{ height: 8, borderRadius: 99, overflow: "hidden", background: TV.surface2 }}>
                      <div style={{ width: `${fw.cobertura}%`, height: "100%", background: `rgba(${fw.cor},0.85)` }} />
                    </div>
                    <div style={{ display: "flex", justifyContent: "space-between", marginTop: 3 }}>
                      <span style={{ fontFamily: "var(--font-mono)", fontSize: 9, color: TV.muted }}>{fw.tecnicos}/{fw.total} técnicas</span>
                      <span style={{ fontFamily: "var(--font-mono)", fontSize: 9, color: TV.label }}>{fw.gaps[0]}</span>
                    </div>
                  </div>
                ))}
              </div>
            </TvPanel>

            {/* Capacidade & Workers */}
            <TvPanel title="Capacidade & Workers" right={`${onlineWorkers}/${totalWorkers} online`}>
              <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>

                {/* Scan utilization */}
                <div>
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline", marginBottom: 4 }}>
                    <span style={{ fontSize: 10.5, color: TV.muted }}>Utilização de scan</span>
                    <span style={{ fontFamily: "var(--font-mono)", fontSize: 13, fontWeight: 700, color: scanUtilPct > 80 ? "#ff8a8a" : "#7fe0b0" }}>
                      {scanUtilPct}%
                    </span>
                  </div>
                  <div style={{ height: 8, background: TV.surface2, borderRadius: 99, overflow: "hidden" }}>
                    <div style={{ width: `${scanUtilPct}%`, height: "100%", borderRadius: 99, background: scanUtilPct > 80 ? "#ff8a8a" : "var(--brand-500)", transition: "width 400ms" }} />
                  </div>
                  <div style={{ fontFamily: "var(--font-mono)", fontSize: 9.5, color: TV.label, marginTop: 3 }}>
                    {rodando.length} rodando · cap. {capSlots || "—"} slots {capLevel ? `(nível ${capLevel}/${capMax})` : ""}
                  </div>
                </div>

                {/* Worker utilization */}
                <div>
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline", marginBottom: 4 }}>
                    <span style={{ fontSize: 10.5, color: TV.muted }}>Workers online</span>
                    <span style={{ fontFamily: "var(--font-mono)", fontSize: 13, fontWeight: 700, color: workerUtilPct < 50 ? "#ff8a8a" : "#7fe0b0" }}>
                      {workerUtilPct}%
                    </span>
                  </div>
                  <div style={{ height: 8, background: TV.surface2, borderRadius: 99, overflow: "hidden" }}>
                    <div style={{ width: `${workerUtilPct}%`, height: "100%", borderRadius: 99, background: workerUtilPct < 50 ? "#ff8a8a" : "#7fe0b0", transition: "width 400ms" }} />
                  </div>
                  <div style={{ fontFamily: "var(--font-mono)", fontSize: 9.5, color: TV.label, marginTop: 3 }}>
                    {onlineWorkers} de {totalWorkers} workers ativos
                  </div>
                </div>

                {/* Breakdown by phase */}
                {wkSummary.phase_counts && (
                  <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 6, borderTop: `1px solid ${TV.border}`, paddingTop: 10 }}>
                    {Object.entries({
                      recon: "Recon",
                      analise_vulnerabilidade: "Vuln",
                      osint: "OSINT",
                      desconhecido: "Idle",
                    }).map(([key, label]) => {
                      const v = Number(wkSummary.phase_counts[key] || 0);
                      return (
                        <div key={key} style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                          <span style={{ fontSize: 10, color: TV.muted }}>{label}</span>
                          <span style={{ fontFamily: "var(--font-mono)", fontSize: 11, fontWeight: 700, color: v > 0 ? "#7fe0b0" : TV.label }}>{v}</span>
                        </div>
                      );
                    })}
                  </div>
                )}

              </div>
            </TvPanel>

            {/* Guardrails */}
            <TvPanel title="Guardrails · auditoria de controle" right={`${bloqueados.length} intervenções`}>
              <div style={{ display: "flex", flexDirection: "column" }}>
                {bloqueados.length === 0 ? (
                  <div style={{ fontSize: 11, color: TV.muted, padding: "8px 0" }}>Sem guardrails ativos</div>
                ) : bloqueados.map((s) => (
                  <div key={s.id} style={{ display: "grid", gridTemplateColumns: "44px 1fr", gap: 8, alignItems: "baseline", padding: "5px 0", borderBottom: `1px solid ${TV.border}`, fontSize: 10.5 }}>
                    <span style={{ fontFamily: "var(--font-mono)", color: TV.label }}>#{s.id}</span>
                    <span style={{ fontFamily: "var(--font-mono)", color: TV.text }}>
                      {String(s.target_query||"").slice(0,28)}{" "}
                      <span style={{ color: TV.muted }}>· scan bloqueado</span>
                    </span>
                  </div>
                ))}
              </div>
            </TvPanel>

            {/* Missões recentes · 2 cols */}
            <TvPanel title="Missões recentes" right="últimos resultados" span={2}>
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10 }}>
                {/* Aviso de autorização */}
                <div style={{ gridColumn: "span 2", display: "flex", alignItems: "flex-start", gap: 10, padding: "9px 12px", background: "rgba(254,215,0,0.08)", border: "1px solid rgba(254,215,0,0.25)", borderRadius: 8, fontSize: 11, color: "#ffe08a" }}>
                  <span style={{ flexShrink: 0 }}>⚠</span>
                  <span>Execute testes apenas em ambientes autorizados. Certifique-se de ter autorização formal do proprietário do alvo.</span>
                </div>
                {scans.slice(0,6).map((s) => {
                  const pct = s.mission_progress ?? s.progress ?? 0;
                  const isActive = ACTIVE_STATUS.includes(s.status);
                  return (
                    <div key={s.id} style={{ background: TV.surface2, borderRadius: 8, padding: "10px 12px", border: `1px solid ${TV.border}` }}>
                      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline", marginBottom: 4 }}>
                        <span style={{ fontFamily: "var(--font-mono)", fontSize: 12, fontWeight: 700, color: TV.text }}>#{s.id}</span>
                        <span style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: isActive ? "#7fe0b0" : TV.muted, fontWeight: 600 }}>{s.status}</span>
                      </div>
                      <div style={{ fontFamily: "var(--font-mono)", fontSize: 10.5, color: TV.muted, marginBottom: 6, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{s.target_query}</div>
                      <div style={{ height: 3, background: TV.surface, borderRadius: 99, overflow: "hidden" }}>
                        <div style={{ width: `${pct}%`, height: "100%", background: isActive ? "var(--brand-500)" : TV.muted }} />
                      </div>
                      <div style={{ display: "flex", justifyContent: "space-between", marginTop: 5, fontSize: 10, fontFamily: "var(--font-mono)", color: TV.label }}>
                        <span>C:{s.open_critical||0} A:{s.open_high||0} M:{s.open_medium||0} B:{s.open_low||0}</span>
                        <span>{pct}%</span>
                      </div>
                    </div>
                  );
                })}
              </div>
            </TvPanel>

        </div>
      </div>
    </div>
  );
}
