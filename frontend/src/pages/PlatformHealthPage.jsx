import { useEffect, useState, useCallback } from "react";
import client from "../api/client";

const STATUS_STYLE = (status, isAlert) => {
  const s = String(status || "").toLowerCase();
  if (!isAlert && (s === "healthy")) return { c: "var(--sev-low-text)", bg: "var(--sev-low-bg)", dot: "var(--sev-low-text)" };
  if (!isAlert) return { c: "var(--sev-info-text)", bg: "var(--sev-info-bg)", dot: "var(--sev-info-text)" };
  if (s.includes("oom")) return { c: "#fff", bg: "var(--sev-critical-text)", dot: "#fff" };
  return { c: "var(--sev-critical-text)", bg: "var(--sev-critical-bg)", dot: "var(--sev-critical-text)" };
};

function Card({ label, value, color }) {
  return (
    <div style={{ flex: "1 1 130px", background: "var(--surface)", border: "1px solid var(--line)", borderRadius: 12, padding: "14px 16px", boxShadow: "var(--shadow-card)" }}>
      <div style={{ fontSize: 30, fontWeight: 800, color: color || "var(--ink)", lineHeight: 1 }}>{value}</div>
      <div style={{ marginTop: 6, fontSize: 12, color: "var(--ink-muted)" }}>{label}</div>
    </div>
  );
}

export default function PlatformHealthPage() {
  const [data, setData] = useState(null);
  const [error, setError] = useState("");
  const [auto, setAuto] = useState(true);
  const [expanded, setExpanded] = useState({});

  const load = useCallback(() => {
    client.get("/api/platform/health")
      .then(({ data }) => { setData(data); setError(""); })
      .catch((e) => setError(e?.response?.data?.detail || "Falha ao consultar a saúde da plataforma."));
  }, []);

  useEffect(() => { load(); }, [load]);
  useEffect(() => {
    if (!auto) return undefined;
    const t = setInterval(load, 10000);
    return () => clearInterval(t);
  }, [auto, load]);

  const containers = data?.containers || [];

  return (
    <main className="dpage">
      <section style={{ display: "flex", alignItems: "center", justifyContent: "space-between", flexWrap: "wrap", gap: 10, marginBottom: 16 }}>
        <div>
          <p style={{ margin: 0, fontSize: 11, fontWeight: 700, letterSpacing: "0.08em", textTransform: "uppercase", color: "var(--ink-muted)" }}>Centro Operacional · Saúde da Plataforma</p>
          <h2 style={{ margin: "4px 0 0", color: "var(--ink)" }}>Status dos Containers (Docker)</h2>
        </div>
        <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
          <label style={{ fontSize: 12, color: "var(--ink-muted)", display: "flex", gap: 6, alignItems: "center" }}>
            <input type="checkbox" checked={auto} onChange={(e) => setAuto(e.target.checked)} /> auto (10s)
          </label>
          <button onClick={load} style={{ padding: "6px 14px", borderRadius: 8, border: "1px solid var(--line)", background: "var(--canvas)", fontSize: 12.5, cursor: "pointer" }}>Atualizar</button>
        </div>
      </section>

      {error && (
        <div style={{ marginBottom: 16, padding: "12px 14px", borderRadius: 10, background: "var(--sev-critical-bg)", color: "var(--sev-critical-text)", border: "1px solid var(--sev-critical-text)", fontSize: 13 }}>{error}</div>
      )}

      {/* Banner de alerta global */}
      {data && (
        data.all_healthy ? (
          <div style={{ marginBottom: 16, padding: "12px 16px", borderRadius: 10, background: "var(--sev-low-bg)", color: "var(--sev-low-text)", border: "1px solid var(--sev-low-text)", fontSize: 13.5, fontWeight: 700 }}>
            ✅ Plataforma saudável — {data.up}/{data.total} containers no ar.
          </div>
        ) : (
          <div style={{ marginBottom: 16, padding: "12px 16px", borderRadius: 10, background: "var(--sev-critical-bg)", color: "var(--sev-critical-text)", border: "1px solid var(--sev-critical-text)", fontSize: 13.5, fontWeight: 700 }}>
            🚨 ALERTA — {data.down} container(es) fora/instável(is): {(data.alerts || []).join(", ")}
          </div>
        )
      )}

      {data?.note && (
        <div style={{ marginBottom: 16, fontSize: 11.5, color: "var(--ink-muted)" }}>{data.note}</div>
      )}

      {data && (
        <section style={{ display: "flex", gap: 12, marginBottom: 20, flexWrap: "wrap" }}>
          <Card label="Containers" value={data.total} />
          <Card label="No ar" value={data.up} color="var(--sev-low-text)" />
          <Card label="Fora / alerta" value={data.down} color={data.down ? "var(--sev-critical-text)" : "var(--ink-muted)"} />
        </section>
      )}

      <section style={{ display: "grid", gap: 10, gridTemplateColumns: "repeat(auto-fill, minmax(300px, 1fr))" }}>
        {containers.map((c) => {
          const st = STATUS_STYLE(c.status, c.is_alert);
          const open = !!expanded[c.name];
          return (
            <article key={c.name} style={{ background: "var(--surface)", border: `1px solid ${c.is_alert ? "var(--sev-critical-text)" : "var(--line)"}`, borderLeft: `4px solid ${st.dot}`, borderRadius: 12, padding: "12px 14px", boxShadow: "var(--shadow-card)" }}>
              <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 8 }}>
                <div>
                  <div style={{ fontWeight: 700, fontSize: 14, color: "var(--ink)" }}>{c.name}</div>
                  {c.role && <div style={{ fontSize: 11, color: "var(--ink-muted)" }}>{c.role}</div>}
                </div>
                <span style={{ display: "inline-flex", alignItems: "center", gap: 6, padding: "3px 10px", borderRadius: 999, fontSize: 11, fontWeight: 800, color: st.c, background: st.bg, border: `1px solid ${st.c}` }}>
                  <span style={{ width: 7, height: 7, borderRadius: "50%", background: st.dot }} /> {c.status}
                </span>
              </div>

              <div style={{ marginTop: 8, display: "flex", gap: 12, flexWrap: "wrap", fontSize: 10.5, color: "var(--ink-muted)", fontFamily: "var(--font-mono)" }}>
                {c.health && c.health !== "none" && <span>health: {c.health}</span>}
                {c.oom_killed && <span style={{ color: "var(--sev-critical-text)", fontWeight: 700 }}>OOM-KILLED</span>}
                {c.exit_code != null && c.exit_code !== 0 && <span>exit: {c.exit_code}</span>}
                {c.restart_count != null && c.restart_count > 0 && <span>restarts: {c.restart_count}</span>}
                {c.last_seen_at && <span>last_seen: {String(c.last_seen_at).slice(0, 19)}</span>}
              </div>

              {/* Último erro em destaque */}
              {c.last_error && (
                <pre style={{ marginTop: 8, fontSize: 10, fontFamily: "var(--font-mono)", background: "#1a0d0d", color: "#ff8a8a", padding: "8px 10px", borderRadius: 6, overflow: "auto", maxHeight: 110, whiteSpace: "pre-wrap" }}>{c.last_error}</pre>
              )}

              {(c.last_log || c.last_error) && (
                <button onClick={() => setExpanded((p) => ({ ...p, [c.name]: !open }))} style={{ marginTop: 8, fontSize: 11, color: "var(--brand-700)", background: "none", border: "none", cursor: "pointer", padding: 0 }}>
                  {open ? "▼ ocultar log" : "▶ ver último log"}
                </button>
              )}
              {open && c.last_log && (
                <pre style={{ marginTop: 6, fontSize: 10, fontFamily: "var(--font-mono)", background: "var(--canvas-soft, var(--canvas))", color: "var(--ink-soft)", padding: "8px 10px", borderRadius: 6, overflow: "auto", maxHeight: 200, whiteSpace: "pre-wrap", border: "1px solid var(--line)" }}>{c.last_log}</pre>
              )}
            </article>
          );
        })}
      </section>

      {!data && !error && <div style={{ padding: 40, textAlign: "center", color: "var(--ink-muted)" }}>Carregando saúde da plataforma…</div>}
    </main>
  );
}
