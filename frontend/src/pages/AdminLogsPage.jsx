import { useCallback, useEffect, useState } from "react";
import client from "../api/client";

const ERROR_RE = /(error|exception|traceback|killed|oom|fatal|panic|refused|cannot|failed|warn)/i;

function LogLine({ line }) {
  const isErr = ERROR_RE.test(line);
  return (
    <div style={{
      fontFamily: "var(--font-mono)", fontSize: 11.5, lineHeight: 1.55,
      whiteSpace: "pre-wrap", wordBreak: "break-word",
      color: isErr ? "#ff9b9b" : "var(--ink-soft)",
      padding: "1px 0",
    }}>{line}</div>
  );
}

export default function AdminLogsPage() {
  const [kind, setKind] = useState("workers");
  const [tail, setTail] = useState(50);
  const [data, setData] = useState({ sources: [] });
  const [loading, setLoading] = useState(false);
  const [auto, setAuto] = useState(true);
  const [updatedAt, setUpdatedAt] = useState("");

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const r = await client.get(`/api/admin/logs?kind=${kind}&tail=${tail}`);
      setData(r.data || { sources: [] });
      const n = new Date();
      setUpdatedAt(`${String(n.getHours()).padStart(2, "0")}:${String(n.getMinutes()).padStart(2, "0")}:${String(n.getSeconds()).padStart(2, "0")}`);
    } catch (e) {
      setData({ sources: [], error: e?.response?.data?.detail || "Falha ao carregar logs" });
    } finally {
      setLoading(false);
    }
  }, [kind, tail]);

  useEffect(() => { load(); }, [load]);
  useEffect(() => {
    if (!auto) return;
    const t = setInterval(load, 8000);
    return () => clearInterval(t);
  }, [auto, load]);

  const sources = Array.isArray(data.sources) ? data.sources : [];

  return (
    <div style={{ padding: "24px 28px", maxWidth: 1200, margin: "0 auto" }}>
      <div style={{ display: "flex", alignItems: "baseline", gap: 12, flexWrap: "wrap", marginBottom: 6 }}>
        <h1 style={{ fontSize: 20, fontWeight: 700, margin: 0 }}>Logs do ambiente</h1>
        <span style={{ fontSize: 12.5, color: "var(--ink-muted)" }}>
          últimas {tail} linhas · {kind === "workers" ? "execução dos workers" : "comunicações (MCP interno · Kali externo · API)"}
        </span>
      </div>

      <div style={{ display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap", margin: "14px 0 18px" }}>
        <div style={{ display: "inline-flex", background: "var(--surface-soft)", border: "1px solid var(--border)", borderRadius: 9, padding: 3 }}>
          {[["workers", "Workers"], ["comms", "Comunicações"]].map(([k, l]) => (
            <button key={k} onClick={() => setKind(k)} style={{
              fontSize: 12.5, padding: "6px 14px", borderRadius: 6, cursor: "pointer", border: "none",
              background: kind === k ? "var(--brand-500)" : "transparent",
              color: kind === k ? "#fff" : "var(--ink-soft)", fontWeight: kind === k ? 700 : 500,
            }}>{l}</button>
          ))}
        </div>

        <label style={{ fontSize: 12.5, color: "var(--ink-soft)", display: "inline-flex", alignItems: "center", gap: 6 }}>
          linhas:
          <select value={tail} onChange={(e) => setTail(Number(e.target.value))}
            style={{ fontSize: 12.5, padding: "5px 8px", borderRadius: 7 }}>
            {[50, 100, 200, 500].map((n) => <option key={n} value={n}>{n}</option>)}
          </select>
        </label>

        <label style={{ fontSize: 12.5, color: "var(--ink-soft)", display: "inline-flex", alignItems: "center", gap: 6, cursor: "pointer" }}>
          <input type="checkbox" checked={auto} onChange={(e) => setAuto(e.target.checked)} />
          auto-atualizar (8s)
        </label>

        <button onClick={load} disabled={loading} style={{
          marginLeft: "auto", fontSize: 12.5, padding: "6px 14px", borderRadius: 8, cursor: "pointer",
          background: "var(--surface-soft)", border: "1px solid var(--border)", color: "var(--ink)",
        }}>{loading ? "atualizando…" : "↻ Atualizar"}</button>
        {updatedAt && <span style={{ fontSize: 11.5, color: "var(--ink-muted)" }}>atualizado {updatedAt}</span>}
      </div>

      {data.error && (
        <div style={{ padding: 14, borderRadius: 10, background: "rgba(214,69,69,0.08)", border: "1px solid rgba(214,69,69,0.3)", color: "#d64545", fontSize: 13, marginBottom: 16 }}>
          {data.error}
        </div>
      )}

      <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
        {sources.length === 0 && !data.error && (
          <div style={{ fontSize: 13, color: "var(--ink-muted)" }}>Sem fontes de log disponíveis.</div>
        )}
        {sources.map((src) => (
          <div key={src.container} style={{ border: "1px solid var(--border)", borderRadius: 12, overflow: "hidden" }}>
            <div style={{ display: "flex", alignItems: "center", gap: 10, padding: "10px 14px", background: "var(--surface-soft)", borderBottom: "1px solid var(--border)" }}>
              <span style={{ fontWeight: 700, fontSize: 13.5 }}>{src.name}</span>
              {src.role && <span style={{ fontSize: 11.5, color: "var(--ink-muted)" }}>{src.role}</span>}
              {src.status && (
                <span style={{ fontSize: 10.5, fontFamily: "var(--font-mono)", padding: "2px 8px", borderRadius: 99,
                  background: src.status === "running" ? "rgba(34,145,96,0.15)" : "rgba(214,69,69,0.15)",
                  color: src.status === "running" ? "#229160" : "#d64545" }}>{src.status}</span>
              )}
              <span style={{ marginLeft: "auto", fontSize: 11, color: "var(--ink-muted)", fontFamily: "var(--font-mono)" }}>
                {(src.lines || []).length} linhas
              </span>
            </div>
            <div style={{ padding: "10px 14px", background: "var(--surface)", maxHeight: 360, overflowY: "auto" }}>
              {src.error ? (
                <div style={{ fontSize: 12, color: "#d64545" }}>{src.error}</div>
              ) : (src.lines || []).length === 0 ? (
                <div style={{ fontSize: 12, color: "var(--ink-muted)" }}>sem linhas recentes</div>
              ) : (
                (src.lines || []).map((ln, i) => <LogLine key={i} line={ln} />)
              )}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
