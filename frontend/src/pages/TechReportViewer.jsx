import { useCallback, useEffect, useRef, useState } from "react";
import { useParams, Link } from "react-router-dom";
import client from "../api/client";
import "../styles/dashboard.css";

/* Visualizador do Relatório Técnico com URL própria (/relatorios/tecnico/:scanId).
   Permite dar refresh e acompanhar a evolução do status enquanto o scan roda —
   sem reabrir uma janela em branco a cada geração. */

const STATUS_LABEL = {
  running: "em execução", queued: "na fila", completed: "concluído",
  completed_with_gaps: "concluído com gaps", failed: "falhou",
  blocked: "bloqueado", waiting_for_auth: "aguardando credencial",
  stopped: "parado", cancelled: "cancelado",
};
const TERMINAL = new Set(["completed", "completed_with_gaps", "failed", "stopped", "cancelled", "canceled"]);
const AUTO_REFRESH_SECONDS = 30;

export default function TechReportViewer() {
  const { scanId } = useParams();
  const [html, setHtml] = useState("");
  const [status, setStatus] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [updatedAt, setUpdatedAt] = useState("");
  const [autoRefresh, setAutoRefresh] = useState(true);
  const timerRef = useRef(null);

  const loadStatus = useCallback(async () => {
    try {
      const { data } = await client.get(`/api/scans/${scanId}/status`, { _skipToast: true });
      setStatus(data || null);
      return data;
    } catch {
      return null;
    }
  }, [scanId]);

  const loadReport = useCallback(async () => {
    try {
      const res = await client.get(`/api/scans/${scanId}/pentest-report`, {
        responseType: "text",
        transformResponse: [(v) => v],
        _skipToast: true,
      });
      setHtml(String(res.data || ""));
      setError("");
      // Sao Paulo local time, no seconds-of-day dependency
      setUpdatedAt(new Date().toLocaleTimeString("pt-BR", { timeZone: "America/Sao_Paulo" }));
    } catch (err) {
      setError(err?.response?.data?.detail || "Não foi possível gerar o relatório técnico (indisponível ou sem permissão).");
    }
  }, [scanId]);

  const refresh = useCallback(async () => {
    await Promise.all([loadStatus(), loadReport()]);
  }, [loadStatus, loadReport]);

  useEffect(() => {
    setLoading(true);
    refresh().finally(() => setLoading(false));
  }, [refresh]);

  // Auto-refresh enquanto o scan não estiver em estado terminal.
  useEffect(() => {
    if (timerRef.current) { clearInterval(timerRef.current); timerRef.current = null; }
    const terminal = status && TERMINAL.has(String(status.status || "").toLowerCase());
    if (!autoRefresh || terminal) return;
    timerRef.current = setInterval(() => { refresh(); }, AUTO_REFRESH_SECONDS * 1000);
    return () => { if (timerRef.current) clearInterval(timerRef.current); };
  }, [autoRefresh, status, refresh]);

  const downloadHtml = () => {
    if (!html) return;
    const url = URL.createObjectURL(new Blob([html], { type: "text/html;charset=utf-8" }));
    const a = document.createElement("a");
    a.href = url;
    a.download = `relatorio-tecnico-scan-${scanId}.html`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 60000);
  };

  const printPdf = () => {
    const f = document.getElementById("tech-report-frame");
    if (f?.contentWindow) { f.contentWindow.focus(); f.contentWindow.print(); }
  };

  const st = String(status?.status || "").toLowerCase();
  const terminal = TERMINAL.has(st);
  const statusColor = st === "failed" ? "var(--sev-critical-text)"
    : terminal ? "var(--sev-low-text)"
    : "var(--sev-medium-text)";

  return (
    <main className="dash">
      <div className="content" style={{ padding: "16px 20px", display: "grid", gap: 12, height: "100%" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 14, flexWrap: "wrap", background: "#fff", border: "1px solid var(--line)", borderRadius: 10, padding: "10px 14px", boxShadow: "var(--shadow-card)" }}>
          <div style={{ display: "grid", gap: 2 }}>
            <div style={{ fontSize: 16, fontWeight: 800, color: "var(--ink)" }}>
              Relatório Técnico · Teste #{scanId}
            </div>
            <div style={{ fontSize: 12, color: "var(--ink-muted)" }}>
              Status: <strong style={{ color: statusColor }}>{STATUS_LABEL[st] || status?.status || "—"}</strong>
              {" · "}Progresso: <strong className="sk-mono">{Number(status?.mission_progress || 0)}%</strong>
              {status?.current_step ? <> · <span className="sk-mono">{String(status.current_step).slice(0, 90)}</span></> : null}
            </div>
          </div>
          <div style={{ flex: 1 }} />
          <span style={{ fontSize: 11, color: "var(--ink-muted)" }}>
            {updatedAt ? `Atualizado ${updatedAt}` : ""}
            {!terminal && autoRefresh ? ` · auto a cada ${AUTO_REFRESH_SECONDS}s` : ""}
            {terminal ? " · scan finalizado" : ""}
          </span>
          <label style={{ fontSize: 12, color: "var(--ink-soft)", display: "flex", alignItems: "center", gap: 6, cursor: "pointer" }}>
            <input type="checkbox" checked={autoRefresh} onChange={(e) => setAutoRefresh(e.target.checked)} disabled={terminal} />
            auto-atualizar
          </label>
          <button type="button" className="app-btn-primary rounded-lg border px-3 py-2 text-sm font-semibold" onClick={refresh}>Atualizar</button>
          <button type="button" className="app-btn-secondary rounded-lg border px-3 py-2 text-sm" onClick={printPdf} disabled={!html}>Baixar PDF</button>
          <button type="button" className="app-btn-secondary rounded-lg border px-3 py-2 text-sm" onClick={downloadHtml} disabled={!html}>Baixar HTML</button>
          <Link to="/relatorios" className="app-btn-secondary rounded-lg border px-3 py-2 text-sm" style={{ textDecoration: "none" }}>← Voltar</Link>
        </div>

        {loading && !html ? (
          <div className="dash-state"><div><div className="spin" /><p className="st-title">Gerando relatório técnico do teste #{scanId}…</p></div></div>
        ) : error && !html ? (
          <div className="dash-err">{error}</div>
        ) : (
          <iframe
            id="tech-report-frame"
            title={`Relatório técnico do teste ${scanId}`}
            srcDoc={html}
            style={{ width: "100%", flex: 1, minHeight: "calc(100vh - 130px)", border: "1px solid var(--line)", borderRadius: 10, background: "#fff", boxShadow: "var(--shadow-card)" }}
          />
        )}
      </div>
    </main>
  );
}
