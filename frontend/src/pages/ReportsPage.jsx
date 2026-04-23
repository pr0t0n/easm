import { useEffect, useMemo, useRef, useState } from "react";
import client from "../api/client";

// ReportsPage: extração de relatórios por scan ou por alvo/subdomínio.
// Para visualização de evolução temporal → /evolucao

function resolveApiBaseUrl() {
  const byClient = String(client.defaults?.baseURL || "").trim();
  if (byClient) return byClient.replace(/\/$/, "");
  return `${window.location.protocol}//${window.location.hostname}:8000`;
}

const SEV_COLORS = {
  critical: "#dc2626",
  high: "#f97316",
  medium: "#eab308",
  low: "#22c55e",
  info: "#6b7280",
};

export default function ReportsPage() {
  const apiUrl = useMemo(() => resolveApiBaseUrl(), []);

  /* ─── modo ──────────────────────────────────────────────── */
  const [mode, setMode] = useState("scan"); // "scan" | "target"

  /* ─── modo scan ─────────────────────────────────────────── */
  const [scans, setScans] = useState([]);
  const [selectedId, setSelectedId] = useState("");
  const [loadingScans, setLoadingScans] = useState(true);

  /* ─── modo target ───────────────────────────────────────── */
  const [targets, setTargets] = useState([]);
  const [loadingTargets, setLoadingTargets] = useState(false);
  const [targetInput, setTargetInput] = useState("");
  const [selectedTarget, setSelectedTarget] = useState("");
  const [resolvedScanId, setResolvedScanId] = useState("");
  const [resolving, setResolving] = useState(false);
  const [resolveError, setResolveError] = useState("");
  const inputRef = useRef(null);

  /* ─── carrega scans ──────────────────────────────────────── */
  useEffect(() => {
    let ok = true;
    setLoadingScans(true);
    client
      .get("/api/scans", { params: { limit: 300 } })
      .then(({ data }) => {
        if (!ok) return;
        const list = Array.isArray(data) ? data : [];
        setScans(list);
        if (list.length > 0) setSelectedId(String(list[0].id));
      })
      .finally(() => ok && setLoadingScans(false));
    return () => { ok = false; };
  }, []);

  /* ─── carrega targets (somente na 1ª vez que entra no modo) ─ */
  useEffect(() => {
    if (mode !== "target" || targets.length > 0) return;
    let ok = true;
    setLoadingTargets(true);
    client
      .get("/api/reports/by-target")
      .then(({ data }) => ok && setTargets(Array.isArray(data) ? data : []))
      .finally(() => ok && setLoadingTargets(false));
    return () => { ok = false; };
  }, [mode]);

  useEffect(() => {
    if (selectedTarget) setTargetInput(selectedTarget);
  }, [selectedTarget]);

  const handleResolve = async () => {
    const t = targetInput.trim();
    if (!t) return;
    setResolving(true);
    setResolveError("");
    setResolvedScanId("");
    try {
      const { data } = await client.get("/api/reports/by-target/latest", { params: { target: t } });
      setResolvedScanId(String(data.scan_id));
    } catch (err) {
      setResolveError(err?.response?.data?.detail || "Nenhum scan concluído encontrado para este alvo.");
    } finally {
      setResolving(false);
    }
  };

  /* ─── URL do iframe ─────────────────────────────────────── */
  const scanId = mode === "scan" ? selectedId : resolvedScanId;
  const reportUrl = useMemo(() => {
    if (!scanId) return "";
    return `/custom-report/index.html?${new URLSearchParams({ scan_id: scanId, api_url: apiUrl })}`;
  }, [scanId, apiUrl]);

  const openNewTab = () => reportUrl && window.open(reportUrl, "_blank", "noopener,noreferrer");
  const printReport = () => {
    const f = document.getElementById("report-iframe");
    if (f?.contentWindow) { f.contentWindow.focus(); f.contentWindow.print(); }
  };

  /* ─── scan selecionado (para exibir summary) ────────────── */
  const selectedScan = scans.find((s) => String(s.id) === String(selectedId));

  return (
    <div style={{ padding: 16, display: "grid", gap: 12 }}>
      {/* ── toolbar ─────────────────────────────────────────── */}
      <div
        style={{
          display: "flex",
          flexWrap: "wrap",
          gap: 8,
          alignItems: "center",
          background: "#ffffff",
          border: "1px solid #d1d5db",
          borderRadius: 10,
          padding: 12,
        }}
      >
        {/* tabs */}
        {["scan", "target"].map((m) => (
          <button
            key={m}
            type="button"
            onClick={() => setMode(m)}
            style={{
              padding: "6px 14px",
              borderRadius: 8,
              border: `1px solid ${mode === m ? "#2563eb" : "#d1d5db"}`,
              background: mode === m ? "#eff6ff" : "#f9fafb",
              color: mode === m ? "#1d4ed8" : "#374151",
              fontWeight: mode === m ? 600 : 400,
              fontSize: 13,
              cursor: "pointer",
            }}
          >
            {m === "scan" ? "Por Scan" : "Por Alvo"}
          </button>
        ))}

        <div style={{ width: 1, height: 24, background: "#e5e7eb" }} />

        {/* controles por scan */}
        {mode === "scan" && (
          <select
            value={selectedId}
            onChange={(e) => setSelectedId(e.target.value)}
            disabled={loadingScans || scans.length === 0}
            style={{ padding: "6px 10px", borderRadius: 8, border: "1px solid #d1d5db", fontSize: 13 }}
          >
            {scans.length === 0 && <option value="">Sem scans disponíveis</option>}
            {scans.map((s) => (
              <option key={s.id} value={s.id}>
                #{s.id} · {String(s.target_query || "(sem alvo)").slice(0, 60)}
                {s.target_query?.length > 60 ? "…" : ""}
              </option>
            ))}
          </select>
        )}

        {/* controles por target */}
        {mode === "target" && (
          <>
            {targets.length > 0 && (
              <select
                value={selectedTarget}
                onChange={(e) => setSelectedTarget(e.target.value)}
                disabled={loadingTargets}
                style={{ padding: "6px 10px", borderRadius: 8, border: "1px solid #d1d5db", fontSize: 13, maxWidth: 220 }}
              >
                <option value="">-- selecionar alvo --</option>
                {targets.map((t) => (
                  <option key={t.target} value={t.target}>{t.target}</option>
                ))}
              </select>
            )}
            <input
              ref={inputRef}
              type="text"
              placeholder="digitar subdomínio / alvo…"
              value={targetInput}
              onChange={(e) => setTargetInput(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && handleResolve()}
              style={{ padding: "6px 10px", borderRadius: 8, border: "1px solid #d1d5db", fontSize: 13, minWidth: 210 }}
            />
            <button
              type="button"
              onClick={handleResolve}
              disabled={resolving || !targetInput.trim()}
              style={{
                padding: "6px 14px",
                borderRadius: 8,
                border: "1px solid #d1d5db",
                background: "#f9fafb",
                fontSize: 13,
                cursor: "pointer",
                opacity: resolving || !targetInput.trim() ? 0.5 : 1,
              }}
            >
              {resolving ? "Buscando…" : "Gerar"}
            </button>
            {resolvedScanId && (
              <span style={{ fontSize: 12, color: "#6b7280" }}>Scan #{resolvedScanId}</span>
            )}
            {resolveError && (
              <span style={{ fontSize: 12, color: "#dc2626" }}>{resolveError}</span>
            )}
          </>
        )}

        <div style={{ flex: 1 }} />

        {/* ações de exportação */}
        <button
          type="button"
          onClick={openNewTab}
          disabled={!reportUrl}
          className="app-btn-secondary rounded-lg border px-3 py-2 text-sm disabled:cursor-not-allowed disabled:opacity-50"
        >
          Abrir em nova aba
        </button>
        <button
          type="button"
          onClick={printReport}
          disabled={!reportUrl}
          className="app-btn-primary rounded-lg border px-3 py-2 text-sm font-semibold disabled:cursor-not-allowed disabled:opacity-50"
        >
          Imprimir / PDF
        </button>
      </div>

      {/* ── metadados do scan selecionado ────────────────────── */}
      {mode === "scan" && selectedScan && (
        <div
          style={{
            display: "flex",
            gap: 20,
            padding: "8px 14px",
            background: "#f9fafb",
            border: "1px solid #e5e7eb",
            borderRadius: 8,
            fontSize: 12,
            color: "#6b7280",
            flexWrap: "wrap",
          }}
        >
          <span><strong style={{ color: "#374151" }}>Alvo:</strong> {selectedScan.target_query || "—"}</span>
          <span>
            <strong style={{ color: "#374151" }}>Status:</strong>{" "}
            <span
              style={{
                color: selectedScan.status === "completed" ? "#16a34a" : selectedScan.status === "failed" ? "#dc2626" : "#d97706",
                fontWeight: 600,
              }}
            >
              {selectedScan.status}
            </span>
          </span>
          <span>
            <strong style={{ color: "#374151" }}>Criado em:</strong>{" "}
            {selectedScan.created_at ? new Date(selectedScan.created_at).toLocaleString("pt-BR") : "—"}
          </span>
        </div>
      )}

      {/* ── iframe do relatório ───────────────────────────────── */}
      {reportUrl ? (
        <iframe
          id="report-iframe"
          key={reportUrl}
          src={reportUrl}
          title="Relatório"
          style={{
            width: "100%",
            minHeight: "calc(100vh - 200px)",
            border: "1px solid #d1d5db",
            borderRadius: 10,
            background: "#fff",
          }}
        />
      ) : (
        <div
          style={{
            padding: 40,
            textAlign: "center",
            color: "#9ca3af",
            border: "1px dashed #d1d5db",
            borderRadius: 10,
            fontSize: 14,
          }}
        >
          {mode === "scan"
            ? loadingScans ? "Carregando scans…" : "Selecione um scan para gerar o relatório."
            : "Selecione ou digite um alvo e clique em Gerar."}
        </div>
      )}
    </div>
  );
}


const PAGE_STYLE = {
  padding: "16px",
  display: "grid",
  gap: "12px",
};

const TOOLBAR_STYLE = {
  display: "flex",
  flexWrap: "wrap",
  gap: "8px",
  alignItems: "center",
  background: "#ffffff",
  border: "1px solid #d1d5db",
  borderRadius: "10px",
  padding: "12px",
};

const TAB_STYLE = (active) => ({
  padding: "6px 16px",
  borderRadius: 8,
  border: "1px solid",
  borderColor: active ? "#2563eb" : "#d1d5db",
  background: active ? "#eff6ff" : "#f9fafb",
  color: active ? "#1d4ed8" : "#374151",
  fontWeight: active ? 600 : 400,
  fontSize: 14,
  cursor: "pointer",
});

const IFRAME_STYLE = {
  width: "100%",
  minHeight: "calc(100vh - 220px)",
  border: "1px solid #d1d5db",
  borderRadius: "10px",
  background: "#fff",
};

function resolveApiBaseUrl() {
  const byClient = String(client.defaults?.baseURL || "").trim();
  if (byClient) {
    return byClient.replace(/\/$/, "");
  }
  return `${window.location.protocol}//${window.location.hostname}:8000`;
}

export default function ReportsPage() {
  const [mode, setMode] = useState("scan"); // "scan" | "target"

  // --- Modo scan ---
  const [scans, setScans] = useState([]);
  const [selectedId, setSelectedId] = useState("");
  const [loadingScans, setLoadingScans] = useState(true);
  const [errorScans, setErrorScans] = useState("");

  // --- Modo target ---
  const [targets, setTargets] = useState([]); // [{target, scan_id, scan_created_at}]
  const [loadingTargets, setLoadingTargets] = useState(false);
  const [errorTargets, setErrorTargets] = useState("");
  const [targetInput, setTargetInput] = useState("");
  const [selectedTarget, setSelectedTarget] = useState("");
  const [resolvedScanId, setResolvedScanId] = useState("");
  const [resolving, setResolving] = useState(false);
  const [resolveError, setResolveError] = useState("");
  const targetInputRef = useRef(null);

  const apiUrl = useMemo(() => resolveApiBaseUrl(), []);

  // Carrega lista de scans (modo scan)
  useEffect(() => {
    let mounted = true;
    setLoadingScans(true);
    setErrorScans("");
    client
      .get("/api/scans", { params: { limit: 200 } })
      .then(({ data }) => {
        if (!mounted) return;
        const list = Array.isArray(data) ? data : [];
        setScans(list);
        if (list.length > 0) setSelectedId(String(list[0].id));
      })
      .catch((err) => {
        if (!mounted) return;
        setErrorScans(err?.response?.data?.detail || "Falha ao carregar scans.");
      })
      .finally(() => {
        if (mounted) setLoadingScans(false);
      });
    return () => {
      mounted = false;
    };
  }, []);

  // Carrega lista de targets únicos com último scan (modo target)
  useEffect(() => {
    if (mode !== "target" || targets.length > 0) return;
    let mounted = true;
    setLoadingTargets(true);
    setErrorTargets("");
    client
      .get("/api/reports/by-target")
      .then(({ data }) => {
        if (!mounted) return;
        setTargets(Array.isArray(data) ? data : []);
      })
      .catch((err) => {
        if (!mounted) return;
        setErrorTargets(err?.response?.data?.detail || "Falha ao carregar alvos.");
      })
      .finally(() => {
        if (mounted) setLoadingTargets(false);
      });
    return () => {
      mounted = false;
    };
  }, [mode]);

  // Quando seleciona target no dropdown, preenche input
  useEffect(() => {
    if (selectedTarget) setTargetInput(selectedTarget);
  }, [selectedTarget]);

  // Resolve o último scan para o alvo digitado/selecionado
  const handleResolveTarget = async () => {
    const t = targetInput.trim();
    if (!t) return;
    setResolving(true);
    setResolveError("");
    setResolvedScanId("");
    try {
      const { data } = await client.get("/api/reports/by-target/latest", { params: { target: t } });
      setResolvedScanId(String(data.scan_id));
    } catch (err) {
      const detail = err?.response?.data?.detail;
      setResolveError(detail || "Nenhum scan concluido encontrado para este alvo.");
    } finally {
      setResolving(false);
    }
  };

  // URL do iframe conforme modo
  const reportUrl = useMemo(() => {
    const scanId = mode === "scan" ? selectedId : resolvedScanId;
    if (!scanId) return "";
    const params = new URLSearchParams({ scan_id: String(scanId), api_url: apiUrl });
    return `/custom-report/index.html?${params.toString()}`;
  }, [mode, selectedId, resolvedScanId, apiUrl]);

  const selectedScan = useMemo(
    () => scans.find((scan) => String(scan.id) === String(selectedId)),
    [scans, selectedId],
  );

  const handleOpenNewTab = () => {
    if (!reportUrl) return;
    window.open(reportUrl, "_blank", "noopener,noreferrer");
  };

  const handlePrint = () => {
    const iframe = document.getElementById("custom-report-iframe");
    if (!iframe?.contentWindow) return;
    iframe.contentWindow.focus();
    iframe.contentWindow.print();
  };

  return (
    <div style={PAGE_STYLE}>
      <div style={TOOLBAR_STYLE}>
        {/* Tabs de modo */}
        <button type="button" style={TAB_STYLE(mode === "scan")} onClick={() => setMode("scan")}>
          Por Scan
        </button>
        <button type="button" style={TAB_STYLE(mode === "target")} onClick={() => setMode("target")}>
          Por Alvo / Subdomínio
        </button>

        <div style={{ width: 1, height: 28, background: "#e5e7eb", margin: "0 4px" }} />

        {/* Controles por scan */}
        {mode === "scan" && (
          <select
            value={selectedId}
            onChange={(e) => setSelectedId(e.target.value)}
            disabled={loadingScans || scans.length === 0}
            style={{ padding: "8px 10px", borderRadius: 8, border: "1px solid #d1d5db" }}
          >
            {scans.length === 0 ? <option value="">Sem scans disponiveis</option> : null}
            {scans.map((scan) => (
              <option key={scan.id} value={scan.id}>
                #{scan.id} - {scan.target_query || "(sem alvo)"}
              </option>
            ))}
          </select>
        )}

        {/* Controles por alvo */}
        {mode === "target" && (
          <>
            {targets.length > 0 && (
              <select
                value={selectedTarget}
                onChange={(e) => setSelectedTarget(e.target.value)}
                disabled={loadingTargets}
                style={{ padding: "8px 10px", borderRadius: 8, border: "1px solid #d1d5db", maxWidth: 240 }}
              >
                <option value="">-- selecionar alvo --</option>
                {targets.map((t) => (
                  <option key={t.target} value={t.target}>
                    {t.target}
                  </option>
                ))}
              </select>
            )}
            <input
              ref={targetInputRef}
              type="text"
              placeholder="ou digitar subdomínio/alvo…"
              value={targetInput}
              onChange={(e) => setTargetInput(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && handleResolveTarget()}
              style={{ padding: "8px 10px", borderRadius: 8, border: "1px solid #d1d5db", minWidth: 220 }}
            />
            <button
              type="button"
              onClick={handleResolveTarget}
              disabled={resolving || !targetInput.trim()}
              className="app-btn-secondary rounded-lg border px-3 py-2 text-sm disabled:cursor-not-allowed disabled:opacity-60"
            >
              {resolving ? "Buscando…" : "Gerar Relatório"}
            </button>
            {resolvedScanId && (
              <span style={{ fontSize: 12, color: "#6b7280" }}>
                Scan #{resolvedScanId}
              </span>
            )}
          </>
        )}

        <div style={{ flex: 1 }} />

        <button
          type="button"
          onClick={handleOpenNewTab}
          disabled={!reportUrl}
          className="app-btn-secondary rounded-lg border px-3 py-2 text-sm disabled:cursor-not-allowed disabled:opacity-60"
        >
          Abrir em nova aba
        </button>

        <button
          type="button"
          onClick={handlePrint}
          disabled={!reportUrl}
          className="app-btn-primary rounded-lg border px-3 py-2 text-sm font-semibold disabled:cursor-not-allowed disabled:opacity-60"
        >
          Imprimir
        </button>
      </div>

      {/* Mensagens de status */}
      {mode === "scan" && loadingScans && <div style={{ color: "#6b7280" }}>Carregando scans...</div>}
      {mode === "scan" && errorScans && <div style={{ color: "#b91c1c" }}>{errorScans}</div>}
      {mode === "target" && loadingTargets && <div style={{ color: "#6b7280" }}>Carregando alvos...</div>}
      {mode === "target" && errorTargets && <div style={{ color: "#b91c1c" }}>{errorTargets}</div>}
      {mode === "target" && resolveError && <div style={{ color: "#b91c1c" }}>{resolveError}</div>}

      {reportUrl ? (
        <iframe
          id="custom-report-iframe"
          key={reportUrl}
          src={reportUrl}
          title={mode === "scan" ? `Relatorio scan ${selectedId}` : `Relatorio alvo ${targetInput}`}
          style={IFRAME_STYLE}
        />
      ) : null}
    </div>
  );
}
