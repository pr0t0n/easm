import { useEffect, useMemo, useRef, useState } from "react";
import client from "../api/client";

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
