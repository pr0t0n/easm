import { useEffect, useMemo, useState } from "react";
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
  const [scans, setScans] = useState([]);
  const [selectedId, setSelectedId] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    let mounted = true;

    async function loadScans() {
      setLoading(true);
      setError("");
      try {
        const { data } = await client.get("/api/scans", { params: { limit: 200 } });
        if (!mounted) return;
        const list = Array.isArray(data) ? data : [];
        setScans(list);
        if (list.length > 0) {
          setSelectedId(String(list[0].id));
        }
      } catch (err) {
        if (!mounted) return;
        setError(err?.response?.data?.detail || "Falha ao carregar scans para gerar o relatorio.");
      } finally {
        if (mounted) setLoading(false);
      }
    }

    loadScans();
    return () => {
      mounted = false;
    };
  }, []);

  const selectedScan = useMemo(
    () => scans.find((scan) => String(scan.id) === String(selectedId)),
    [scans, selectedId],
  );

  const apiUrl = useMemo(() => resolveApiBaseUrl(), []);

  const reportUrl = useMemo(() => {
    if (!selectedId) return "";
    const params = new URLSearchParams({
      scan_id: String(selectedId),
      api_url: apiUrl,
    });
    return `/easm-report/index.html?${params.toString()}`;
  }, [selectedId, apiUrl]);

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
        <select
          value={selectedId}
          onChange={(e) => setSelectedId(e.target.value)}
          disabled={loading || scans.length === 0}
          style={{ marginLeft: "auto", padding: "8px 10px", borderRadius: 8, border: "1px solid #d1d5db" }}
        >
          {scans.length === 0 ? <option value="">Sem scans disponiveis</option> : null}
          {scans.map((scan) => (
            <option key={scan.id} value={scan.id}>
              #{scan.id} - {scan.target_query || "(sem alvo)"}
            </option>
          ))}
        </select>

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

      {loading ? <div style={{ color: "#6b7280" }}>Carregando scans...</div> : null}
      {error ? <div style={{ color: "#b91c1c" }}>{error}</div> : null}

      {selectedScan && reportUrl ? (
        <iframe
          id="custom-report-iframe"
          key={reportUrl}
          src={reportUrl}
          title={`Relatorio do scan ${selectedScan.id}`}
          style={IFRAME_STYLE}
        />
      ) : null}
    </div>
  );
}
