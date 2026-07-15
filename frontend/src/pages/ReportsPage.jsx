// ReportsPage: relatório único por scan ou por alvo/subdomínio.
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import client from "../api/client";
import CompanyScopeSelect from "../components/CompanyScopeSelect";

function resolveApiBaseUrl() {
  const byClient = String(client.defaults?.baseURL || "").trim();
  // Only use byClient if it's an absolute URL; relative base ("/api") should use current origin
  if (byClient && (byClient.startsWith("http://") || byClient.startsWith("https://"))) {
    return byClient.replace(/\/$/, "");
  }
  // When client uses relative paths (Vite proxy), use the current window origin
  // so the iframe also routes through the proxy instead of hitting :8000 directly
  if (typeof window !== "undefined") return window.location.origin;
  return `${window.location.protocol}//${window.location.hostname}:8000`;
}

function normalizeTargetToken(raw) {
  const value = String(raw || "").trim().toLowerCase();
  if (!value) return "";
  try {
    if (value.startsWith("http://") || value.startsWith("https://")) {
      return String(new URL(value).hostname || "").trim().toLowerCase();
    }
  } catch {
    // noop
  }
  return value.replace(/^\.+|\.+$/g, "");
}

function splitTargets(raw) {
  return String(raw || "")
    .split(/[\n,;\s]+/g)
    .map((item) => normalizeTargetToken(item))
    .filter(Boolean);
}

const controlLabel = {
  display: "grid",
  gap: 4,
  fontSize: 12,
  color: "var(--ink-muted)",
};

const controlInput = {
  padding: "6px 10px",
  borderRadius: 8,
  border: "1px solid var(--line)",
  fontSize: 13,
  background: "#ffffff",
  color: "var(--ink)",
};

const reportCard = {
  background: "#ffffff",
  border: "1px solid var(--line)",
  borderRadius: 10,
  padding: 12,
  boxShadow: "var(--shadow-card)",
};

export default function ReportsPage() {
  const apiUrl = useMemo(() => resolveApiBaseUrl(), []);
  const [compareScanId, setCompareScanId] = useState("");
  const [mode, setMode] = useState("scan");
  const [scans, setScans] = useState([]);
  const [selectedId, setSelectedId] = useState("");
  // Narrative state
  const [narrative, setNarrative] = useState("");
  const [narrativeMethod, setNarrativeMethod] = useState("");
  const [generatingNarrative, setGeneratingNarrative] = useState(false);
  const [narrativeError, setNarrativeError] = useState("");
  const [showNarrative, setShowNarrative] = useState(false);
  const [loadingScans, setLoadingScans] = useState(true);
  const [targets, setTargets] = useState([]);
  const [loadingTargets, setLoadingTargets] = useState(false);
  const [targetInput, setTargetInput] = useState("");
  const [selectedTarget, setSelectedTarget] = useState("");
  const [resolvedScanId, setResolvedScanId] = useState("");
  const [resolving, setResolving] = useState(false);
  const [resolveError, setResolveError] = useState("");
  const [selectedIncludeTargets, setSelectedIncludeTargets] = useState([]);
  const [customTargetsInput, setCustomTargetsInput] = useState("");
  const [accessGroupId, setAccessGroupId] = useState("");
  const inputRef = useRef(null);

  useEffect(() => {
    let ok = true;
    setLoadingScans(true);
    client
      .get("/api/scans", { params: { limit: 300 } })
      .then(({ data }) => {
        if (!ok) return;
        const list = (Array.isArray(data) ? data : [])
          .filter((scan) => !accessGroupId || String(scan.access_group_id || "") === String(accessGroupId));
        setScans(list);
        if (!list.some((scan) => String(scan.id) === String(selectedId))) {
          setSelectedId(list[0]?.id ? String(list[0].id) : "");
        }
      })
      .finally(() => ok && setLoadingScans(false));
    return () => { ok = false; };
  }, [accessGroupId, selectedId]);

  useEffect(() => {
    let ok = true;
    setLoadingTargets(true);
    client
      .get("/api/reports/by-target", { params: accessGroupId ? { access_group_id: accessGroupId } : {} })
      .then(({ data }) => ok && setTargets(Array.isArray(data) ? data : []))
      .finally(() => ok && setLoadingTargets(false));
    return () => { ok = false; };
  }, [accessGroupId]);

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
      const params = { target: t };
      if (accessGroupId) params.access_group_id = accessGroupId;
      const { data } = await client.get("/api/reports/by-target/latest", { params });
      setResolvedScanId(String(data.scan_id));
    } catch (err) {
      setResolveError(err?.response?.data?.detail || "Nenhum scan concluído encontrado para este alvo.");
    } finally {
      setResolving(false);
    }
  };

  const scanId = mode === "scan" ? selectedId : resolvedScanId;

  const availableTargetOptions = useMemo(() => {
    const rows = Array.isArray(targets) ? targets : [];
    return rows.map((item) => String(item?.target || "").trim()).filter(Boolean);
  }, [targets]);

  const effectiveIncludeTargets = useMemo(() => {
    const merged = [];
    const push = (raw) => {
      const token = normalizeTargetToken(raw);
      if (token && !merged.includes(token)) merged.push(token);
    };

    if (mode === "target") {
      push(targetInput);
      push(selectedTarget);
    }

    for (const token of selectedIncludeTargets) push(token);
    for (const token of splitTargets(customTargetsInput)) push(token);

    return merged;
  }, [mode, targetInput, selectedTarget, selectedIncludeTargets, customTargetsInput]);

  const reportUrl = useMemo(() => {
    if (!scanId) return "";
    const params = new URLSearchParams({
      scan_id: scanId,
      api_url: apiUrl,
      persona: "complete",
      output_mode: "visual",
      severity_min: "all",
      period_days: "all",
    });
    if (effectiveIncludeTargets.length > 0) {
      params.set("include_targets", effectiveIncludeTargets.join(","));
    }
    if (compareScanId) {
      params.set("compare_scan_id", String(compareScanId));
    }
    return `/custom-report/index.html?${params.toString()}`;
  }, [scanId, apiUrl, effectiveIncludeTargets, compareScanId]);

  const scopeReady = useMemo(() => {
    if (!scanId) return false;
    if (mode === "target" && !targetInput.trim()) return false;
    return true;
  }, [scanId, mode, targetInput]);

  const openNewTab = () => reportUrl && window.open(reportUrl, "_blank", "noopener,noreferrer");
  const printReport = () => {
    const f = document.getElementById("report-iframe");
    if (f?.contentWindow) { f.contentWindow.focus(); f.contentWindow.print(); }
  };

  // Load narrative when scan changes
  useEffect(() => {
    if (!selectedId) return;
    setNarrative("");
    setNarrativeMethod("");
    client.get(`/api/scans/${selectedId}/attack-narrative`)
      .then(({ data }) => { setNarrative(data.narrative || ""); setNarrativeMethod(data.method || ""); })
      .catch(() => {});
  }, [selectedId]);

  const generateNarrative = useCallback(async () => {
    if (!selectedId) return;
    setGeneratingNarrative(true);
    setNarrativeError("");
    try {
      const { data } = await client.post(`/api/scans/${selectedId}/generate-narrative`);
      setNarrative(data.narrative || "");
      setNarrativeMethod(data.method || "");
      setShowNarrative(true);
    } catch (err) {
      setNarrativeError(err?.response?.data?.detail || "Falha ao gerar narrativa.");
    } finally {
      setGeneratingNarrative(false);
    }
  }, [selectedId]);

  const selectedScan = scans.find((s) => String(s.id) === String(selectedId));

  return (
    <div className="dpage" style={{ display: "grid", gap: 12 }}>
      <div style={{ ...reportCard, display: "grid", gap: 10 }}>
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 10, flexWrap: "wrap" }}>
          <div>
            <div style={{ color: "var(--brand-700)", fontSize: 11, fontWeight: 800, letterSpacing: "0.14em", textTransform: "uppercase", marginBottom: 6 }}>
              Entrega executiva e técnica
            </div>
            <div style={{ fontSize: 24, fontWeight: 800, color: "var(--ink)", letterSpacing: 0 }}>
              O que o Blue Team precisa fazer primeiro
            </div>
            <div style={{ marginTop: 3, color: "var(--ink-muted)", fontSize: 13 }}>
              Relatório único com narrativa, evidências, recomendações, matriz Blue Team, delta entre scans e plano de remediação.
            </div>
          </div>
          <div style={{ color: "var(--ink-muted)", fontSize: 12, textAlign: "right" }}>
            Modo completo · histórico completo · todas as severidades
          </div>
        </div>
      </div>

      <div style={{ ...reportCard, display: "flex", flexWrap: "wrap", gap: 8, alignItems: "center" }}>
        <CompanyScopeSelect
          value={accessGroupId}
          onChange={(value) => {
            setAccessGroupId(value);
            setResolvedScanId("");
            setSelectedTarget("");
            setTargetInput("");
            setCompareScanId("");
            setSelectedIncludeTargets([]);
          }}
          style={{ minWidth: 220 }}
        />
        {["scan", "target"].map((m) => (
          <button
            key={m}
            type="button"
            onClick={() => setMode(m)}
            style={{ padding: "6px 14px", borderRadius: 8, border: `1px solid ${mode === m ? "var(--brand-500)" : "var(--line)"}`, background: mode === m ? "var(--brand-500)" : "#ffffff", color: mode === m ? "#ffffff" : "var(--ink-soft)", fontWeight: mode === m ? 600 : 400, fontSize: 13, cursor: "pointer" }}
          >
            {m === "scan" ? "Por Scan" : "Por Alvo"}
          </button>
        ))}
        <div style={{ width: 1, height: 24, background: "var(--line)" }} />
        {mode === "scan" && (
          <select
            value={selectedId}
            onChange={(e) => setSelectedId(e.target.value)}
            disabled={loadingScans || scans.length === 0}
            style={controlInput}
          >
            {scans.length === 0 && <option value="">Sem scans disponíveis</option>}
            {scans.map((s) => (
              <option key={s.id} value={s.id}>
                #{s.id} · {String(s.target_query || "(sem alvo)").slice(0, 60)}{(s.target_query?.length ?? 0) > 60 ? "…" : ""}
              </option>
            ))}
          </select>
        )}
        {mode === "target" && (
          <>
            {targets.length > 0 && (
              <select value={selectedTarget} onChange={(e) => setSelectedTarget(e.target.value)} disabled={loadingTargets} style={{ ...controlInput, maxWidth: 220 }}>
                <option value="">-- selecionar alvo --</option>
                {targets.map((t) => <option key={t.target} value={t.target}>{t.target}</option>)}
              </select>
            )}
            <input ref={inputRef} type="text" placeholder="digitar subdomínio / alvo…" value={targetInput} onChange={(e) => setTargetInput(e.target.value)} onKeyDown={(e) => e.key === "Enter" && handleResolve()} style={{ ...controlInput, minWidth: 210 }} />
            <button type="button" onClick={handleResolve} disabled={resolving || !targetInput.trim()} style={{ padding: "6px 14px", borderRadius: 8, border: "1px solid var(--brand-500)", background: "var(--brand-500)", color: "#ffffff", fontSize: 13, cursor: "pointer", opacity: resolving || !targetInput.trim() ? 0.5 : 1 }}>
              {resolving ? "Buscando…" : "Gerar"}
            </button>
            {resolvedScanId && <span style={{ fontSize: 12, color: "var(--ink-muted)" }}>Scan #{resolvedScanId}</span>}
            {resolveError && <span style={{ fontSize: 12, color: "var(--sev-critical-text)" }}>{resolveError}</span>}
          </>
        )}

        <div style={{ display: "grid", gap: 4, minWidth: 260 }}>
          <label style={{ fontSize: 11, color: "var(--ink-muted)" }}>Alvos incluídos no relatório (customizável)</label>
          <select
            multiple
            value={selectedIncludeTargets}
            onChange={(e) => {
              const values = Array.from(e.target.selectedOptions || []).map((opt) => normalizeTargetToken(opt.value)).filter(Boolean);
              setSelectedIncludeTargets(values);
            }}
            style={{ ...controlInput, fontSize: 12, minHeight: 72 }}
          >
            {availableTargetOptions.map((target) => (
              <option key={target} value={target}>{target}</option>
            ))}
          </select>
          <input
            type="text"
            placeholder="Extras (csv): ex. app.site.com,api.site.com"
            value={customTargetsInput}
            onChange={(e) => setCustomTargetsInput(e.target.value)}
            style={{ ...controlInput, fontSize: 12 }}
          />
          <span style={{ fontSize: 11, color: "var(--ink-muted)" }}>
            Escopo ativo: {effectiveIncludeTargets.length > 0 ? effectiveIncludeTargets.join(", ") : "scan completo"}
          </span>
        </div>

        <label style={{ ...controlLabel, minWidth: 190, fontSize: 11 }}>
          Comparar com scan (opcional)
          <select
            value={compareScanId}
            onChange={(e) => setCompareScanId(e.target.value)}
            style={{ ...controlInput, fontSize: 12 }}
          >
            <option value="">Sem comparação</option>
            {scans
              .filter((s) => String(s.id) !== String(scanId || ""))
              .slice(0, 200)
              .map((s) => (
                <option key={`compare-${s.id}`} value={s.id}>#{s.id} · {String(s.target_query || "(sem alvo)").slice(0, 44)}</option>
              ))}
          </select>
        </label>

        <div style={{ flex: 1 }} />
        <button type="button" onClick={openNewTab} disabled={!reportUrl || !scopeReady} className="app-btn-secondary rounded-lg border px-3 py-2 text-sm disabled:cursor-not-allowed disabled:opacity-50">Abrir em nova aba</button>
        <button type="button" onClick={printReport} disabled={!reportUrl || !scopeReady} className="app-btn-primary rounded-lg border px-3 py-2 text-sm font-semibold disabled:cursor-not-allowed disabled:opacity-50">Imprimir / PDF</button>
      </div>

      <div style={{ position: "sticky", top: 8, zIndex: 4, background: "rgba(255,255,255,0.94)", border: "1px solid var(--line)", borderRadius: 10, padding: "10px 12px", display: "grid", gap: 3, fontSize: 12, color: "var(--ink-muted)", boxShadow: "var(--shadow-card)", backdropFilter: "blur(8px)" }}>
        <div style={{ color: "var(--ink)", fontWeight: 600 }}>Resumo do escopo</div>
        <div>Relatório: único e completo | Saída: interativa / imprimível</div>
        <div>Modo: {mode === "scan" ? "Por scan" : "Por alvo"} | Severidade: todas | Janela: histórico completo</div>
        <div>Scan base: {scanId ? `#${scanId}` : "não selecionado"} {compareScanId ? `| comparação: #${compareScanId}` : "| sem comparação"}</div>
        <div>Alvos incluídos: {effectiveIncludeTargets.length > 0 ? effectiveIncludeTargets.join(", ") : "todos do scan"}</div>
      </div>

      {mode === "scan" && selectedScan && (
        <div style={{ display: "flex", gap: 20, padding: "8px 14px", background: "#ffffff", border: "1px solid var(--line)", borderRadius: 8, fontSize: 12, color: "var(--ink-muted)", flexWrap: "wrap" }}>
          <span><strong style={{ color: "var(--ink)" }}>Alvo:</strong> {selectedScan.target_query || "—"}</span>
          <span><strong style={{ color: "var(--ink)" }}>Status:</strong> <span style={{ color: selectedScan.status === "completed" ? "var(--sev-low-text)" : selectedScan.status === "failed" ? "var(--sev-critical-text)" : "var(--sev-medium-text)", fontWeight: 600 }}>{selectedScan.status}</span></span>
          <span><strong style={{ color: "var(--ink)" }}>Criado em:</strong> {selectedScan.created_at ? new Date(selectedScan.created_at).toLocaleString("pt-BR", { timeZone: "America/Sao_Paulo" }) : "—"}</span>
        </div>
      )}

      {/* ── Attack Narrative Panel ──────────────────────────────────────────── */}
      {scanId && (
        <div style={{ ...reportCard }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 10 }}>
            <div>
              <div style={{ fontWeight: 700, fontSize: 14 }}>
                📖 Narrativa de Ataque
                {narrativeMethod && (
                  <span style={{ fontWeight: 400, fontSize: 11, color: "var(--ink-muted)", marginLeft: 6 }}>
                    via {narrativeMethod}
                  </span>
                )}
              </div>
              <div style={{ fontSize: 12, color: "var(--ink-muted)", marginTop: 2 }}>
                Relatório em linguagem natural gerado por LLM — kill chain, achados críticos, remediações
              </div>
            </div>
            <div style={{ display: "flex", gap: 8 }}>
              {narrative && (
                <button
                  type="button"
                  onClick={() => setShowNarrative((v) => !v)}
                  style={{ padding: "6px 14px", borderRadius: 8, border: "1px solid var(--line)", background: "transparent", fontSize: 12, cursor: "pointer", color: "var(--ink-soft)" }}
                >
                  {showNarrative ? "▲ Ocultar" : "▼ Mostrar narrativa"}
                </button>
              )}
              <button
                type="button"
                onClick={generateNarrative}
                disabled={generatingNarrative || !scanId}
                style={{ padding: "6px 14px", borderRadius: 8, border: "none", background: "var(--brand-500)", color: "#fff", fontSize: 12, fontWeight: 600, cursor: "pointer", opacity: generatingNarrative ? 0.6 : 1 }}
              >
                {generatingNarrative ? "⟳ Gerando…" : narrative ? "↻ Regenerar" : "⚡ Gerar Narrativa"}
              </button>
            </div>
          </div>
          {narrativeError && <div style={{ color: "#dc2626", fontSize: 12, marginTop: 8 }}>{narrativeError}</div>}
          {showNarrative && narrative && (
            <div style={{
              marginTop: 14,
              fontFamily: "var(--font-mono)", fontSize: 12.5, lineHeight: 1.7,
              whiteSpace: "pre-wrap", maxHeight: 520, overflowY: "auto",
              background: "#0f172a", color: "#e2e8f0",
              padding: "16px 18px", borderRadius: 8,
            }}>
              {narrative}
            </div>
          )}
          {!narrative && !generatingNarrative && (
            <div style={{ marginTop: 10, fontSize: 12, color: "var(--ink-muted)" }}>
              Narrativa não gerada ainda para este scan. Clique em "⚡ Gerar Narrativa" para criar.
              Requer Ollama rodando com <code>llama3.2:3b</code> ou configure <code>LLM_OPERATOR_ENABLED=true</code>.
            </div>
          )}
        </div>
      )}

      {/* ── Pentest Report direct link ─────────────────────────────────────── */}
      {scanId && (
        <div style={{ ...reportCard, background: "linear-gradient(135deg,#1a1a2e 0%,#2d1b3d 100%)", border: "1px solid #4a1942", display: "flex", alignItems: "center", gap: 16, flexWrap: "wrap" }}>
          <div style={{ flex: 1, minWidth: 200 }}>
            <div style={{ fontWeight: 700, fontSize: 14, color: "#ffffff" }}>
              🔴 Relatório ScriptKidd.o
            </div>
            <div style={{ fontSize: 12, color: "#c8a4e0", marginTop: 3 }}>
              Vulnerabilidades confirmadas com PoC · Kill chain · Evidência sandbox P21 · Matriz Blue Team · CVSS · Delta cross-scan
            </div>
          </div>
          <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
            <a
              href={`${apiUrl}/api/scans/${scanId}/pentest-report${compareScanId ? `?previous_scan_id=${compareScanId}` : ""}`}
              target="_blank"
              rel="noopener noreferrer"
              style={{ padding: "8px 18px", borderRadius: 8, background: "#c0392b", color: "#fff", fontWeight: 700, fontSize: 13, textDecoration: "none", border: "none", display: "inline-block", cursor: "pointer" }}
            >
              Abrir Relatório Pentest
            </a>
            <a
              href={`${apiUrl}/api/scans/${scanId}/pentest-report${compareScanId ? `?previous_scan_id=${compareScanId}` : ""}`}
              download={`pentest-scan${scanId}.html`}
              style={{ padding: "8px 18px", borderRadius: 8, background: "transparent", color: "#c8a4e0", fontWeight: 600, fontSize: 13, textDecoration: "none", border: "1px solid #6a3060", display: "inline-block", cursor: "pointer" }}
            >
              Baixar HTML
            </a>
          </div>
          <div style={{ fontSize: 11, color: "#8a6080", width: "100%", marginTop: -4 }}>
            Scan #{scanId} · Endpoint: /api/scans/{scanId}/pentest-report
            {compareScanId ? ` · Delta vs #${compareScanId}` : ""}
          </div>
        </div>
      )}

      {reportUrl ? (
        <iframe id="report-iframe" key={reportUrl} src={reportUrl} title="Relatório" style={{ width: "100%", minHeight: "calc(100vh - 200px)", border: "1px solid var(--line)", borderRadius: 10, background: "#ffffff", boxShadow: "var(--shadow-card)" }} />
      ) : (
        <div style={{ padding: 40, textAlign: "center", color: "var(--ink-muted)", border: "1px dashed var(--line-strong)", borderRadius: 10, fontSize: 14, background: "#ffffff" }}>
          {mode === "scan" ? (loadingScans ? "Carregando scans…" : "Selecione um scan para gerar o relatório.") : "Selecione ou digite um alvo e clique em Gerar."}
        </div>
      )}
    </div>
  );
}
