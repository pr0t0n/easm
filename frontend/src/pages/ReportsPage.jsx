// ReportsPage: extração de relatórios por scan ou por alvo/subdomínio.
// Para visualização de evolução temporal → /evolucao
import { useEffect, useMemo, useRef, useState } from "react";
import client from "../api/client";

function resolveApiBaseUrl() {
  const byClient = String(client.defaults?.baseURL || "").trim();
  if (byClient) return byClient.replace(/\/$/, "");
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

const PERSONA_LABEL = {
  executive: "Executivo",
  technical: "Técnico",
  compliance: "Compliance",
};

const OUTPUT_LABEL = {
  visual: "Interativo",
  pdf_exec: "PDF Executivo",
  pdf_tech: "PDF Técnico",
};

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
  const [wizardStep, setWizardStep] = useState(1);
  const [persona, setPersona] = useState("executive");
  const [outputMode, setOutputMode] = useState("visual");
  const [severityMin, setSeverityMin] = useState("all");
  const [periodDays, setPeriodDays] = useState("all");
  const [compareScanId, setCompareScanId] = useState("");
  const [mode, setMode] = useState("scan");
  const [scans, setScans] = useState([]);
  const [selectedId, setSelectedId] = useState("");
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
  const inputRef = useRef(null);

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

  useEffect(() => {
    if (targets.length > 0) return;
    let ok = true;
    setLoadingTargets(true);
    client
      .get("/api/reports/by-target")
      .then(({ data }) => ok && setTargets(Array.isArray(data) ? data : []))
      .finally(() => ok && setLoadingTargets(false));
    return () => { ok = false; };
  }, [targets.length]);

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
      persona,
      output_mode: outputMode,
      severity_min: severityMin,
      period_days: periodDays,
    });
    if (effectiveIncludeTargets.length > 0) {
      params.set("include_targets", effectiveIncludeTargets.join(","));
    }
    if (compareScanId) {
      params.set("compare_scan_id", String(compareScanId));
    }
    return `/custom-report/index.html?${params.toString()}`;
  }, [scanId, apiUrl, effectiveIncludeTargets, persona, outputMode, severityMin, periodDays, compareScanId]);

  const scopeReady = useMemo(() => {
    if (!scanId) return false;
    if (mode === "target" && !targetInput.trim()) return false;
    return true;
  }, [scanId, mode, targetInput]);

  const stepTitle = useMemo(() => {
    if (wizardStep === 1) return "Defina objetivo e formato";
    if (wizardStep === 2) return "Escolha escopo e alvo";
    return "Revise e gere o relatório";
  }, [wizardStep]);

  const openNewTab = () => reportUrl && window.open(reportUrl, "_blank", "noopener,noreferrer");
  const printReport = () => {
    const f = document.getElementById("report-iframe");
    if (f?.contentWindow) { f.contentWindow.focus(); f.contentWindow.print(); }
  };

  const selectedScan = scans.find((s) => String(s.id) === String(selectedId));

  return (
    <div style={{ padding: 16, display: "grid", gap: 12, background: "var(--bg-main)", color: "var(--ink)" }}>
      <div style={{ ...reportCard, display: "grid", gap: 10 }}>
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 10, flexWrap: "wrap" }}>
          <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
            {[1, 2, 3].map((step) => (
              <button
                key={step}
                type="button"
                onClick={() => setWizardStep(step)}
                style={{
                  padding: "6px 10px",
                  borderRadius: 999,
                  border: `1px solid ${wizardStep === step ? "var(--brand-500)" : "var(--line)"}`,
                  background: wizardStep === step ? "var(--brand-500)" : "#ffffff",
                  color: wizardStep === step ? "#ffffff" : "var(--ink-soft)",
                  fontSize: 12,
                  cursor: "pointer",
                }}
              >
                {step}. {step === 1 ? "Objetivo" : step === 2 ? "Escopo" : "Revisão"}
              </button>
            ))}
          </div>
          <div style={{ color: "var(--ink-muted)", fontSize: 12 }}>{stepTitle}</div>
        </div>

        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(180px,1fr))", gap: 8 }}>
          <label style={controlLabel}>
            Persona
            <select value={persona} onChange={(e) => setPersona(e.target.value)} style={{ ...controlInput, fontSize: 12 }}>
              <option value="executive">Executivo</option>
              <option value="technical">Técnico</option>
              <option value="compliance">Compliance</option>
            </select>
          </label>
          <label style={controlLabel}>
            Formato de saída
            <select value={outputMode} onChange={(e) => setOutputMode(e.target.value)} style={{ ...controlInput, fontSize: 12 }}>
              <option value="visual">Interativo</option>
              <option value="pdf_exec">PDF Executivo</option>
              <option value="pdf_tech">PDF Técnico</option>
            </select>
          </label>
          <label style={controlLabel}>
            Severidade mínima
            <select value={severityMin} onChange={(e) => setSeverityMin(e.target.value)} style={{ ...controlInput, fontSize: 12 }}>
              <option value="all">Todas</option>
              <option value="critical">Crítica+</option>
              <option value="high">Alta+</option>
              <option value="medium">Média+</option>
              <option value="low">Baixa+</option>
            </select>
          </label>
          <label style={controlLabel}>
            Janela temporal
            <select value={periodDays} onChange={(e) => setPeriodDays(e.target.value)} style={{ ...controlInput, fontSize: 12 }}>
              <option value="all">Histórico completo</option>
              <option value="7">Últimos 7 dias</option>
              <option value="30">Últimos 30 dias</option>
              <option value="90">Últimos 90 dias</option>
            </select>
          </label>
        </div>
      </div>

      <div style={{ ...reportCard, display: "flex", flexWrap: "wrap", gap: 8, alignItems: "center" }}>
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
        <button
          type="button"
          onClick={() => setWizardStep((prev) => Math.max(1, prev - 1))}
          disabled={wizardStep === 1}
          className="app-btn-secondary rounded-lg border px-3 py-2 text-sm disabled:cursor-not-allowed disabled:opacity-50"
        >
          Voltar
        </button>
        <button
          type="button"
          onClick={() => setWizardStep((prev) => Math.min(3, prev + 1))}
          disabled={wizardStep === 3}
          className="app-btn-secondary rounded-lg border px-3 py-2 text-sm disabled:cursor-not-allowed disabled:opacity-50"
        >
          Avançar
        </button>
        <button type="button" onClick={openNewTab} disabled={!reportUrl || !scopeReady || wizardStep < 3} className="app-btn-secondary rounded-lg border px-3 py-2 text-sm disabled:cursor-not-allowed disabled:opacity-50">Abrir em nova aba</button>
        <button type="button" onClick={printReport} disabled={!reportUrl || !scopeReady || wizardStep < 3} className="app-btn-primary rounded-lg border px-3 py-2 text-sm font-semibold disabled:cursor-not-allowed disabled:opacity-50">Imprimir / PDF</button>
      </div>

      <div style={{ position: "sticky", top: 8, zIndex: 4, background: "rgba(255,255,255,0.94)", border: "1px solid var(--line)", borderRadius: 10, padding: "10px 12px", display: "grid", gap: 3, fontSize: 12, color: "var(--ink-muted)", boxShadow: "var(--shadow-card)", backdropFilter: "blur(8px)" }}>
        <div style={{ color: "var(--ink)", fontWeight: 600 }}>Resumo do escopo</div>
        <div>Persona: {PERSONA_LABEL[persona] || persona} | Saída: {OUTPUT_LABEL[outputMode] || outputMode}</div>
        <div>Modo: {mode === "scan" ? "Por scan" : "Por alvo"} | Severidade mínima: {severityMin} | Janela: {periodDays === "all" ? "completa" : `${periodDays} dias`}</div>
        <div>Scan base: {scanId ? `#${scanId}` : "não selecionado"} {compareScanId ? `| comparação: #${compareScanId}` : "| sem comparação"}</div>
        <div>Alvos incluídos: {effectiveIncludeTargets.length > 0 ? effectiveIncludeTargets.join(", ") : "todos do scan"}</div>
      </div>

      {mode === "scan" && selectedScan && (
        <div style={{ display: "flex", gap: 20, padding: "8px 14px", background: "#ffffff", border: "1px solid var(--line)", borderRadius: 8, fontSize: 12, color: "var(--ink-muted)", flexWrap: "wrap" }}>
          <span><strong style={{ color: "var(--ink)" }}>Alvo:</strong> {selectedScan.target_query || "—"}</span>
          <span><strong style={{ color: "var(--ink)" }}>Status:</strong> <span style={{ color: selectedScan.status === "completed" ? "var(--sev-low-text)" : selectedScan.status === "failed" ? "var(--sev-critical-text)" : "var(--sev-medium-text)", fontWeight: 600 }}>{selectedScan.status}</span></span>
          <span><strong style={{ color: "var(--ink)" }}>Criado em:</strong> {selectedScan.created_at ? new Date(selectedScan.created_at).toLocaleString("pt-BR") : "—"}</span>
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
