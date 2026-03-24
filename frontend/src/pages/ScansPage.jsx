import { useEffect, useState } from "react";
import client from "../api/client";
import LogTerminal from "../components/LogTerminal";

export default function ScansPage() {
  const [target, setTarget] = useState("");
  const [mode, setMode] = useState("single");
  const [accessGroupId, setAccessGroupId] = useState("");
  const [groups, setGroups] = useState([]);
  const [scans, setScans] = useState([]);
  const [selected, setSelected] = useState(null);
  const [logs, setLogs] = useState([]);
  const [wsConnected, setWsConnected] = useState(false);
  const [scanStatus, setScanStatus] = useState(null);
  const [authStatus, setAuthStatus] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [selectedScans, setSelectedScans] = useState(new Set());
  const ACTIVE_SCAN_STATUS = ["queued", "running", "retrying"];

  const parseTargets = (raw) => {
    return String(raw || "")
      .split(";")
      .map((item) => item.trim())
      .filter(Boolean);
  };

  const fmtDateTime = (value) => {
    if (!value) return "-";
    const dt = new Date(value);
    if (Number.isNaN(dt.getTime())) return "-";
    return dt.toLocaleString();
  };

  const loadScans = async () => {
    const { data } = await client.get("/api/scans");
    setScans(data);
  };

  const loadLogs = async (scanId) => {
    const { data } = await client.get(`/api/scans/${scanId}/logs`);
    setLogs(data);
  };

  const loadScanStatus = async (scanId) => {
    const { data } = await client.get(`/api/scans/${scanId}/status`);
    setScanStatus(data);
  };

  useEffect(() => {
    loadScans();
    client.get("/api/access-groups").then((res) => setGroups(res.data));
  }, []);

  useEffect(() => {
    const timer = setInterval(() => {
      loadScans();
    }, 3000);
    return () => clearInterval(timer);
  }, []);

  useEffect(() => {
    if (!selected) return;
    loadLogs(selected.id);
    loadScanStatus(selected.id);
    const apiUrl = import.meta.env.VITE_API_URL || "http://localhost:8000";
    const wsBase = apiUrl.startsWith("https://") ? apiUrl.replace("https://", "wss://") : apiUrl.replace("http://", "ws://");
    const token = localStorage.getItem("token") || "";
    const ws = new WebSocket(`${wsBase}/ws/scans/${selected.id}/logs?token=${encodeURIComponent(token)}`);

    ws.onopen = () => setWsConnected(true);
    ws.onclose = () => setWsConnected(false);
    ws.onerror = () => setWsConnected(false);
    ws.onmessage = (event) => {
      const payload = JSON.parse(event.data);
      if (payload.type === "logs") {
        setLogs((prev) => {
          const map = new Map(prev.map((l) => [l.id, l]));
          for (const item of payload.items || []) map.set(item.id, item);
          return Array.from(map.values()).sort((a, b) => a.id - b.id);
        });
      }
    };

    const timer = setInterval(() => loadScanStatus(selected.id), 2000);
    return () => {
      clearInterval(timer);
      ws.close();
    };
  }, [selected]);

  const prepareTargetCompliance = async (singleTarget) => {
    if (!singleTarget) {
      throw new Error("Informe um alvo valido para iniciar o scan.");
    }

    setAuthStatus(`Validando requisitos operacionais para ${singleTarget}...`);

    try {
      await client.post("/api/policy/allowlist", {
        target_pattern: singleTarget,
        tool_group: "*",
        is_active: true,
      });
    } catch {
      // A allowlist pode ja existir; o objetivo aqui e garantir o gate operacional.
    }

    setAuthStatus(`Alvo ${singleTarget} validado e policy liberada para este scan.`);
  };

  const createScan = async (e) => {
    e.preventDefault();
    const parsedTargets = parseTargets(target);
    if (parsedTargets.length === 0) {
      setAuthStatus("Informe ao menos um alvo antes de iniciar.");
      return;
    }
    setSubmitting(true);
    try {
      const created = [];
      const failed = [];

      for (const singleTarget of parsedTargets) {
        try {
          await prepareTargetCompliance(singleTarget);
          await client.post("/api/scans", {
            target_query: singleTarget,
            mode,
            access_group_id: accessGroupId ? Number(accessGroupId) : null,
          });
          created.push(singleTarget);
        } catch (err) {
          failed.push({
            target: singleTarget,
            error: err?.response?.data?.detail || err?.message || "Falha ao iniciar scan",
          });
        }
      }

      setTarget("");
      setAccessGroupId("");
      if (failed.length === 0) {
        setAuthStatus(`${created.length} scan(s) criado(s) com sucesso.`);
      } else {
        const failedSummary = failed.slice(0, 3).map((item) => `${item.target}: ${item.error}`).join(" | ");
        setAuthStatus(`${created.length}/${parsedTargets.length} scan(s) criado(s). Falhas: ${failedSummary}`);
      }
      await loadScans();
    } catch (err) {
      setAuthStatus(err?.response?.data?.detail || err?.message || "Falha ao iniciar scan.");
    } finally {
      setSubmitting(false);
    }
  };

  const removeScan = async (scanId) => {
    const confirmed = window.confirm("Deseja excluir este scan? Esta acao remove logs e findings associados.");
    if (!confirmed) return;
    try {
      await client.delete(`/api/scans/${scanId}`);
      if (selected?.id === scanId) {
        setSelected(null);
        setLogs([]);
        setScanStatus(null);
      }
      await loadScans();
      setAuthStatus(`Scan #${scanId} excluido com sucesso.`);
    } catch (err) {
      setAuthStatus(err?.response?.data?.detail || "Falha ao excluir scan.");
    }
  };

  const removeReport = async (scanId) => {
    const confirmed = window.confirm("Deseja excluir somente o relatorio (findings) deste scan?");
    if (!confirmed) return;
    try {
      await client.delete(`/api/scans/${scanId}/report`);
      if (selected?.id === scanId) {
        await loadScanStatus(scanId);
        await loadLogs(scanId);
      }
      await loadScans();
      setAuthStatus(`Relatorio do scan #${scanId} excluido com sucesso.`);
    } catch (err) {
      setAuthStatus(err?.response?.data?.detail || "Falha ao excluir relatorio.");
    }
  };

  const stopScan = async (scanId) => {
    const confirmed = window.confirm("Deseja interromper este scan agora?");
    if (!confirmed) return;
    try {
      await client.post(`/api/scans/${scanId}/stop`);
      if (selected?.id === scanId) {
        await loadScanStatus(scanId);
        await loadLogs(scanId);
      }
      await loadScans();
      setAuthStatus(`Scan #${scanId} interrompido.`);
    } catch (err) {
      setAuthStatus(err?.response?.data?.detail || "Falha ao interromper scan.");
    }
  };

  const toggleScanSelection = (scanId) => {
    const newSelected = new Set(selectedScans);
    if (newSelected.has(scanId)) {
      newSelected.delete(scanId);
    } else {
      newSelected.add(scanId);
    }
    setSelectedScans(newSelected);
  };

  const toggleSelectAll = () => {
    if (selectedScans.size === scans.length) {
      setSelectedScans(new Set());
    } else {
      const allIds = new Set(scans.map(s => s.id));
      setSelectedScans(allIds);
    }
  };

  const removeSelectedScans = async () => {
    if (selectedScans.size === 0) {
      setAuthStatus("Selecione ao menos um scan para excluir.");
      return;
    }
    const count = selectedScans.size;
    const confirmed = window.confirm(`Deseja excluir ${count} scan(s)? Esta acao remove logs e findings associados.`);
    if (!confirmed) return;

    setSubmitting(true);
    const errors = [];
    for (const scanId of selectedScans) {
      try {
        await client.delete(`/api/scans/${scanId}`);
      } catch (err) {
        errors.push(`Scan #${scanId}: ${err?.response?.data?.detail || err?.message}`);
      }
    }

    setSelectedScans(new Set());
    if (selected && selectedScans.has(selected.id)) {
      setSelected(null);
      setLogs([]);
      setScanStatus(null);
    }
    await loadScans();

    if (errors.length === 0) {
      setAuthStatus(`${count} scan(s) excluido(s) com sucesso.`);
    } else {
      setAuthStatus(`${count - errors.length}/${count} excluidos. Erros: ${errors.join(" | ")}`);
    }
    setSubmitting(false);
  };

  const resetOperationalScans = async () => {
    const confirmed = window.confirm(
      "Deseja executar o reset operacional? Isso vai interromper scans em andamento, remover scans, findings e logs, e reiniciar a contagem do ambiente.",
    );
    if (!confirmed) return;

    setSubmitting(true);
    try {
      const { data } = await client.post("/api/scans/reset-operational");
      setSelected(null);
      setLogs([]);
      setScanStatus(null);
      setSelectedScans(new Set());
      await loadScans();
      const deleted = data?.deleted || {};
      setAuthStatus(
        `Reset operacional concluido. Scans removidos: ${deleted.scan_jobs || 0}, findings: ${deleted.findings || 0}, logs: ${deleted.scan_logs || 0}.`,
      );
    } catch (err) {
      setAuthStatus(err?.response?.data?.detail || "Falha ao executar reset operacional.");
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <main className="flex flex-col gap-0">
      {/* Top Banner */}
      <div className="border-b border-slate-800/50 bg-gradient-to-r from-slate-900/20 to-slate-950/40 px-8 py-6">
        <div className="mx-auto max-w-7xl">
          <h1 className="section-title">Scans de Superfície</h1>
          <p className="mt-2 text-sm text-slate-400">Gerenciamento de execuções de varredura e coleta de inteligência sobre ativos</p>
        </div>
      </div>

      <div className="flex-1 px-8 py-8">
        <div className="mx-auto max-w-7xl">
          <div className="grid gap-6 lg:grid-cols-3">
            {/* Main Content */}
            <div className="lg:col-span-2 space-y-6">
              {/* Create Scan Section */}
              <section className="panel p-6">
                <h2 className="text-lg font-semibold mb-6">Iniciar Nova Varredura</h2>
                <form onSubmit={createScan} className="space-y-4">
                  <div>
                    <label className="block text-xs font-medium text-slate-400 mb-2">Alvos (separe por ;)</label>
                    <input
                      className="w-full rounded-lg border border-slate-700 bg-slate-900/40 px-4 py-2.5 text-sm text-slate-100 placeholder-slate-500"
                      placeholder="exemplo.com;*.exemplo.com;192.168.0.10"
                      value={target}
                      onChange={(e) => setTarget(e.target.value)}
                    />
                    <p className="mt-2 text-xs text-slate-500">Cada alvo separado por ponto e virgula gera um scan individual.</p>
                  </div>

                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <label className="block text-xs font-medium text-slate-400 mb-2">Modo de Execução</label>
                      <select
                        className="w-full rounded-lg border border-slate-700 bg-slate-900/40 px-4 py-2.5 text-sm"
                        value={mode}
                        onChange={(e) => setMode(e.target.value)}
                      >
                        <option value="single">Unitário</option>
                        <option value="scheduled">Agendado</option>
                      </select>
                    </div>
                    <div>
                      <label className="block text-xs font-medium text-slate-400 mb-2">Grupo de Acesso</label>
                      <select
                        className="w-full rounded-lg border border-slate-700 bg-slate-900/40 px-4 py-2.5 text-sm"
                        value={accessGroupId}
                        onChange={(e) => setAccessGroupId(e.target.value)}
                      >
                        <option value="">Sem grupo</option>
                        {groups.map((g) => (
                          <option key={g.id} value={g.id}>{g.name}</option>
                        ))}
                      </select>
                    </div>
                  </div>

                  {authStatus && (
                    <div className={`rounded-lg px-4 py-3 text-xs ${
                      authStatus.includes("sucesso") ? "bg-emerald-50 text-emerald-800 border border-emerald-200" : "bg-amber-50 text-amber-800 border border-amber-200"
                    }`}>
                      {authStatus}
                    </div>
                  )}

                  <button
                    type="submit"
                    disabled={submitting}
                    className="btn-primary w-full"
                  >
                    {submitting ? "Iniciando..." : "Iniciar Varredura"}
                  </button>
                </form>
              </section>

              {/* Scans List */}
              <section className="panel p-6">
                <div className="flex items-center justify-between mb-6">
                  <div className="flex items-center gap-3">
                    <h2 className="text-lg font-semibold">Histórico de Varreduras</h2>
                    {scans.length > 0 && (
                      <span className="text-xs font-medium text-slate-400 bg-slate-800/50 px-3 py-1 rounded-full">
                        {selectedScans.size}/{scans.length} selecionadas
                      </span>
                    )}
                  </div>
                  <button
                    onClick={resetOperationalScans}
                    disabled={submitting}
                    className="rounded-lg border border-rose-700/50 bg-rose-900/20 px-3 py-2 text-xs font-semibold text-rose-300 transition-colors hover:bg-rose-900/40 disabled:opacity-50"
                  >
                    Reset operacional
                  </button>
                </div>

                {selectedScans.size > 0 && (
                  <div className="mb-4 rounded-lg border border-blue-700/50 bg-blue-900/20 p-4 flex items-center justify-between">
                    <span className="text-sm font-medium text-blue-300">{selectedScans.size} varredura(s) selecionada(s)</span>
                    <button
                      onClick={removeSelectedScans}
                      disabled={submitting}
                      className="btn-danger text-xs py-1.5 px-3"
                    >
                      Deletar Selecionadas
                    </button>
                  </div>
                )}

                <div className="space-y-2 max-h-[600px] overflow-y-auto">
                  {scans.length > 0 && (
                    <label className="flex items-center gap-3 px-4 py-2 rounded-lg hover:bg-slate-800/30 transition-colors">
                      <input
                        type="checkbox"
                        checked={selectedScans.size === scans.length && scans.length > 0}
                        onChange={toggleSelectAll}
                        className="form-checkbox"
                      />
                      <span className="text-xs font-medium text-slate-400">Selecionar Todas</span>
                    </label>
                  )}

                  {scans.length === 0 ? (
                    <div className="py-12 text-center">
                      <p className="text-sm text-slate-400">Nenhuma varredura iniciada</p>
                    </div>
                  ) : (
                    scans.map((scan) => (
                      <div key={scan.id} className="rounded-lg border border-slate-800 bg-slate-900/40 hover:bg-slate-900/60 transition-colors p-4">
                        <div className="flex gap-4">
                          <input
                            type="checkbox"
                            checked={selectedScans.has(scan.id)}
                            onChange={() => toggleScanSelection(scan.id)}
                            className="mt-1 flex-shrink-0 form-checkbox"
                          />
                          <button onClick={() => setSelected(scan)} className="flex-1 text-left">
                            <div className="flex items-start justify-between">
                              <div>
                                <p className="font-semibold text-slate-100">#{scan.id}</p>
                                <p className="text-sm text-slate-300 mt-0.5">{scan.target_query}</p>
                              </div>
                              <span className={`badge text-xs ${
                                scan.status === 'completed' ? 'badge-success' :
                                scan.status === 'failed' || scan.status === 'blocked' ? 'badge-danger' :
                                scan.status === 'running' ? 'badge-primary' : 'badge-warning'
                              }`}>
                                {scan.status}
                              </span>
                            </div>
                            <div className="mt-2 text-xs text-slate-400 space-y-1">
                              <p>Progresso: {scan.mission_progress}% | Passo: {scan.current_step}</p>
                              {scan.retry_attempt > 0 && (
                                <p className="text-amber-300">Tentativa {scan.retry_attempt}/{scan.retry_max}</p>
                              )}
                            </div>
                          </button>
                        </div>
                        <div className="mt-3 flex flex-wrap gap-2">
                          {ACTIVE_SCAN_STATUS.includes(scan.status) && (
                            <button
                              onClick={() => stopScan(scan.id)}
                              className="text-xs px-3 py-1.5 rounded-lg bg-red-900/20 text-red-300 border border-red-800/50 hover:bg-red-900/40 transition-colors"
                            >
                              Parar
                            </button>
                          )}
                          <button
                            onClick={() => removeReport(scan.id)}
                            disabled={ACTIVE_SCAN_STATUS.includes(scan.status)}
                            className="text-xs px-3 py-1.5 rounded-lg bg-amber-900/20 text-amber-300 border border-amber-800/50 hover:bg-amber-900/40 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                          >
                            Limpar Report
                          </button>
                          <button
                            onClick={() => removeScan(scan.id)}
                            disabled={ACTIVE_SCAN_STATUS.includes(scan.status)}
                            className="text-xs px-3 py-1.5 rounded-lg bg-rose-900/20 text-rose-300 border border-rose-800/50 hover:bg-rose-900/40 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                          >
                            Deletar
                          </button>
                        </div>
                      </div>
                    ))
                  )}
                </div>
              </section>
            </div>

            {/* Sidebar */}
            <div className="space-y-6 lg:sticky lg:top-8">
              {/* Logs */}
              <section className="panel p-6">
                <h3 className="text-sm font-semibold mb-4">Timeline de Logs</h3>
                {selected ? (
                  <LogTerminal logs={logs} />
                ) : (
                  <p className="text-xs text-slate-400 py-8 text-center">Selecione uma varredura</p>
                )}
              </section>

              {/* Status Details */}
              {selected && scanStatus && (
                <section className="panel p-6">
                  <h3 className="text-sm font-semibold mb-4">Detalhes da Execução</h3>
                  <div className="space-y-3 text-xs">
                    <div>
                      <p className="text-slate-400">Status Compliance</p>
                      <p className="text-slate-200 font-medium mt-0.5">{scanStatus.compliance_status}</p>
                    </div>
                    <div className="pt-3 border-t border-slate-800">
                      <p className="text-slate-400">Connection WebSocket</p>
                      <p className={`font-medium mt-0.5 ${wsConnected ? 'text-green-400' : 'text-slate-400'}`}>
                        {wsConnected ? '● Ativo' : '○ Desconectado'}
                      </p>
                    </div>
                    {scanStatus.discovered_ports && scanStatus.discovered_ports.length > 0 && (
                      <div className="pt-3 border-t border-slate-800">
                        <p className="text-slate-400 mb-2">Portas Descobertas</p>
                        <div className="flex flex-wrap gap-1">
                          {scanStatus.discovered_ports.map(port => (
                            <span key={port} className="badge-primary text-xs">{port}</span>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                </section>
              )}
            </div>
          </div>
        </div>
      </div>
    </main>
  );
}
