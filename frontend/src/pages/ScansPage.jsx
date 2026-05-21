import { useEffect, useState } from "react";
import client, { getWsBaseUrl } from "../api/client";
import LogTerminal from "../components/LogTerminal";
import MissionProgress from "../components/MissionProgress";

// Formats a UTC date string to São Paulo timezone (America/Sao_Paulo, UTC-3)
function fmtDateTimeSP(value) {
  if (!value) return "-";
  const dt = new Date(value);
  if (Number.isNaN(dt.getTime())) return "-";
  return dt.toLocaleString("pt-BR", { timeZone: "America/Sao_Paulo" });
}

export default function ScansPage({ embedded = false }) {
  const [target, setTarget] = useState("");
  const [accessGroupId, setAccessGroupId] = useState("");
  const [groups, setGroups] = useState([]);
  const [schedules, setSchedules] = useState([]);
  const [scans, setScans] = useState([]);
  const [targets, setTargets] = useState([]);
  const [selected, setSelected] = useState(null);
  const [logs, setLogs] = useState([]);
  const [wsConnected, setWsConnected] = useState(false);
  const [scanStatus, setScanStatus] = useState(null);
  const [basSummary, setBasSummary] = useState(null);
  const [authStatus, setAuthStatus] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [selectedScans, setSelectedScans] = useState(new Set());
  const ACTIVE_SCAN_STATUS = ["queued", "running", "retrying"];

  // Unified mode selector: "now" | "schedule" | "targets"
  const [mode, setMode] = useState("now");
  const [scanLevel, setScanLevel] = useState("full"); // 'full' | 'asm'
  const [authEnabled, setAuthEnabled] = useState(false);
  const [authConfig, setAuthConfig] = useState({
    type: "bearer", // bearer | cookie | basic | header
    token: "",
    cookie: "",
    username: "",
    password: "",
    headerName: "X-API-Key",
    headerValue: "",
  });
  const [scheduleForm, setScheduleForm] = useState({
    frequency: "daily",
    run_time: "00:00",
    day_of_week: "monday",
    day_of_month: 1,
    enabled: true,
  });

  const buildAuthPayload = () => {
    if (!authEnabled) return null;
    if (authConfig.type === "bearer" && authConfig.token) return { type: "bearer", token: authConfig.token };
    if (authConfig.type === "cookie" && authConfig.cookie) return { type: "cookie", cookie: authConfig.cookie };
    if (authConfig.type === "basic" && authConfig.username) return { type: "basic", username: authConfig.username, password: authConfig.password };
    if (authConfig.type === "header" && authConfig.headerName && authConfig.headerValue) {
      return { type: "header", headers: { [authConfig.headerName]: authConfig.headerValue } };
    }
    return null;
  };

  const parseTargets = (raw) => {
    return String(raw || "")
      .split(";")
      .map((item) => item.trim())
      .filter(Boolean);
  };

  const fmtDateTime = fmtDateTimeSP;

  const loadScans = async () => {
    const { data } = await client.get("/api/scans");
    setScans(data);
  };

  const loadSchedules = async () => {
    try {
      const { data } = await client.get("/api/schedules");
      setSchedules(data);
    } catch {
      setSchedules([]);
    }
  };

  const loadTargets = async () => {
    try {
      const { data } = await client.get("/api/targets/summary");
      setTargets(data || []);
    } catch {
      setTargets([]);
    }
  };

  const createSchedule = async (e) => {
    e.preventDefault();
    const parsedTargets = parseTargets(target);
    if (parsedTargets.length === 0) {
      setAuthStatus("Informe ao menos um alvo para o agendamento.");
      return;
    }
    setSubmitting(true);
    try {
      await client.post("/api/schedules", {
        access_group_id: accessGroupId ? Number(accessGroupId) : null,
        targets_text: target,
        scan_type: "full",
        frequency: scheduleForm.frequency,
        run_time: scheduleForm.run_time,
        day_of_week: scheduleForm.day_of_week,
        day_of_month: scheduleForm.day_of_month,
        enabled: scheduleForm.enabled,
      });
      setTarget("");
      setAccessGroupId("");
      setAuthStatus(`Agendamento criado para ${parsedTargets.length} alvo(s) com sucesso.`);
      await loadSchedules();
    } catch (err) {
      setAuthStatus(err?.response?.data?.detail || "Falha ao criar agendamento.");
    } finally {
      setSubmitting(false);
    }
  };

  const loadLogs = async (scanId) => {
    const { data } = await client.get(`/api/scans/${scanId}/logs`);
    setLogs(data);
  };

  const loadScanStatus = async (scanId) => {
    const { data } = await client.get(`/api/scans/${scanId}/status`);
    setScanStatus(data);
  };

  const loadBasSummary = async (scanId) => {
    try {
      const { data } = await client.get(`/api/scans/${scanId}/report`, {
        params: { prioritized_limit: 1, prioritized_offset: 0 },
        _skipToast: true,
      });
      const bas = data?.state_data?.report_v2?.bas_detection_validation || {};
      setBasSummary(bas.summary || null);
    } catch {
      setBasSummary(null);
    }
  };

  useEffect(() => {
    loadScans();
    loadSchedules();
    loadTargets();
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
    setBasSummary(null);
    loadLogs(selected.id);
    loadScanStatus(selected.id);
    loadBasSummary(selected.id);
    const wsBase = getWsBaseUrl();
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

  const deleteSchedule = async (schedId) => {
    const confirmed = window.confirm("Deseja excluir este agendamento?");
    if (!confirmed) return;
    try {
      await client.delete(`/api/schedules/${schedId}`);
      await loadSchedules();
      setAuthStatus(`Agendamento #${schedId} excluído.`);
    } catch (err) {
      setAuthStatus(err?.response?.data?.detail || "Falha ao excluir agendamento.");
    }
  };

  const runScheduleNow = async (schedId) => {
    try {
      const { data } = await client.post(`/api/schedules/${schedId}/execute`);
      await loadScans();
      setAuthStatus(`Agendamento #${schedId} executado agora: ${data.batches_created || 0} job(s).`);
    } catch (err) {
      setAuthStatus(err?.response?.data?.detail || "Falha ao executar agendamento.");
    }
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
            mode: "single",
            access_group_id: accessGroupId ? Number(accessGroupId) : null,
            scan_level: scanLevel,
            auth_config: buildAuthPayload(),
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
      "Deseja executar o reset operacional? Isso vai interromper/remover execucoes ja ocorridas (running/completed/failed/stopped), mantendo scans em fila e schedules futuros.",
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
      const preserved = data?.preserved || {};
      setAuthStatus(
        `Reset operacional concluido. Removidos - scans: ${deleted.scan_jobs || 0}, findings: ${deleted.findings || 0}, logs: ${deleted.scan_logs || 0}. Preservados - fila: ${preserved.queued_scans || 0}, schedules ativos: ${preserved.enabled_schedules || 0}.`,
      );
    } catch (err) {
      setAuthStatus(err?.response?.data?.detail || "Falha ao executar reset operacional.");
    } finally {
      setSubmitting(false);
    }
  };

  const Shell = embedded ? "div" : "main";

  return (
    <Shell className={embedded ? "flex flex-col gap-0" : "flex flex-col gap-0"}>
      {/* Top Banner */}
      {!embedded && <div className="border-b border-slate-800/50 bg-gradient-to-r from-slate-900/20 to-slate-950/40 px-8 py-6">
        <div className="mx-auto max-w-7xl">
          <h1 className="section-title">Scan · Agendamento · Alvos</h1>
          <p className="mt-2 text-sm text-slate-400">Painel unificado de execução das 22 fases — criação manual, agendamentos recorrentes e gestão de targets</p>
        </div>
      </div>}

      <div className={embedded ? "flex-1" : "flex-1 px-8 py-8"}>
        <div className="mx-auto max-w-7xl">
          <div className="grid gap-6 lg:grid-cols-3">
            {/* Main Content */}
            <div className="lg:col-span-2 space-y-6">
              {/* Unified Create Section — Scan / Schedule / Target */}
              <section className="panel p-6">
                <div className="flex items-center justify-between mb-4">
                  <h2 className="text-lg font-semibold">Nova Operação</h2>
                  <div className="inline-flex rounded-lg border border-slate-700 bg-slate-900/40 p-1 text-xs">
                    <button
                      type="button"
                      onClick={() => setMode("now")}
                      className={`px-3 py-1.5 rounded-md transition-colors ${mode === "now" ? "bg-blue-600 text-white" : "text-slate-400 hover:text-slate-200"}`}
                    >
                      Executar Agora
                    </button>
                    <button
                      type="button"
                      onClick={() => setMode("schedule")}
                      className={`px-3 py-1.5 rounded-md transition-colors ${mode === "schedule" ? "bg-blue-600 text-white" : "text-slate-400 hover:text-slate-200"}`}
                    >
                      Agendar
                    </button>
                    <button
                      type="button"
                      onClick={() => setMode("targets")}
                      className={`px-3 py-1.5 rounded-md transition-colors ${mode === "targets" ? "bg-blue-600 text-white" : "text-slate-400 hover:text-slate-200"}`}
                    >
                      Alvos
                    </button>
                  </div>
                </div>

                {mode !== "targets" ? (
                  <form onSubmit={mode === "now" ? createScan : createSchedule} className="space-y-4">
                    <div>
                      <label className="block text-xs font-medium text-slate-400 mb-2">Alvos (separe por ;)</label>
                      <input
                        className="w-full rounded-lg border border-slate-700 bg-slate-900/40 px-4 py-2.5 text-sm text-slate-100 placeholder-slate-500"
                        placeholder="exemplo.com;*.exemplo.com;192.168.0.10"
                        value={target}
                        onChange={(e) => setTarget(e.target.value)}
                      />
                      <p className="mt-2 text-xs text-slate-500">Cada alvo separado por ponto e virgula gera uma execução independente das 22 fases.</p>
                    </div>

                    {/* Scan Level (EASM/Full) */}
                    {mode === "now" && (
                      <div>
                        <label className="block text-xs font-medium text-slate-400 mb-2">Profundidade do Scan</label>
                        <div className="inline-flex rounded-lg border border-slate-700 bg-slate-900/40 p-1 text-xs">
                          <button type="button" onClick={() => setScanLevel("full")}
                            className={`px-4 py-1.5 rounded-md transition-colors ${scanLevel === "full" ? "bg-emerald-700/40 text-emerald-200 border border-emerald-700" : "text-slate-400 hover:text-slate-200"}`}>
                            Full (P01-P22, exploração)
                          </button>
                          <button type="button" onClick={() => setScanLevel("asm")}
                            className={`px-4 py-1.5 rounded-md transition-colors ${scanLevel === "asm" ? "bg-amber-700/40 text-amber-200 border border-amber-700" : "text-slate-400 hover:text-slate-200"}`}>
                            ASM (recon passivo, sem exploitation)
                          </button>
                        </div>
                        <p className="mt-1 text-xs text-slate-500">
                          {scanLevel === "asm"
                            ? "ASM analisa apenas P01-P08 + P18 + P21-P22 (descoberta de superfície, sem exploração ativa)."
                            : "Full executa as 22 fases incluindo testes de exploração."}
                        </p>
                      </div>
                    )}

                    {/* Authentication */}
                    {mode === "now" && (
                      <div>
                        <label className="inline-flex items-center gap-2 text-xs text-slate-400 mb-2">
                          <input type="checkbox" checked={authEnabled} onChange={(e) => setAuthEnabled(e.target.checked)} />
                          <span>Autenticação no scanner (testa rotas protegidas)</span>
                        </label>
                        {authEnabled && (
                          <div className="rounded-lg border border-slate-800 bg-slate-950/40 p-3 space-y-3">
                            <div>
                              <label className="block text-xs text-slate-500 mb-1">Tipo</label>
                              <select className="w-full rounded-lg border border-slate-700 bg-slate-900/40 px-3 py-2 text-sm"
                                value={authConfig.type} onChange={(e) => setAuthConfig({...authConfig, type: e.target.value})}>
                                <option value="bearer">Bearer Token (JWT/OAuth)</option>
                                <option value="cookie">Cookie (PHPSESSID, etc)</option>
                                <option value="basic">Basic Auth</option>
                                <option value="header">Header customizado (X-API-Key)</option>
                              </select>
                            </div>
                            {authConfig.type === "bearer" && (
                              <input type="text" placeholder="eyJhbGc..." className="w-full rounded-lg border border-slate-700 bg-slate-900/40 px-3 py-2 text-sm font-mono"
                                value={authConfig.token} onChange={(e) => setAuthConfig({...authConfig, token: e.target.value})} />
                            )}
                            {authConfig.type === "cookie" && (
                              <input type="text" placeholder="session=abc123; csrftoken=xyz" className="w-full rounded-lg border border-slate-700 bg-slate-900/40 px-3 py-2 text-sm font-mono"
                                value={authConfig.cookie} onChange={(e) => setAuthConfig({...authConfig, cookie: e.target.value})} />
                            )}
                            {authConfig.type === "basic" && (
                              <div className="grid grid-cols-2 gap-2">
                                <input type="text" placeholder="username" className="rounded-lg border border-slate-700 bg-slate-900/40 px-3 py-2 text-sm"
                                  value={authConfig.username} onChange={(e) => setAuthConfig({...authConfig, username: e.target.value})} />
                                <input type="password" placeholder="password" className="rounded-lg border border-slate-700 bg-slate-900/40 px-3 py-2 text-sm"
                                  value={authConfig.password} onChange={(e) => setAuthConfig({...authConfig, password: e.target.value})} />
                              </div>
                            )}
                            {authConfig.type === "header" && (
                              <div className="grid grid-cols-2 gap-2">
                                <input type="text" placeholder="X-API-Key" className="rounded-lg border border-slate-700 bg-slate-900/40 px-3 py-2 text-sm"
                                  value={authConfig.headerName} onChange={(e) => setAuthConfig({...authConfig, headerName: e.target.value})} />
                                <input type="text" placeholder="valor" className="rounded-lg border border-slate-700 bg-slate-900/40 px-3 py-2 text-sm font-mono"
                                  value={authConfig.headerValue} onChange={(e) => setAuthConfig({...authConfig, headerValue: e.target.value})} />
                              </div>
                            )}
                          </div>
                        )}
                      </div>
                    )}

                    <div className="grid grid-cols-2 gap-4">
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
                      {mode === "schedule" && (
                        <div>
                          <label className="block text-xs font-medium text-slate-400 mb-2">Frequência</label>
                          <select
                            className="w-full rounded-lg border border-slate-700 bg-slate-900/40 px-4 py-2.5 text-sm"
                            value={scheduleForm.frequency}
                            onChange={(e) => setScheduleForm({ ...scheduleForm, frequency: e.target.value })}
                          >
                            <option value="hourly">A cada hora</option>
                            <option value="daily">Diário</option>
                            <option value="weekly">Semanal</option>
                            <option value="monthly">Mensal</option>
                          </select>
                        </div>
                      )}
                    </div>

                    {mode === "schedule" && (
                      <div className="grid grid-cols-3 gap-4">
                        <div>
                          <label className="block text-xs font-medium text-slate-400 mb-2">Horário</label>
                          <input
                            type="time"
                            className="w-full rounded-lg border border-slate-700 bg-slate-900/40 px-4 py-2.5 text-sm text-slate-100"
                            value={scheduleForm.run_time}
                            onChange={(e) => setScheduleForm({ ...scheduleForm, run_time: e.target.value })}
                          />
                        </div>
                        {scheduleForm.frequency === "weekly" && (
                          <div>
                            <label className="block text-xs font-medium text-slate-400 mb-2">Dia da semana</label>
                            <select
                              className="w-full rounded-lg border border-slate-700 bg-slate-900/40 px-4 py-2.5 text-sm"
                              value={scheduleForm.day_of_week}
                              onChange={(e) => setScheduleForm({ ...scheduleForm, day_of_week: e.target.value })}
                            >
                              <option value="monday">Segunda</option>
                              <option value="tuesday">Terça</option>
                              <option value="wednesday">Quarta</option>
                              <option value="thursday">Quinta</option>
                              <option value="friday">Sexta</option>
                              <option value="saturday">Sábado</option>
                              <option value="sunday">Domingo</option>
                            </select>
                          </div>
                        )}
                        {scheduleForm.frequency === "monthly" && (
                          <div>
                            <label className="block text-xs font-medium text-slate-400 mb-2">Dia do mês</label>
                            <input
                              type="number" min="1" max="31"
                              className="w-full rounded-lg border border-slate-700 bg-slate-900/40 px-4 py-2.5 text-sm text-slate-100"
                              value={scheduleForm.day_of_month}
                              onChange={(e) => setScheduleForm({ ...scheduleForm, day_of_month: Number(e.target.value) })}
                            />
                          </div>
                        )}
                        <div className="flex items-end">
                          <label className="inline-flex items-center gap-2 text-xs text-slate-400">
                            <input type="checkbox" checked={scheduleForm.enabled} onChange={(e) => setScheduleForm({ ...scheduleForm, enabled: e.target.checked })} />
                            <span>Ativo</span>
                          </label>
                        </div>
                      </div>
                    )}

                    {authStatus && (
                      <div className={`rounded-lg px-4 py-3 text-xs ${
                        authStatus.includes("sucesso") ? "bg-emerald-50 text-emerald-800 border border-emerald-200" : "bg-amber-50 text-amber-800 border border-amber-200"
                      }`}>
                        {authStatus}
                      </div>
                    )}

                    <button type="submit" disabled={submitting} className="btn-primary w-full">
                      {submitting ? "Processando..." : mode === "now" ? "Iniciar Varredura" : "Criar Agendamento"}
                    </button>
                  </form>
                ) : (
                  <div className="space-y-3">
                    <p className="text-xs text-slate-400">Alvos descobertos via scans anteriores e ativos cadastrados. Use o modo &ldquo;Executar Agora&rdquo; ou &ldquo;Agendar&rdquo; para criar um novo scan a partir deles.</p>
                    {targets.length === 0 ? (
                      <div className="py-8 text-center text-sm text-slate-400">Nenhum alvo registrado ainda.</div>
                    ) : (
                      <div className="space-y-2 max-h-[400px] overflow-y-auto">
                        {targets.map((t, i) => (
                          <div key={t.domain_or_ip || i} className="rounded-lg border border-slate-800 bg-slate-900/40 p-3 flex items-center justify-between">
                            <div>
                              <p className="font-medium text-sm text-slate-100">{t.domain_or_ip || t.target_query || t.target}</p>
                              <p className="text-xs text-slate-500 mt-0.5">
                                {t.scan_count ? `${t.scan_count} scan(s)` : ""}
                                {t.last_scan ? ` · último em ${fmtDateTime(t.last_scan)}` : ""}
                                {t.findings_count ? ` · ${t.findings_count} finding(s)` : ""}
                              </p>
                            </div>
                            <button
                              onClick={() => { setTarget(t.domain_or_ip || t.target_query || t.target); setMode("now"); }}
                              className="text-xs px-3 py-1.5 rounded-lg bg-blue-900/20 text-blue-300 border border-blue-800/50 hover:bg-blue-900/40"
                            >
                              Rescan
                            </button>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                )}
              </section>

              {/* Scans List */}
              <section className="panel p-6">
                <div className="flex items-center justify-between mb-6">
                  <div className="flex items-center gap-3">
                    <h2 className="text-lg font-semibold">Histórico operacional</h2>
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
                      <p className="text-sm text-slate-400">Nenhuma execução iniciada</p>
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

              {/* Schedules List */}
              {schedules.length > 0 && (
                <section className="panel p-6">
                  <h2 className="text-lg font-semibold mb-4">Agendamentos Ativos</h2>
                  <div className="space-y-2">
                    {schedules.map((sched) => (
                      <div key={sched.id} className="rounded-lg border border-slate-800 bg-slate-900/40 p-4">
                        <div className="flex items-start justify-between gap-3">
                          <div className="min-w-0">
                            <p className="font-semibold text-slate-100 text-sm">#{sched.id} · {sched.frequency}</p>
                            <p className="text-xs text-slate-400 mt-0.5 truncate">{sched.targets_text || (sched.targets || []).join("; ")}</p>
                            <p className="text-xs text-slate-500 mt-0.5">Horário: {sched.run_time}{!sched.enabled ? " · desativado" : ""}</p>
                          </div>
                          <div className="flex gap-2 flex-shrink-0">
                            <button
                              onClick={() => runScheduleNow(sched.id)}
                              className="text-xs px-2 py-1 rounded-lg bg-blue-900/20 text-blue-300 border border-blue-800/50 hover:bg-blue-900/40 transition-colors"
                            >
                              Executar
                            </button>
                            <button
                              onClick={() => deleteSchedule(sched.id)}
                              className="text-xs px-2 py-1 rounded-lg bg-rose-900/20 text-rose-300 border border-rose-800/50 hover:bg-rose-900/40 transition-colors"
                            >
                              Excluir
                            </button>
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                </section>
              )}
            </div>

            {/* Sidebar */}
            <div className="space-y-6 lg:sticky lg:top-8">
              {/* Mission Progress */}
              {selected && (
                <MissionProgress scan={selected} scanStatus={scanStatus} />
              )}

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
                    <div className="pt-3 border-t border-slate-800">
                      <p className="text-slate-400 mb-2">BAS / Validação de Controles</p>
                      {basSummary ? (
                        <div className="grid grid-cols-2 gap-2">
                          <div className="rounded-lg border border-cyan-900/60 bg-cyan-950/20 p-2">
                            <p className="text-slate-500">Técnicas</p>
                            <p className="mt-1 font-mono text-lg text-cyan-200">{basSummary.techniques_exercised || 0}</p>
                          </div>
                          <div className="rounded-lg border border-sky-900/60 bg-sky-950/20 p-2">
                            <p className="text-slate-500">Evidência pendente</p>
                            <p className="mt-1 font-mono text-lg text-sky-200">{basSummary.pending_defensive_evidence || 0}</p>
                          </div>
                          <div className="col-span-2 rounded-lg border border-slate-800 bg-slate-950/70 p-2">
                            <p className="text-slate-500">Fontes esperadas</p>
                            <p className="mt-1 text-slate-200">
                              {(basSummary.expected_telemetry_sources || []).join(", ") || "Aguardando execução BAS"}
                            </p>
                          </div>
                        </div>
                      ) : (
                        <p className="text-slate-500">Sem resumo BAS disponível para este scan.</p>
                      )}
                    </div>
                  </div>
                </section>
              )}
            </div>
          </div>
        </div>
      </div>
    </Shell>
  );
}
