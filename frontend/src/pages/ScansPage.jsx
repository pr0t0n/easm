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
  const [ownershipProof, setOwnershipProof] = useState("");
  const [authorizationCode, setAuthorizationCode] = useState("");
  const [requestAuthorizationCode, setRequestAuthorizationCode] = useState("");
  const [authStatus, setAuthStatus] = useState("");
  const [isAuthorizedForTarget, setIsAuthorizedForTarget] = useState(false);

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

  const authorizeTarget = async () => {
    if (!target || !ownershipProof) {
      setAuthStatus("Informe alvo e prova de ownership antes de autorizar.");
      return;
    }
    setAuthStatus("Solicitando autorizacao...");
    const req = await client.post("/api/compliance/authorizations/request", {
      target_query: target,
      ownership_proof: ownershipProof,
      notes: "Aprovacao administrativa via tela de scan",
    });
    const code = req.data.authorization_code;
    setRequestAuthorizationCode(code);
    await client.put(`/api/compliance/authorizations/${req.data.authorization_id}/approve`, {
      notes: "Aprovado pelo administrador para execucao.",
    });
    setIsAuthorizedForTarget(true);
    setAuthorizationCode(code);
    setAuthStatus(`Alvo autorizado. Codigo para este scan: ${code}`);
  };

  const createScan = async (e) => {
    e.preventDefault();
    await client.post("/api/scans", {
      target_query: target,
      authorization_code: authorizationCode,
      mode,
      access_group_id: accessGroupId ? Number(accessGroupId) : null,
    });
    setTarget("");
    setAccessGroupId("");
    setOwnershipProof("");
    setAuthorizationCode("");
    setRequestAuthorizationCode("");
    setIsAuthorizedForTarget(false);
    setAuthStatus("");
    await loadScans();
  };

  return (
    <main className="mx-auto mt-6 grid w-[95%] max-w-6xl gap-4 pb-10 lg:grid-cols-2">
      <section className="panel p-5">
        <h2 className="text-xl font-semibold">Novo Scan</h2>
        <form onSubmit={createScan} className="mt-4 space-y-3">
          <input
            className="w-full rounded-xl border border-slate-700 bg-slate-950 px-3 py-2"
            placeholder="empresa.com ou *.empresa.com"
            value={target}
            onChange={(e) => {
              setTarget(e.target.value);
              setIsAuthorizedForTarget(false);
            }}
          />
          <textarea
            className="w-full rounded-xl border border-slate-700 bg-slate-950 px-3 py-2"
            placeholder="Prova de ownership/autorizacao (ticket, link, documento, email formal)"
            rows={2}
            value={ownershipProof}
            onChange={(e) => {
              setOwnershipProof(e.target.value);
              setIsAuthorizedForTarget(false);
            }}
          />
          <input
            className="w-full rounded-xl border border-slate-700 bg-slate-950 px-3 py-2"
            placeholder="Codigo de autorizacao por scan"
            value={authorizationCode}
            onChange={(e) => {
              setAuthorizationCode(e.target.value);
              setIsAuthorizedForTarget(Boolean(e.target.value));
            }}
          />
          <select
            className="w-full rounded-xl border border-slate-700 bg-slate-950 px-3 py-2"
            value={mode}
            onChange={(e) => setMode(e.target.value)}
          >
            <option value="single">Unitario</option>
            <option value="scheduled">Agendado</option>
          </select>
          <select
            className="w-full rounded-xl border border-slate-700 bg-slate-950 px-3 py-2"
            value={accessGroupId}
            onChange={(e) => setAccessGroupId(e.target.value)}
          >
            <option value="">Sem grupo</option>
            {groups.map((g) => (
              <option key={g.id} value={g.id}>{g.name}</option>
            ))}
          </select>
          <button
            type="button"
            onClick={authorizeTarget}
            className="rounded-xl bg-amber-400 px-4 py-2 font-semibold text-slate-950"
          >
            Autorizar
          </button>
          {authStatus && <p className="text-xs text-slate-300">{authStatus}</p>}
          {requestAuthorizationCode && <p className="text-xs text-emerald-300">Codigo emitido: {requestAuthorizationCode}</p>}
          <button disabled={!isAuthorizedForTarget} className="rounded-xl bg-brand-500 px-4 py-2 font-semibold text-slate-950 disabled:cursor-not-allowed disabled:opacity-40">Iniciar</button>
        </form>

        <h3 className="mt-6 text-lg font-semibold">Execucoes</h3>
        <div className="mt-3 space-y-2">
          {scans.map((scan) => (
            <button
              key={scan.id}
              onClick={() => setSelected(scan)}
              className="w-full rounded-xl border border-slate-800 bg-slate-900/70 p-3 text-left"
            >
              <p className="font-medium">#{scan.id} - {scan.target_query}</p>
              <p className="text-xs text-slate-300">{scan.status} | grupo {scan.access_group_id || "-"} | {scan.current_step} | {scan.mission_progress}%</p>
            </button>
          ))}
        </div>
      </section>

      <section>{selected ? <LogTerminal logs={logs} /> : <div className="panel p-5">Selecione um scan.</div>}</section>

      {selected && scanStatus && (
        <section className="panel p-5 lg:col-span-2">
          <h3 className="text-lg font-semibold">Status de Execucao</h3>
          <p className="text-sm text-slate-300">Scan #{scanStatus.id} | status: {scanStatus.status} | compliance: {scanStatus.compliance_status}</p>
          <p className="text-sm text-slate-300">WebSocket logs: {wsConnected ? "conectado" : "desconectado"}</p>
          <p className="text-sm text-slate-300">Passo: {scanStatus.current_step} | progresso: {scanStatus.mission_progress}%</p>
          <p className="mt-2 text-sm text-slate-300">Portas descobertas: {(scanStatus.discovered_ports || []).join(", ") || "nenhuma"}</p>
          <p className="text-sm text-slate-300">Retestes pendentes: {(scanStatus.pending_port_tests || []).join(", ") || "nenhum"}</p>
        </section>
      )}
    </main>
  );
}
