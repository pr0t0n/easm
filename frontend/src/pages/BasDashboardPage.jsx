import { useEffect, useState } from "react";
import client from "../api/client";
import { authStore } from "../store/auth";
import { toastError, toastSuccess } from "../utils/toast";

const HEARTBEAT_INTERVAL_MS = 60_000;

const fieldStyle = {
  width: "100%", padding: "9px 12px", borderRadius: 8,
  border: "1px solid var(--line)", background: "var(--canvas)",
  fontSize: 13, color: "var(--ink)",
};

// Opening the dashboard via localhost/127.0.0.1 (common in local dev) is
// meaningless to a remote BAS agent, so never treat that as "the real IP".
const LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1", "::1"]);

// A saved callback_host override never expires on its own. window.location.hostname
// is the freshest proof of reachability there is -- the address that just
// successfully loaded this page. Once the saved value drifts from it, it's almost
// certainly a dead/stale IP from a network change rather than an intentional pin.
function isCallbackHostStale(cfg, browserHost) {
  if (!cfg?.callback_host || cfg.callback_host === "backend") return false;
  return cfg.callback_host !== browserHost && !LOOPBACK_HOSTS.has(browserHost);
}

export default function BasDashboardPage() {
  const [summary, setSummary] = useState(null);
  const [agents, setAgents] = useState([]);
  const [installConfig, setInstallConfig] = useState(null);
  const [newToken, setNewToken] = useState(null);
  const [tokenUsername, setTokenUsername] = useState("bas-agent");
  const [editingCallback, setEditingCallback] = useState(false);
  const [callbackHostInput, setCallbackHostInput] = useState("");
  const [callbackPortInput, setCallbackPortInput] = useState("");

  const isAdmin = Boolean(authStore.me?.is_admin);

  const load = async (silent = false) => {
    try {
      const [{ data: s }, { data: a }, { data: cfg }] = await Promise.all([
        client.get("/api/bas/dashboard/summary"),
        client.get("/api/bas/agents"),
        client.get("/api/bas/install-config"),
      ]);
      setSummary(s);
      setAgents(a);
      setInstallConfig(cfg);
      await healStaleHost(cfg);
    } catch (error) {
      if (silent) return;
      const detail = error?.response?.data?.detail;
      toastError(typeof detail === "string" ? detail : "Falha ao carregar o painel BAS.");
    }
  };

  // Auto-correct a stale callback_host instead of waiting for an admin to
  // notice the banner and click "Usar X agora". Only admins can write
  // install-config (PUT requires_admin), so this is a no-op for viewers
  // rather than a failing request on every heartbeat tick.
  const healStaleHost = async (cfg) => {
    if (!isAdmin) return;
    const browser = window.location.hostname;
    if (!isCallbackHostStale(cfg, browser)) return;
    try {
      const previous = cfg.callback_host;
      await client.put("/api/bas/install-config", {
        callback_host: browser,
        callback_port: cfg.callback_port || "",
      }, { _skipToast: true });
      toastSuccess(`IP atualizado automaticamente: ${previous} → ${browser}`);
      const { data: fresh } = await client.get("/api/bas/install-config");
      setInstallConfig(fresh);
    } catch {
      // Best-effort self-heal; the manual banner/button remain as a fallback.
    }
  };

  useEffect(() => {
    load();
    const heartbeat = setInterval(() => load(true), HEARTBEAT_INTERVAL_MS);
    return () => clearInterval(heartbeat);
  }, []);

  const generateToken = async () => {
    try {
      const { data } = await client.post("/api/bas/enrollment-tokens", { username: tokenUsername, max_uses: 1 });
      setNewToken(data);
      toastSuccess("Token de enrollment gerado — copie agora, não será mostrado de novo.");
    } catch (error) {
      const detail = error?.response?.data?.detail;
      toastError(typeof detail === "string" ? detail : "Falha ao gerar token.");
    }
  };

  const downloadAgent = async (os) => {
    try {
      const res = await client.get(`/api/bas/download/agent/${os}`, { responseType: "blob" });
      const url = URL.createObjectURL(res.data);
      const a = document.createElement("a");
      a.href = url;
      a.download = os === "windows" ? "bas-agent.exe" : `bas-agent-${os}`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      setTimeout(() => URL.revokeObjectURL(url), 60000);
    } catch (error) {
      const detail = error?.response?.data?.detail;
      toastError(typeof detail === "string" ? detail : `Agente ${os} ainda não disponível.`);
    }
  };

  const copy = (value) => {
    if (navigator.clipboard) navigator.clipboard.writeText(String(value || ""));
  };

  const deleteAgent = async (agent) => {
    const label = agent.label || agent.hostname || `agente #${agent.id}`;
    if (!window.confirm(
      `Remover "${label}"? Isso apaga o agente, seus agendamentos (testes) e todas as vulnerabilidades/achados que ele gerou. Não pode ser desfeito.`
    )) return;
    try {
      await client.delete(`/api/bas/agents/${agent.id}`);
      toastSuccess(`Agente "${label}" removido.`);
      await load();
    } catch (error) {
      const detail = error?.response?.data?.detail;
      toastError(typeof detail === "string" ? detail : "Falha ao remover agente.");
    }
  };

  // "backend" is the container-internal default GET /install-config returns
  // when no admin override was ever saved -- meaningless to a real agent.
  // The operator's own browser already reached this platform through a
  // real, current, externally-reachable address, so use that as the primary
  // suggestion -- correct for an agent outside Docker (LAN/host/VM). For an
  // agent running as a sibling container on the same docker-compose network,
  // that address is unreachable; container_network_ip (the backend's own
  // docker-bridge IP, detected server-side) is shown alongside it instead.
  const isAutoDetectedHost = installConfig?.callback_host === "backend";
  const browserHost = window.location.hostname;
  const effectiveHost = isAutoDetectedHost ? browserHost : (installConfig?.callback_host || "");
  const containerIp = installConfig?.container_network_ip;
  // Shown regardless of whether callback_host is auto-detected or a saved
  // override -- a saved external LAN IP (case: agent outside Docker) must
  // not hide the docker-network IP (case: agent as a sibling container),
  // since an operator may need either depending on where THIS agent runs.
  const showContainerIpHint = containerIp && containerIp !== effectiveHost;
  // healStaleHost() already auto-corrects this for admins; this stays as
  // the visible signal (and manual fallback) for the brief window before
  // the heal completes, and for non-admin viewers who can't trigger it.
  const overrideLooksStale = isCallbackHostStale(installConfig, browserHost);

  const startEditingCallback = () => {
    setCallbackHostInput(effectiveHost);
    setCallbackPortInput(installConfig?.callback_port || "");
    setEditingCallback(true);
  };

  const useDetectedHostNow = async () => {
    try {
      await client.put("/api/bas/install-config", {
        callback_host: browserHost,
        callback_port: installConfig?.callback_port || "",
      });
      toastSuccess("IP atualizado para o endereço detectado agora.");
      await load();
    } catch (error) {
      const detail = error?.response?.data?.detail;
      toastError(typeof detail === "string" ? detail : "Falha ao atualizar IP.");
    }
  };

  const saveCallback = async () => {
    try {
      await client.put("/api/bas/install-config", {
        callback_host: callbackHostInput.trim(),
        callback_port: callbackPortInput.trim(),
      });
      setEditingCallback(false);
      toastSuccess("IP/porta de instalação atualizados.");
      await load();
    } catch (error) {
      const detail = error?.response?.data?.detail;
      toastError(typeof detail === "string" ? detail : "Falha ao salvar IP/porta de instalação.");
    }
  };

  return (
    <main className="dpage space-y-4">
      <div className="page-intro">
        <h2>BAS — Breach &amp; Attack Simulation.</h2>
        <div className="sub">agentes instalados, credenciais de enrollment e status da rede interna (real ou simulada, conforme o agente)</div>
      </div>

      {summary && (
        <section style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 12 }}>
          <div className="card"><div className="mono-sm muted">agentes online</div><div style={{ fontSize: 22, fontWeight: 700 }}>{summary.agents_online}</div></div>
          <div className="card"><div className="mono-sm muted">agentes offline</div><div style={{ fontSize: 22, fontWeight: 700 }}>{summary.agents_offline}</div></div>
          <div className="card"><div className="mono-sm muted">agendamentos ativos</div><div style={{ fontSize: 22, fontWeight: 700 }}>{summary.schedules_active}</div></div>
          <div className="card"><div className="mono-sm muted">jobs hoje</div><div style={{ fontSize: 22, fontWeight: 700 }}>{summary.jobs_today}</div></div>
        </section>
      )}

      <section className="card">
        <div className="card-h"><div><h3>Baixar agente</h3><div className="sub">instale na máquina Windows ou Linux que ficará dentro da rede do cliente — escolha a arquitetura certa, um binário amd64 rodando sob emulação num host arm64 (ex.: VM Linux no VirtualBox em Mac Apple Silicon) trava</div></div></div>
        <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
          <button className="btn btn-primary" onClick={() => downloadAgent("windows")}>Baixar agente (Windows)</button>
          <button className="btn btn-primary" onClick={() => downloadAgent("linux-amd64")}>Baixar agente (Linux amd64)</button>
          <button className="btn btn-primary" onClick={() => downloadAgent("linux-arm64")}>Baixar agente (Linux arm64)</button>
        </div>
      </section>

      <section className="card">
        <div className="card-h"><div><h3>Como instalar</h3><div className="sub">rode o instalador na máquina de destino e informe os dados abaixo quando solicitado</div></div></div>
        <ol style={{ margin: 0, paddingLeft: 18, fontSize: 13, color: "var(--ink-soft)", display: "grid", gap: 6 }}>
          <li>Baixe o instalador correspondente ao sistema operacional da máquina.</li>
          <li>Gere um token de enrollment abaixo (ele só é mostrado uma vez).</li>
          <li>Execute o instalador — ele vai pedir <strong>usuário</strong>, <strong>senha</strong>, <strong>token</strong>, <strong>IP</strong> e <strong>porta de conexão</strong>.</li>
          <li>Use o IP/porta mostrados no bloco de credenciais abaixo — é o endereço da própria plataforma.</li>
          <li>
            Para rodar como serviço persistente (sobrevive a reinício/logout): <code className="mono-sm">./bas-agent install</code>.
            Para remover: <code className="mono-sm">./bas-agent uninstall</code>.
            No Windows, o instalador imprime os comandos <code className="mono-sm">sc.exe</code> equivalentes (sem serviço nativo embutido nesta fase).
          </li>
        </ol>
      </section>

      <section className="card">
        <div className="card-h"><div><h3>Credenciais de instalação</h3><div className="sub">IP/porta de conexão + gerar um novo token de enrollment</div></div></div>
        {installConfig && !editingCallback && (
          <>
            {overrideLooksStale && (
              <div className="mono-sm" style={{ marginBottom: 10, padding: "10px 12px", borderRadius: 8, border: "1px solid var(--sev-high-border)", background: "var(--sev-high-bg)", display: "flex", justifyContent: "space-between", alignItems: "center", gap: 10, flexWrap: "wrap" }}>
                <span>
                  O IP salvo (<strong>{installConfig.callback_host}</strong>) é diferente do endereço usado para acessar esta página agora
                  (<strong>{browserHost}</strong>) — a rede provavelmente mudou e o IP salvo pode estar morto.
                </span>
                {isAdmin && (
                  <button className="btn btn-primary" onClick={useDetectedHostNow}>Usar {browserHost} agora</button>
                )}
              </div>
            )}
            <div className="mono-sm muted" style={{ marginBottom: 10 }}>
              {isAutoDetectedHost
                ? "IP detectado automaticamente pelo navegador (endereço usado para acessar esta página agora)."
                : "IP salvo manualmente."}{" "}
              Use o campo abaixo se o agente roda fora do Docker (máquina real, VM, outro host na LAN).
              {showContainerIpHint && " Se o agente é outro container na mesma rede docker desta plataforma, use o IP de rede docker abaixo em vez deste."}
            </div>
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10, marginBottom: 10 }}>
              <div>
                <div className="mono-sm muted">IP / host da plataforma (fora do Docker)</div>
                <div className="mono" style={{ fontWeight: 600, cursor: "pointer" }} onClick={() => copy(effectiveHost)} title="clique para copiar">
                  {effectiveHost}
                </div>
              </div>
              <div>
                <div className="mono-sm muted">porta de conexão</div>
                <div className="mono" style={{ fontWeight: 600, cursor: "pointer" }} onClick={() => copy(installConfig.callback_port)} title="clique para copiar">
                  {installConfig.callback_port}
                </div>
              </div>
            </div>
            {showContainerIpHint && (
              <div style={{ marginBottom: 10 }}>
                <div className="mono-sm muted">IP de rede docker (agente rodando como outro container nesta mesma rede)</div>
                <div className="mono" style={{ fontWeight: 600, cursor: "pointer" }} onClick={() => copy(containerIp)} title="clique para copiar">
                  {containerIp}
                </div>
              </div>
            )}
            {isAdmin && (
              <button className="btn" onClick={startEditingCallback} style={{ marginBottom: 14 }}>Editar IP/porta</button>
            )}
          </>
        )}
        {isAdmin && editingCallback && (
          <div style={{ display: "flex", gap: 8, alignItems: "flex-end", marginBottom: 14, flexWrap: "wrap" }}>
            <div>
              <div className="mono-sm muted" style={{ marginBottom: 4 }}>IP / host da plataforma</div>
              <input style={fieldStyle} value={callbackHostInput} onChange={(e) => setCallbackHostInput(e.target.value)} placeholder="IP ou hostname" />
            </div>
            <div>
              <div className="mono-sm muted" style={{ marginBottom: 4 }}>porta de conexão</div>
              <input style={{ ...fieldStyle, maxWidth: 120 }} value={callbackPortInput} onChange={(e) => setCallbackPortInput(e.target.value)} placeholder="8001" />
            </div>
            <button className="btn btn-primary" onClick={saveCallback}>Salvar</button>
            <button className="btn" onClick={() => setEditingCallback(false)}>Cancelar</button>
          </div>
        )}

        <div style={{ display: "flex", gap: 8, alignItems: "center", marginBottom: 10 }}>
          <input style={{ ...fieldStyle, maxWidth: 260 }} value={tokenUsername} onChange={(e) => setTokenUsername(e.target.value)} placeholder="nome do agente" />
          <button className="btn btn-primary" onClick={generateToken}>Gerar token de enrollment</button>
        </div>

        {newToken && (
          <div style={{ padding: "14px 16px", borderRadius: 10, border: "1px solid var(--sev-high-border)", background: "var(--sev-high-bg)" }}>
            <div className="mono-sm muted" style={{ marginBottom: 6 }}>{newToken.warning}</div>
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 10 }}>
              <div><div className="mono-sm muted">usuário</div><div className="mono" onClick={() => copy(newToken.username)} style={{ cursor: "pointer" }}>{newToken.username}</div></div>
              <div><div className="mono-sm muted">senha</div><div className="mono" onClick={() => copy(newToken.password)} style={{ cursor: "pointer" }}>{newToken.password}</div></div>
              <div><div className="mono-sm muted">token</div><div className="mono" onClick={() => copy(newToken.code)} style={{ cursor: "pointer" }}>{newToken.code}</div></div>
            </div>
          </div>
        )}
      </section>

      <section className="t-wrap">
        <div className="t-head"><div><h3>Agentes</h3><div className="sub">{agents.length} agente(s)</div></div></div>
        {agents.length === 0 && <div className="empty">Nenhum agente enrolado ainda.</div>}
        {agents.map((a) => (
          <div key={a.id} style={{ padding: "14px 22px", borderBottom: "1px solid var(--line-soft)", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <div>
              <span className="mono" style={{ fontWeight: 600 }}>{a.label || a.hostname || `agente #${a.id}`}</span>
              <span className={`b ${a.status === "online" ? "b-low" : "b-neutral"}`} style={{ marginLeft: 8 }}>{a.status}</span>
              <div className="mono-sm muted" style={{ marginTop: 4 }}>{a.os} · último heartbeat: {a.last_heartbeat_at || "—"}</div>
            </div>
            <button className="btn" onClick={() => deleteAgent(a)} title="Remove o agente, seus agendamentos e as vulnerabilidades que ele gerou">
              Remover
            </button>
          </div>
        ))}
      </section>
    </main>
  );
}
