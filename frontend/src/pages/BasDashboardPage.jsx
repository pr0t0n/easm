import { useEffect, useState } from "react";
import client from "../api/client";
import { toastError, toastSuccess } from "../utils/toast";

const fieldStyle = {
  width: "100%", padding: "9px 12px", borderRadius: 8,
  border: "1px solid var(--line)", background: "var(--canvas)",
  fontSize: 13, color: "var(--ink)",
};

export default function BasDashboardPage() {
  const [summary, setSummary] = useState(null);
  const [agents, setAgents] = useState([]);
  const [installConfig, setInstallConfig] = useState(null);
  const [newToken, setNewToken] = useState(null);
  const [tokenUsername, setTokenUsername] = useState("bas-agent");
  const [editingCallback, setEditingCallback] = useState(false);
  const [callbackHostInput, setCallbackHostInput] = useState("");
  const [callbackPortInput, setCallbackPortInput] = useState("");

  const load = async () => {
    try {
      const [{ data: s }, { data: a }, { data: cfg }] = await Promise.all([
        client.get("/api/bas/dashboard/summary"),
        client.get("/api/bas/agents"),
        client.get("/api/bas/install-config"),
      ]);
      setSummary(s);
      setAgents(a);
      setInstallConfig(cfg);
    } catch (error) {
      const detail = error?.response?.data?.detail;
      toastError(typeof detail === "string" ? detail : "Falha ao carregar o painel BAS.");
    }
  };

  useEffect(() => { load(); }, []);

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

  const startEditingCallback = () => {
    setCallbackHostInput(installConfig?.callback_host || "");
    setCallbackPortInput(installConfig?.callback_port || "");
    setEditingCallback(true);
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
            {(installConfig.callback_host === "backend" || installConfig.callback_port === "8000") && (
              <div className="mono-sm" style={{ marginBottom: 10, color: "var(--sev-high-text, #b45309)" }}>
                "backend"/"8000" são o nome interno do container e a porta interna do Docker — não alcançáveis de fora.
                Edite abaixo com o IP/host real da plataforma e a porta mapeada no host (padrão 8001).
              </div>
            )}
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10, marginBottom: 10 }}>
              <div>
                <div className="mono-sm muted">IP / host da plataforma</div>
                <div className="mono" style={{ fontWeight: 600, cursor: "pointer" }} onClick={() => copy(installConfig.callback_host)} title="clique para copiar">
                  {installConfig.callback_host}
                </div>
              </div>
              <div>
                <div className="mono-sm muted">porta de conexão</div>
                <div className="mono" style={{ fontWeight: 600, cursor: "pointer" }} onClick={() => copy(installConfig.callback_port)} title="clique para copiar">
                  {installConfig.callback_port}
                </div>
              </div>
            </div>
            <button className="btn" onClick={startEditingCallback} style={{ marginBottom: 14 }}>Editar IP/porta</button>
          </>
        )}
        {editingCallback && (
          <div style={{ display: "flex", gap: 8, alignItems: "flex-end", marginBottom: 14, flexWrap: "wrap" }}>
            <div>
              <div className="mono-sm muted" style={{ marginBottom: 4 }}>IP / host da plataforma</div>
              <input style={fieldStyle} value={callbackHostInput} onChange={(e) => setCallbackHostInput(e.target.value)} placeholder="ex.: 192.168.16.154" />
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
          </div>
        ))}
      </section>
    </main>
  );
}
