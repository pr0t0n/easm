import { useEffect, useState } from "react";
import client from "../api/client";

export default function ConfigurationPage() {
  const [activeTab, setActiveTab] = useState("runtime");
  const [shodanApiKey, setShodanApiKey] = useState("");
  const [shodanMeta, setShodanMeta] = useState({ configured: false, enabled: false, status: "desativado" });
  const [runtime, setRuntime] = useState({
    debug_mode: false,
    verbose_mode: false,
    scan_retry_enabled: true,
    scan_retry_max_attempts: 3,
    scan_retry_delay_seconds: 45,
    worker_health_stale_after_seconds: 60,
    worker_orphan_cutoff_minutes: 8,
    worker_orphan_requeue_limit: 100,
  });
  const [aiStatus, setAiStatus] = useState(null);
  const [workerGroups, setWorkerGroups] = useState({});
  const [overview, setOverview] = useState(null);
  const [lines, setLines] = useState([]);
  const [newLine, setNewLine] = useState({ name: "", category: "reconhecimento", position: 0, enabled: true });
  const [toolsCatalog, setToolsCatalog] = useState({ unit: [], scheduled: [] });
  const [nessusMeta, setNessusMeta] = useState({ enabled: false, configured: false, pynessus_installed: false, url: "" });
  const [nessusConfig, setNessusConfig] = useState({ enabled: false, url: "", access_key: "", secret_key: "", verify_tls: true });
  const [burpMeta, setBurpMeta] = useState({ enabled: false, configured: false, burp_cli_installed: false, status: "desativado" });
  const [burpConfig, setBurpConfig] = useState({ enabled: false, license_key: "" });
  const [supervisorTrail, setSupervisorTrail] = useState({ summary: null, scans: [] });

  const loadAll = async () => {
    const [shodanRes, runtimeRes, statusRes, workerGroupsRes, linesRes, overviewRes, toolsRes, nessusRes, burpRes, supervisorRes] = await Promise.all([
      client.get("/api/config/shodan"),
      client.get("/api/config/runtime"),
      client.get("/api/config/ai-status"),
      client.get("/api/worker-manager/groups"),
      client.get("/api/worker-manager/lines"),
      client.get("/api/worker-manager/overview"),
      client.get("/api/config/tools"),
      client.get("/api/config/nessus"),
      client.get("/api/config/burp"),
      client.get("/api/worker-manager/supervisor-trail", { params: { limit: 20 } }),
    ]);
    setShodanApiKey(shodanRes.data.api_key || "");
    setRuntime(runtimeRes.data);
    setAiStatus(statusRes.data);
    setWorkerGroups(workerGroupsRes.data || {});
    setLines(linesRes.data);
    setOverview(overviewRes.data || null);
    setToolsCatalog(toolsRes.data?.catalog || { unit: [], scheduled: [] });
    setNessusMeta(toolsRes.data?.nessus || { enabled: false, configured: false, pynessus_installed: false, url: "" });
    setNessusConfig({
      enabled: Boolean(nessusRes.data?.enabled),
      url: nessusRes.data?.url || "",
      access_key: nessusRes.data?.access_key || "",
      secret_key: "",
      verify_tls: Boolean(nessusRes.data?.verify_tls),
    });
    setBurpMeta(toolsRes.data?.burp || { enabled: false, configured: false, burp_cli_installed: false, status: "desativado" });
    setBurpConfig({
      enabled: Boolean(burpRes.data?.enabled),
      license_key: burpRes.data?.license_key || "",
    });
    setSupervisorTrail(supervisorRes.data || { summary: null, scans: [] });
    setShodanMeta({
      configured: Boolean(shodanRes.data?.configured),
      enabled: Boolean(shodanRes.data?.enabled),
      status: shodanRes.data?.status || "desativado",
    });
  };

  useEffect(() => {
    loadAll();
  }, []);

  const saveShodan = async () => {
    await client.put("/api/config/shodan", { api_key: shodanApiKey });
  };

  const saveRuntime = async () => {
    await client.put("/api/config/runtime", runtime);
    await loadAll();
  };

  const saveNessus = async () => {
    await client.put("/api/config/nessus", nessusConfig);
    await loadAll();
  };

  const saveBurp = async () => {
    await client.put("/api/config/burp", burpConfig);
    await loadAll();
  };

  const addLine = async () => {
    await client.post("/api/worker-manager/lines", { ...newLine, definition: {} });
    setNewLine({ name: "", category: "reconhecimento", position: 0, enabled: true });
    await loadAll();
  };

  const toggleLine = async (line) => {
    await client.put(`/api/worker-manager/lines/${line.id}`, { enabled: !line.enabled });
    await loadAll();
  };

  const deleteLine = async (lineId) => {
    await client.delete(`/api/worker-manager/lines/${lineId}`);
    await loadAll();
  };


  return (
    <main className="mx-auto mt-6 w-[95%] max-w-6xl space-y-4 pb-10">
      <section className="panel p-4">
        <div className="flex flex-wrap gap-2">
          <button onClick={() => setActiveTab("runtime")} className={`rounded-lg px-3 py-1 text-sm ${activeTab === "runtime" ? "bg-blue-700 text-white" : "border border-slate-700 bg-slate-800 text-slate-300"}`}>Runtime</button>
          <button onClick={() => setActiveTab("tools")} className={`rounded-lg px-3 py-1 text-sm ${activeTab === "tools" ? "bg-blue-700 text-white" : "border border-slate-700 bg-slate-800 text-slate-300"}`}>Ferramentas</button>
          <button onClick={() => setActiveTab("workers")} className={`rounded-lg px-3 py-1 text-sm ${activeTab === "workers" ? "bg-blue-700 text-white" : "border border-slate-700 bg-slate-800 text-slate-300"}`}>Workers</button>
        </div>
      </section>

      {activeTab === "runtime" && (
      <section className="panel p-5">
        <h2 className="text-xl font-semibold">Configuracao</h2>

        <div className="mt-4">
          <div>
            <h3 className="text-sm font-semibold">Modo de Execucao / Logs</h3>
            <label className="mt-2 flex items-center gap-2 text-sm">
              <input
                type="checkbox"
                checked={runtime.debug_mode}
                onChange={(e) => setRuntime({ ...runtime, debug_mode: e.target.checked })}
              />
              Debug Mode
            </label>
            <label className="mt-2 flex items-center gap-2 text-sm">
              <input
                type="checkbox"
                checked={runtime.verbose_mode}
                onChange={(e) => setRuntime({ ...runtime, verbose_mode: e.target.checked })}
              />
              Verbose Mode
            </label>
            <label className="mt-2 flex items-center gap-2 text-sm">
              <input
                type="checkbox"
                checked={runtime.scan_retry_enabled}
                onChange={(e) => setRuntime({ ...runtime, scan_retry_enabled: e.target.checked })}
              />
              Habilitar retry automatico de scans
            </label>
            <div className="mt-3 grid gap-2 md:grid-cols-2">
              <label className="text-xs text-slate-300">
                Max tentativas de retry
                <input
                  type="number"
                  min={1}
                  max={10}
                  className="mt-1 w-full rounded-xl border border-slate-700 bg-slate-950 px-3 py-2"
                  value={runtime.scan_retry_max_attempts}
                  onChange={(e) => setRuntime({ ...runtime, scan_retry_max_attempts: Number(e.target.value) })}
                />
              </label>
              <label className="text-xs text-slate-300">
                Delay entre retries (seg)
                <input
                  type="number"
                  min={5}
                  max={3600}
                  className="mt-1 w-full rounded-xl border border-slate-700 bg-slate-950 px-3 py-2"
                  value={runtime.scan_retry_delay_seconds}
                  onChange={(e) => setRuntime({ ...runtime, scan_retry_delay_seconds: Number(e.target.value) })}
                />
              </label>
              <label className="text-xs text-slate-300">
                Worker stale timeout (seg)
                <input
                  type="number"
                  min={10}
                  max={3600}
                  className="mt-1 w-full rounded-xl border border-slate-700 bg-slate-950 px-3 py-2"
                  value={runtime.worker_health_stale_after_seconds}
                  onChange={(e) => setRuntime({ ...runtime, worker_health_stale_after_seconds: Number(e.target.value) })}
                />
              </label>
              <label className="text-xs text-slate-300">
                Orphan cutoff (min)
                <input
                  type="number"
                  min={1}
                  max={180}
                  className="mt-1 w-full rounded-xl border border-slate-700 bg-slate-950 px-3 py-2"
                  value={runtime.worker_orphan_cutoff_minutes}
                  onChange={(e) => setRuntime({ ...runtime, worker_orphan_cutoff_minutes: Number(e.target.value) })}
                />
              </label>
              <label className="text-xs text-slate-300 md:col-span-2">
                Limite de requeue de orfaos por operacao
                <input
                  type="number"
                  min={1}
                  max={2000}
                  className="mt-1 w-full rounded-xl border border-slate-700 bg-slate-950 px-3 py-2"
                  value={runtime.worker_orphan_requeue_limit}
                  onChange={(e) => setRuntime({ ...runtime, worker_orphan_requeue_limit: Number(e.target.value) })}
                />
              </label>
            </div>
            <button onClick={saveRuntime} className="mt-2 rounded-xl bg-blue-600 px-4 py-2 font-semibold text-white">Salvar runtime</button>
          </div>
        </div>
      </section>
      )}

      {activeTab === "runtime" && (
      <section className="panel p-5">
        <div className="flex items-center justify-between">
          <h3 className="text-lg font-semibold">Status das IAs</h3>
          <button onClick={loadAll} className="rounded-lg bg-[#1A365D] px-3 py-1 text-xs text-white hover:bg-[#2C5282]">Atualizar</button>
        </div>

        {aiStatus && (
          <div className="mt-3 space-y-2 text-sm">
            <p>
              Ollama:{" "}
              <span className={`rounded-md px-2 py-0.5 text-xs font-semibold ${aiStatus.ollama.health === "online" ? "bg-emerald-100 text-emerald-800" : "bg-rose-100 text-rose-800"}`}>
                {aiStatus.ollama.health}
              </span>
            </p>
            <p>Base URL: {aiStatus.ollama.base_url}</p>
            <p>Modelo configurado: {aiStatus.ollama.configured_model}</p>
            <p>Modelos disponiveis: {(aiStatus.ollama.available_models || []).join(", ") || "nenhum"}</p>
            {aiStatus.ollama.error && <p className="text-rose-700">Erro IA: {aiStatus.ollama.error}</p>}
            <p>
              Runtime atual: debug={String(aiStatus.runtime.debug_mode)} | verbose={String(aiStatus.runtime.verbose_mode)}
              {" | "}retry={String(aiStatus.runtime.scan_retry_enabled)} ({aiStatus.runtime.scan_retry_max_attempts}x/{aiStatus.runtime.scan_retry_delay_seconds}s)
            </p>
            <p>
              Workers: stale={aiStatus.runtime.worker_health_stale_after_seconds}s | orphan_cutoff={aiStatus.runtime.worker_orphan_cutoff_minutes}min | orphan_limit={aiStatus.runtime.worker_orphan_requeue_limit}
            </p>

            <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-3">
              <h4 className="font-semibold">Ultimos erros</h4>
              {(aiStatus.recent_errors || []).length === 0 && <p className="text-slate-400">Sem erros recentes.</p>}
              {(aiStatus.recent_errors || []).map((err) => (
                <p key={err.id} className="font-mono text-xs text-rose-300">
                  [{new Date(err.created_at).toLocaleString()}] {err.source}: {err.message}
                </p>
              ))}
            </div>
          </div>
        )}
      </section>
      )}

      {activeTab === "workers" && (
      <section className="panel p-5">
        <h3 className="text-lg font-semibold">Workers Predefinidos</h3>
        <div className="mt-3 space-y-2">
          {Object.entries(workerGroups).map(([modeName, groupsByName]) => (
            <div key={modeName} className="rounded-xl border border-slate-800 bg-slate-900/70 p-3">
              <p className="font-semibold uppercase">{modeName}</p>
              <div className="mt-2 space-y-2">
                {Object.entries(groupsByName || {}).map(([groupName, group]) => (
                  <div key={`${modeName}-${groupName}`} className="rounded-lg border border-slate-800 bg-slate-950/60 p-2">
                    <p className="font-medium">{groupName} - fila: {group.queue}</p>
                    <p className="text-xs text-slate-300">{group.description}</p>
                    <p className="mt-1 text-xs text-slate-400">Ferramentas: {(group.tools || []).join(", ")}</p>
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>
      </section>
      )}

      {activeTab === "workers" && (
      <section className="panel p-5">
        <h3 className="text-lg font-semibold">Indicadores de Interacao</h3>
        {!overview && <p className="text-sm text-slate-400">Carregando metricas...</p>}
        {overview && (
          <div className="mt-3 space-y-2 text-sm">
            <p>Scans analisados: {overview.interaction_metrics.scans_analyzed}</p>
            <p>Crescimento lateral medio (ativos novos): {overview.interaction_metrics.avg_lateral_growth_assets}</p>
            <p>Media de portas descobertas: {overview.interaction_metrics.avg_discovered_ports}</p>
            <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-3">
              <h4 className="font-semibold">Tempo por Atividade (ms)</h4>
              {Object.entries(overview.interaction_metrics.node_timing || {}).map(([node, t]) => (
                <p key={node} className="text-xs text-slate-300">
                  {node}: avg {t.avg_ms} | max {t.max_ms} | amostras {t.samples}
                </p>
              ))}
            </div>
            <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-3">
              <h4 className="font-semibold">Transicoes no Grafo</h4>
              {Object.entries(overview.interaction_metrics.transition_counts || {}).map(([edge, count]) => (
                <p key={edge} className="text-xs text-slate-300">{edge}: {count}</p>
              ))}
            </div>
          </div>
        )}
      </section>
      )}

      {activeTab === "workers" && (
      <section className="panel p-5">
        <h3 className="text-lg font-semibold">Validacao da Trilha do Supervisor</h3>
        <p className="mt-1 text-xs text-slate-300">Confere o padrao supervisor -&gt; worker -&gt; supervisor e confirma execucao do no OSINT.</p>

        {!supervisorTrail?.summary && <p className="mt-2 text-sm text-slate-400">Carregando validacao...</p>}

        {supervisorTrail?.summary && (
          <div className="mt-3 grid gap-2 text-sm md:grid-cols-3">
            <p className="rounded-lg border border-slate-700 bg-slate-900/70 px-3 py-2">scans analisados: {supervisorTrail.summary.scans_analyzed}</p>
            <p className="rounded-lg border border-emerald-500/30 bg-emerald-500/10 px-3 py-2 text-emerald-200">fluxo valido: {supervisorTrail.summary.valid_supervisor_flow}</p>
            <p className="rounded-lg border border-rose-500/30 bg-rose-500/10 px-3 py-2 text-rose-200">fluxo invalido: {supervisorTrail.summary.invalid_supervisor_flow}</p>
            <p className="rounded-lg border border-blue-500/35 bg-blue-500/10 px-3 py-2 text-blue-200">com no osint: {supervisorTrail.summary.scans_with_osint_node}</p>
            <p className="rounded-lg border border-amber-500/30 bg-amber-500/10 px-3 py-2 text-amber-200 md:col-span-2">sem no osint: {supervisorTrail.summary.scans_without_osint_node}</p>
          </div>
        )}

        <div className="mt-4 space-y-2">
          {(supervisorTrail?.scans || []).map((scan) => (
            <div key={scan.scan_id} className="rounded-xl border border-slate-800 bg-slate-900/70 p-3">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <p className="font-mono text-sm font-semibold">#{scan.scan_id} - {scan.target_query}</p>
                <span className={`rounded-md px-2 py-0.5 text-xs ${scan.validation?.valid ? "bg-emerald-500/20 text-emerald-300" : "bg-rose-500/20 text-rose-300"}`}>
                  {scan.validation?.valid ? "OK" : "NOK"}
                </span>
              </div>
              <p className="mt-1 text-xs text-slate-300">modo: {scan.mode} | status: {scan.status} | osint: {String(Boolean(scan.validation?.has_osint_node))}</p>
              <p className="text-xs text-slate-400">transicoes: {(scan.validation?.transitions || []).slice(0, 8).join(" | ") || "sem historico"}</p>
              {(scan.validation?.invalid_edges || []).length > 0 && (
                <p className="mt-1 text-xs text-rose-300">invalidas: {scan.validation.invalid_edges.join(" | ")}</p>
              )}
            </div>
          ))}
        </div>
      </section>
      )}

      {activeTab === "workers" && (
      <section className="panel p-5">
        <h3 className="text-lg font-semibold">Worker Manager</h3>
        <div className="mt-3 grid gap-2 md:grid-cols-4">
          <input
            className="rounded-xl border border-slate-700 bg-slate-950 px-3 py-2"
            placeholder="Nome da missao"
            value={newLine.name}
            onChange={(e) => setNewLine({ ...newLine, name: e.target.value })}
          />
          <select
            className="rounded-xl border border-slate-700 bg-slate-950 px-3 py-2"
            value={newLine.category}
            onChange={(e) => setNewLine({ ...newLine, category: e.target.value })}
          >
            <option value="reconhecimento">reconhecimento</option>
            <option value="analise_vulnerabilidade">analise_vulnerabilidade</option>
            <option value="osint">osint</option>
          </select>
          <input
            type="number"
            className="rounded-xl border border-slate-700 bg-slate-950 px-3 py-2"
            value={newLine.position}
            onChange={(e) => setNewLine({ ...newLine, position: Number(e.target.value) })}
          />
          <button onClick={addLine} className="rounded-xl bg-blue-600 px-4 py-2 font-semibold text-white">Adicionar</button>
        </div>

        <div className="mt-3 space-y-2">
          {lines.map((line) => (
            <div key={line.id} className="rounded-xl border border-slate-800 bg-slate-900/70 p-3">
              <p className="font-medium">{line.position} - {line.name} ({line.category})</p>
              <p className="text-xs text-slate-300">enabled: {String(line.enabled)}</p>
              <div className="mt-2 flex gap-2">
                <button onClick={() => toggleLine(line)} className="rounded-lg bg-blue-500/15 px-2 py-1 text-xs text-blue-300">Alternar</button>
                <button onClick={() => deleteLine(line.id)} className="rounded-lg bg-rose-500/20 px-2 py-1 text-xs text-rose-300">Excluir</button>
              </div>
            </div>
          ))}
        </div>
      </section>
      )}

      {activeTab === "tools" && (
        <section className="panel p-5">
          <h3 className="text-lg font-semibold">Ferramentas em Uso / Instaladas</h3>
          <div className="mt-3 grid gap-3 md:grid-cols-2">
            {["unit", "scheduled"].map((modeName) => (
              <div key={modeName} className="rounded-xl border border-slate-800 bg-slate-900/70 p-3">
                <p className="font-semibold uppercase">{modeName}</p>
                <div className="mt-2 space-y-2">
                  {(toolsCatalog[modeName] || []).map((group) => (
                    <div key={`${modeName}-${group.group}`} className="rounded-lg border border-slate-800 bg-slate-950/60 p-2">
                      <p className="text-sm font-medium">{group.group} - {group.queue}</p>
                      <p className="text-xs text-slate-400">{group.description}</p>
                      <div className="mt-1 flex flex-wrap gap-1">
                        {(group.tools || []).map((tool) => (
                          <span key={`${group.group}-${tool.name}`} className={`rounded-md px-2 py-0.5 text-xs ${tool.installed ? "bg-emerald-500/20 text-emerald-300" : "bg-rose-500/20 text-rose-300"}`}>
                            {tool.name} {tool.installed ? "(instalada)" : "(nao instalada)"}
                          </span>
                        ))}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </section>
      )}

      {activeTab === "tools" && (
        <section className="panel p-5">
          <h3 className="text-lg font-semibold">Shodan</h3>
          <p className="mt-1 text-xs text-slate-300">Enriquecimento de ativos e exposicoes externas via API Shodan.</p>
          <div className="mt-3 rounded-xl border border-slate-800 bg-slate-900/70 p-3 text-sm">
            <p>Status: <span className={shodanMeta.configured ? "text-emerald-300" : "text-amber-300"}>{shodanMeta.status}</span></p>
            <p className="mt-1 text-xs text-slate-400">{shodanMeta.configured ? "A integracao pode enriquecer ativos e exposicoes externas." : "Desativado ate que uma API key valida seja salva."}</p>
          </div>
          <div className="mt-3">
            <label className="mb-1 block text-sm text-slate-300">Shodan API Key</label>
            <input
              className="w-full rounded-xl border border-slate-700 bg-slate-950 px-3 py-2"
              value={shodanApiKey}
              onChange={(e) => setShodanApiKey(e.target.value)}
              placeholder="insira a chave"
            />
            <button onClick={saveShodan} className="mt-3 rounded-xl bg-blue-600 px-4 py-2 font-semibold text-white">Salvar chave</button>
          </div>
        </section>
      )}

      {activeTab === "tools" && (
        <section className="panel p-5">
          <h3 className="text-lg font-semibold">Nessus (pynessus)</h3>
          <p className="mt-1 text-xs text-slate-300">Habilita o Nessus como discovery/scanner/analista de vulnerabilidade.</p>
          <div className="mt-3 rounded-xl border border-slate-800 bg-slate-900/70 p-3 text-sm">
            <p>Status: <span className={nessusMeta.configured ? "text-emerald-300" : "text-amber-300"}>{nessusMeta.status || (nessusMeta.configured ? "ativo" : "desativado")}</span></p>
            <p>pynessus instalado: <span className={nessusMeta.pynessus_installed ? "text-emerald-300" : "text-rose-300"}>{String(nessusMeta.pynessus_installed)}</span></p>
            <p>Nessus configurado: <span className={nessusMeta.configured ? "text-emerald-300" : "text-amber-300"}>{String(nessusMeta.configured)}</span></p>
            <p>URL atual: {nessusMeta.url || "nao definida"}</p>
            {!nessusMeta.configured && <p className="mt-1 text-xs text-slate-400">Desativado ate que URL, Access Key e Secret Key sejam informados.</p>}
          </div>

          <div className="mt-3 grid gap-2 md:grid-cols-2">
            <label className="flex items-center gap-2 text-sm md:col-span-2">
              <input type="checkbox" checked={nessusConfig.enabled} onChange={(e) => setNessusConfig({ ...nessusConfig, enabled: e.target.checked })} />
              Habilitar Nessus
            </label>
            <input className="rounded-xl border border-slate-700 bg-slate-950 px-3 py-2" placeholder="https://nessus.local:8834" value={nessusConfig.url} onChange={(e) => setNessusConfig({ ...nessusConfig, url: e.target.value })} />
            <label className="flex items-center gap-2 text-sm">
              <input type="checkbox" checked={nessusConfig.verify_tls} onChange={(e) => setNessusConfig({ ...nessusConfig, verify_tls: e.target.checked })} />
              Verificar TLS
            </label>
            <input className="rounded-xl border border-slate-700 bg-slate-950 px-3 py-2" placeholder="Access Key" value={nessusConfig.access_key} onChange={(e) => setNessusConfig({ ...nessusConfig, access_key: e.target.value })} />
            <input className="rounded-xl border border-slate-700 bg-slate-950 px-3 py-2" placeholder="Secret Key (deixe vazio para manter)" value={nessusConfig.secret_key} onChange={(e) => setNessusConfig({ ...nessusConfig, secret_key: e.target.value })} />
          </div>
          <button onClick={saveNessus} className="mt-3 rounded-xl bg-emerald-500 px-4 py-2 font-semibold text-white">Salvar Nessus</button>
        </section>
      )}

      {activeTab === "tools" && (
        <section className="panel p-5">
          <h3 className="text-lg font-semibold">Burp Professional CLI</h3>
          <p className="mt-1 text-xs text-slate-300">Integra o Burp CLI no worker de vulnerabilidade e usa a licenca salva no settings.</p>
          <div className="mt-3 rounded-xl border border-slate-800 bg-slate-900/70 p-3 text-sm">
            <p>Status: <span className={burpMeta.configured ? "text-emerald-300" : "text-amber-300"}>{burpMeta.status || (burpMeta.configured ? "ativo" : "desativado")}</span></p>
            <p>burp-cli instalado: <span className={burpMeta.burp_cli_installed ? "text-emerald-300" : "text-rose-300"}>{String(burpMeta.burp_cli_installed)}</span></p>
            <p>Licenca configurada: <span className={burpMeta.configured ? "text-emerald-300" : "text-amber-300"}>{String(burpMeta.configured)}</span></p>
          </div>
          <div className="mt-3 grid gap-2 md:grid-cols-2">
            <label className="flex items-center gap-2 text-sm md:col-span-2">
              <input type="checkbox" checked={burpConfig.enabled} onChange={(e) => setBurpConfig({ ...burpConfig, enabled: e.target.checked })} />
              Habilitar Burp CLI
            </label>
            <input
              className="rounded-xl border border-slate-700 bg-slate-950 px-3 py-2 md:col-span-2"
              placeholder="Burp license key (deixe mascarada para manter)"
              value={burpConfig.license_key}
              onChange={(e) => setBurpConfig({ ...burpConfig, license_key: e.target.value })}
            />
          </div>
          <button onClick={saveBurp} className="mt-3 rounded-xl bg-emerald-500 px-4 py-2 font-semibold text-white">Salvar Burp</button>
        </section>
      )}
    </main>
  );
}
