import { useEffect, useState } from "react";
import client from "../api/client";

export default function ConfigurationPage() {
  const [shodanApiKey, setShodanApiKey] = useState("");
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
  const [allowlist, setAllowlist] = useState({ policy: null, entries: [] });
  const [allowlistForm, setAllowlistForm] = useState({ target_pattern: "", tool_group: "*", is_active: true });
  const [groups, setGroups] = useState([]);
  const [groupForm, setGroupForm] = useState({ name: "", description: "" });
  const [newLine, setNewLine] = useState({ name: "", category: "recon", position: 0, enabled: true });

  const loadAll = async () => {
    const [shodanRes, runtimeRes, statusRes, workerGroupsRes, linesRes, overviewRes, allowlistRes] = await Promise.all([
      client.get("/api/config/shodan"),
      client.get("/api/config/runtime"),
      client.get("/api/config/ai-status"),
      client.get("/api/worker-manager/groups"),
      client.get("/api/worker-manager/lines"),
      client.get("/api/worker-manager/overview"),
      client.get("/api/policy/allowlist"),
    ]);
    setShodanApiKey(shodanRes.data.api_key || "");
    setRuntime(runtimeRes.data);
    setAiStatus(statusRes.data);
    setWorkerGroups(workerGroupsRes.data || {});
    setLines(linesRes.data);
    setOverview(overviewRes.data || null);
    setAllowlist(allowlistRes.data || { policy: null, entries: [] });
    const groupsRes = await client.get("/api/access-groups");
    setGroups(groupsRes.data);
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

  const addLine = async () => {
    await client.post("/api/worker-manager/lines", { ...newLine, definition: {} });
    setNewLine({ name: "", category: "recon", position: 0, enabled: true });
    await loadAll();
  };

  const addGroup = async () => {
    await client.post("/api/access-groups", groupForm);
    setGroupForm({ name: "", description: "" });
    await loadAll();
  };

  const deleteGroup = async (groupId) => {
    await client.delete(`/api/access-groups/${groupId}`);
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

  const addAllowlist = async () => {
    await client.post("/api/policy/allowlist", allowlistForm);
    setAllowlistForm({ target_pattern: "", tool_group: "*", is_active: true });
    await loadAll();
  };

  const toggleAllowlist = async (entry) => {
    await client.put(`/api/policy/allowlist/${entry.id}`, { is_active: !entry.is_active });
    await loadAll();
  };

  const deleteAllowlist = async (entryId) => {
    await client.delete(`/api/policy/allowlist/${entryId}`);
    await loadAll();
  };

  return (
    <main className="mx-auto mt-6 w-[95%] max-w-6xl space-y-4 pb-10">
      <section className="panel p-5">
        <h2 className="text-xl font-semibold">Configuracao</h2>

        <div className="mt-4 grid gap-3 md:grid-cols-2">
          <div>
            <label className="mb-1 block text-sm text-slate-300">Shodan API Key</label>
            <input
              className="w-full rounded-xl border border-slate-700 bg-slate-950 px-3 py-2"
              value={shodanApiKey}
              onChange={(e) => setShodanApiKey(e.target.value)}
              placeholder="insira a chave"
            />
            <button onClick={saveShodan} className="mt-2 rounded-xl bg-brand-500 px-4 py-2 font-semibold text-slate-950">Salvar chave</button>
          </div>

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
            <button onClick={saveRuntime} className="mt-2 rounded-xl bg-cyan-500 px-4 py-2 font-semibold text-slate-950">Salvar runtime</button>
          </div>
        </div>
      </section>

      <section className="panel p-5">
        <div className="flex items-center justify-between">
          <h3 className="text-lg font-semibold">Status das IAs</h3>
          <button onClick={loadAll} className="rounded-lg bg-slate-800 px-3 py-1 text-xs">Atualizar</button>
        </div>

        {aiStatus && (
          <div className="mt-3 space-y-2 text-sm">
            <p>Ollama: <span className={aiStatus.ollama.health === "online" ? "text-emerald-300" : "text-rose-300"}>{aiStatus.ollama.health}</span></p>
            <p>Base URL: {aiStatus.ollama.base_url}</p>
            <p>Modelo configurado: {aiStatus.ollama.configured_model}</p>
            <p>Modelos disponiveis: {(aiStatus.ollama.available_models || []).join(", ") || "nenhum"}</p>
            {aiStatus.ollama.error && <p className="text-rose-300">Erro IA: {aiStatus.ollama.error}</p>}
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
                <p key={err.id} className="font-mono text-xs text-rose-200">
                  [{new Date(err.created_at).toLocaleString()}] {err.source}: {err.message}
                </p>
              ))}
            </div>
          </div>
        )}
      </section>

      <section className="panel p-5">
        <h3 className="text-lg font-semibold">Workers Predefinidos</h3>
        <div className="mt-3 space-y-2">
          {Object.entries(workerGroups).map(([name, group]) => (
            <div key={name} className="rounded-xl border border-slate-800 bg-slate-900/70 p-3">
              <p className="font-medium">{name} - fila: {group.queue}</p>
              <p className="text-xs text-slate-300">{group.description}</p>
              <p className="mt-1 text-xs text-slate-400">Ferramentas: {(group.tools || []).join(", ")}</p>
            </div>
          ))}
        </div>
      </section>

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

      <section className="panel p-5">
        <h3 className="text-lg font-semibold">Policy / Allowlist por Cliente</h3>
        <p className="mt-1 text-xs text-slate-300">Apenas alvos permitidos na allowlist passam no gate de policy.</p>
        <div className="mt-3 grid gap-2 md:grid-cols-4">
          <input
            className="rounded-xl border border-slate-700 bg-slate-950 px-3 py-2"
            placeholder="*.empresa.com"
            value={allowlistForm.target_pattern}
            onChange={(e) => setAllowlistForm({ ...allowlistForm, target_pattern: e.target.value })}
          />
          <select
            className="rounded-xl border border-slate-700 bg-slate-950 px-3 py-2"
            value={allowlistForm.tool_group}
            onChange={(e) => setAllowlistForm({ ...allowlistForm, tool_group: e.target.value })}
          >
            <option value="*">*</option>
            <option value="recon">recon</option>
            <option value="fuzzing">fuzzing</option>
            <option value="vuln">vuln</option>
            <option value="code_js">code_js</option>
            <option value="api">api</option>
          </select>
          <label className="flex items-center gap-2 text-sm">
            <input
              type="checkbox"
              checked={allowlistForm.is_active}
              onChange={(e) => setAllowlistForm({ ...allowlistForm, is_active: e.target.checked })}
            />
            Ativo
          </label>
          <button onClick={addAllowlist} className="rounded-xl bg-emerald-500 px-4 py-2 font-semibold text-slate-950">Adicionar</button>
        </div>
        <div className="mt-3 space-y-2">
          {(allowlist.entries || []).map((entry) => (
            <div key={entry.id} className="rounded-xl border border-slate-800 bg-slate-900/70 p-3">
              <p className="text-sm">{entry.target_pattern} | group: {entry.tool_group} | ativo: {String(entry.is_active)}</p>
              <div className="mt-2 flex gap-2">
                <button onClick={() => toggleAllowlist(entry)} className="rounded-lg bg-cyan-500/20 px-2 py-1 text-xs text-cyan-300">Alternar</button>
                <button onClick={() => deleteAllowlist(entry.id)} className="rounded-lg bg-rose-500/20 px-2 py-1 text-xs text-rose-300">Excluir</button>
              </div>
            </div>
          ))}
        </div>
      </section>

      <section className="panel p-5">
        <h3 className="text-lg font-semibold">Grupos de Acesso</h3>
        <div className="mt-3 grid gap-2 md:grid-cols-3">
          <input
            className="rounded-xl border border-slate-700 bg-slate-950 px-3 py-2"
            placeholder="Nome do grupo"
            value={groupForm.name}
            onChange={(e) => setGroupForm({ ...groupForm, name: e.target.value })}
          />
          <input
            className="rounded-xl border border-slate-700 bg-slate-950 px-3 py-2"
            placeholder="Descricao"
            value={groupForm.description}
            onChange={(e) => setGroupForm({ ...groupForm, description: e.target.value })}
          />
          <button onClick={addGroup} className="rounded-xl bg-emerald-500 px-4 py-2 font-semibold text-slate-950">Salvar grupo</button>
        </div>
        <div className="mt-3 space-y-2">
          {groups.map((g) => (
            <div key={g.id} className="rounded-xl border border-slate-800 bg-slate-900/70 p-3">
              <p className="font-medium">#{g.id} - {g.name}</p>
              <p className="text-xs text-slate-300">{g.description || "Sem descricao"}</p>
              <button onClick={() => deleteGroup(g.id)} className="mt-2 rounded-lg bg-rose-500/20 px-2 py-1 text-xs text-rose-300">Excluir grupo</button>
            </div>
          ))}
        </div>
      </section>

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
            <option value="recon">recon</option>
            <option value="fuzzing">fuzzing</option>
            <option value="vuln">vuln</option>
            <option value="code_js">code_js</option>
            <option value="api">api</option>
          </select>
          <input
            type="number"
            className="rounded-xl border border-slate-700 bg-slate-950 px-3 py-2"
            value={newLine.position}
            onChange={(e) => setNewLine({ ...newLine, position: Number(e.target.value) })}
          />
          <button onClick={addLine} className="rounded-xl bg-brand-500 px-4 py-2 font-semibold text-slate-950">Adicionar</button>
        </div>

        <div className="mt-3 space-y-2">
          {lines.map((line) => (
            <div key={line.id} className="rounded-xl border border-slate-800 bg-slate-900/70 p-3">
              <p className="font-medium">{line.position} - {line.name} ({line.category})</p>
              <p className="text-xs text-slate-300">enabled: {String(line.enabled)}</p>
              <div className="mt-2 flex gap-2">
                <button onClick={() => toggleLine(line)} className="rounded-lg bg-cyan-500/20 px-2 py-1 text-xs text-cyan-300">Alternar</button>
                <button onClick={() => deleteLine(line.id)} className="rounded-lg bg-rose-500/20 px-2 py-1 text-xs text-rose-300">Excluir</button>
              </div>
            </div>
          ))}
        </div>
      </section>
    </main>
  );
}
