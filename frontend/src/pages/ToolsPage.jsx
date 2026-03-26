import { useEffect, useState } from "react";
import client from "../api/client";

function SummaryCard({ label, value, tone = "text-slate-100" }) {
  return (
    <div className="rounded-2xl border border-slate-700 bg-slate-900/70 p-4">
      <p className="text-xs uppercase tracking-[0.2em] text-slate-400">{label}</p>
      <p className={`mt-2 text-2xl font-semibold ${tone}`}>{value}</p>
    </div>
  );
}

export default function ToolsPage() {
  const [catalog, setCatalog] = useState({ unit: [], scheduled: [] });
  const [requirementsCatalog, setRequirementsCatalog] = useState([]);
  const [nessus, setNessus] = useState({ configured: false, enabled: false, pynessus_installed: false, url: "" });
  const [shodan, setShodan] = useState({ configured: false, enabled: false, status: "desativado" });
  const [loading, setLoading] = useState(true);
  const [installing, setInstalling] = useState(false);
  const [installStatus, setInstallStatus] = useState({});
  const [error, setError] = useState("");

  const load = async () => {
    setLoading(true);
    setError("");
    try {
      const { data } = await client.get("/api/config/tools");
      setCatalog(data?.catalog || { unit: [], scheduled: [] });
      setRequirementsCatalog(data?.requirements_catalog || []);
      setNessus(data?.nessus || { configured: false, enabled: false, pynessus_installed: false, url: "" });
      setShodan(data?.shodan || { configured: false, enabled: false, status: "desativado" });
    } catch (err) {
      setError(err?.response?.data?.detail || "Falha ao carregar ferramentas.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
  }, []);

  const collectMissingTools = () => {
    const names = new Set();
    ["unit", "scheduled"].forEach((mode) => {
      (catalog[mode] || []).forEach((group) => {
        (group.tools || []).forEach((tool) => {
          if (!tool.installed && tool.install_supported) names.add(tool.name);
        });
      });
    });
    return Array.from(names);
  };

  const installMissingTools = async () => {
    const missingTools = collectMissingTools();
    if (missingTools.length === 0) return;

    const initialStatus = {};
    missingTools.forEach((name) => {
      initialStatus[name] = "aguardando";
    });

    setInstalling(true);
    setInstallStatus(initialStatus);
    setError("");

    for (const toolName of missingTools) {
      setInstallStatus((prev) => ({ ...prev, [toolName]: "em instalacao" }));
      try {
        const { data } = await client.post("/api/config/tools/install-one", { tool: toolName }, { timeout: 120000 });
        setInstallStatus((prev) => ({
          ...prev,
          [toolName]: data?.installed ? "instalada" : "aguardando",
        }));
      } catch {
        setInstallStatus((prev) => ({ ...prev, [toolName]: "aguardando" }));
      }
    }

    await load();
    setInstalling(false);
  };

  const toolStatus = (tool) => {
    if (installStatus[tool.name]) return installStatus[tool.name];
    if (!tool.install_supported && !tool.installed) return "manual";
    return tool.installed ? "instalada" : "ausente";
  };

  const statusClasses = {
    "aguardando": "bg-amber-500/20 text-amber-300 border border-amber-500/40",
    "em instalacao": "bg-sky-500/20 text-sky-300 border border-sky-500/40",
    "instalada": "bg-emerald-500/20 text-emerald-300 border border-emerald-500/40",
    "ausente": "bg-rose-500/20 text-rose-300 border border-rose-500/40",
    "manual": "bg-violet-500/20 text-violet-300 border border-violet-500/40",
  };

  const installedCount = requirementsCatalog.filter((tool) => tool.installed).length;
  const missingCount = requirementsCatalog.filter((tool) => !tool.installed).length;
  const manualCount = requirementsCatalog.filter((tool) => !tool.installed && !tool.install_supported).length;
  const installableCount = requirementsCatalog.filter((tool) => !tool.installed && tool.install_supported).length;

  return (
    <main className="mx-auto mt-6 w-[95%] max-w-7xl space-y-4 pb-10">
      <section className="panel p-5">
        <div className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
          <div>
            <h2 className="text-xl font-semibold">Tools</h2>
            <p className="mt-1 text-sm text-slate-300">Inventario real por grupo, com requisitos, URLs oficiais e status operacional.</p>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={installMissingTools}
              disabled={loading || installing}
              className="rounded-xl bg-emerald-500 px-4 py-2 font-semibold text-white disabled:cursor-not-allowed disabled:opacity-60"
            >
              {installing ? "Instalando..." : "Instalar ausentes suportadas"}
            </button>
            <button
              onClick={load}
              disabled={loading || installing}
              className="rounded-xl bg-blue-600 px-4 py-2 font-semibold text-white disabled:cursor-not-allowed disabled:opacity-60"
            >
              Atualizar
            </button>
          </div>
        </div>
        <p className="mt-2 text-xs text-slate-400">Status: aguardando, em instalacao, instalada, ausente ou instalacao manual.</p>
      </section>

      {error && <section className="rounded-xl border border-rose-500/30 bg-rose-500/10 px-4 py-2 text-sm text-rose-200">{error}</section>}

      <section className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
        <SummaryCard label="Instaladas" value={installedCount} tone="text-emerald-300" />
        <SummaryCard label="Ausentes" value={missingCount} tone="text-rose-300" />
        <SummaryCard label="Auto instalaveis" value={installableCount} tone="text-blue-300" />
        <SummaryCard label="Manuais/externas" value={manualCount} tone="text-violet-300" />
      </section>

      <section className="grid gap-3 lg:grid-cols-2">
        <div className="panel p-5">
          <div className="flex items-center justify-between gap-2">
            <div>
              <h3 className="text-lg font-semibold">Credenciais Externas</h3>
              <p className="mt-1 text-xs text-slate-400">Ferramentas dependentes de chaves ou scanners externos.</p>
            </div>
          </div>
          <div className="mt-3 grid gap-3 md:grid-cols-2">
            <div className="rounded-xl border border-slate-700 bg-slate-900/70 p-4">
              <p className="text-xs uppercase tracking-[0.2em] text-slate-400">Shodan</p>
              <p className={`mt-2 text-lg font-semibold ${shodan.configured ? "text-emerald-300" : "text-amber-300"}`}>{shodan.status}</p>
              <p className="mt-1 text-sm text-slate-400">{shodan.configured ? "API pronta para uso." : "Configure a API key em Configuracao para ativar o enriquecimento."}</p>
            </div>
            <div className="rounded-xl border border-slate-700 bg-slate-900/70 p-4">
              <p className="text-xs uppercase tracking-[0.2em] text-slate-400">Nessus</p>
              <p className={`mt-2 text-lg font-semibold ${nessus.configured ? "text-emerald-300" : "text-amber-300"}`}>{nessus.status || (nessus.configured ? "ativo" : "desativado")}</p>
              <p className="mt-1 text-sm text-slate-400">{nessus.configured ? `Scanner configurado em ${nessus.url || "URL informada"}.` : "Informe URL, Access Key e Secret Key em Configuracao."}</p>
            </div>
          </div>
        </div>

        <div className="panel p-5">
          <h3 className="text-lg font-semibold">Leitura do Inventario</h3>
          <div className="mt-3 space-y-2 text-sm text-slate-300">
            <p><span className="font-semibold text-emerald-300">Instalada:</span> disponivel no container atual.</p>
            <p><span className="font-semibold text-blue-300">Auto instalavel:</span> o backend possui rotina para instalar sob demanda.</p>
            <p><span className="font-semibold text-violet-200">Manual:</span> exige stack externa, pacote do sistema, credenciais ou setup dedicado.</p>
            <p><span className="font-semibold text-amber-200">Requisito:</span> mostra dependencias minimas para subir a tool com estabilidade.</p>
          </div>
        </div>
      </section>

      <section className="panel p-5">
        {loading && <p className="text-sm text-slate-400">Carregando catalogo...</p>}

        <div className="grid gap-3 md:grid-cols-2">
          {["unit", "scheduled"].map((mode) => (
            <div key={mode} className="rounded-xl border border-slate-700 bg-slate-900/50 p-3">
              <h3 className="font-semibold uppercase">{mode}</h3>
              <div className="mt-2 space-y-2">
                {(catalog[mode] || []).map((group) => (
                  <div key={`${mode}-${group.group}`} className="rounded-lg border border-slate-800 bg-slate-950/60 p-2">
                    <p className="text-sm font-medium">{group.group} - fila {group.queue}</p>
                    <p className="text-xs text-slate-400">{group.description}</p>
                    <div className="mt-1 flex flex-wrap gap-1">
                      {(group.tools || []).map((tool) => (
                          <div key={`${group.group}-${tool.name}`} className="rounded-lg border border-slate-800 bg-slate-900/80 px-2 py-2 text-xs">
                            <div className="flex flex-wrap items-center gap-1">
                              <span className="font-semibold text-slate-200">{tool.name}</span>
                              <span className={`rounded-md px-2 py-0.5 ${statusClasses[toolStatus(tool)] || statusClasses.ausente}`}>{toolStatus(tool)}</span>
                              {tool.requires_credentials && <span className="rounded-md bg-amber-100 px-2 py-0.5 text-amber-800">credencial</span>}
                            </div>
                            <p className="mt-1 max-w-xl text-[11px] text-slate-400">{tool.requirements}</p>
                          </div>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>
      </section>

      <section className="panel p-5">
        <h3 className="text-lg font-semibold">Requisitos e URLs Oficiais</h3>
          <div className="mt-3 overflow-hidden rounded-2xl border border-slate-700">
          <div className="hidden grid-cols-[180px_120px_140px_1fr_180px] bg-slate-800/60 px-4 py-3 text-xs font-semibold uppercase tracking-[0.2em] text-slate-400 lg:grid">
            <span>Tool</span>
            <span>Status</span>
            <span>Setup</span>
            <span>Requisitos</span>
            <span>URL</span>
          </div>
          <div className="divide-y divide-slate-800">
            {requirementsCatalog.map((tool) => (
              <div key={tool.name} className="grid gap-2 px-4 py-4 lg:grid-cols-[180px_120px_140px_1fr_180px] lg:items-center">
                <div>
                  <p className="font-semibold text-slate-200">{tool.name}</p>
                  {tool.requires_credentials && <p className="text-xs text-amber-400">requer credencial</p>}
                </div>
                <div>
                  <span className={`inline-flex rounded-md px-2 py-1 text-xs ${tool.installed ? statusClasses.instalada : statusClasses.ausente}`}>{tool.installed ? "instalada" : "ausente"}</span>
                </div>
                <div>
                  <span className={`inline-flex rounded-md px-2 py-1 text-xs border ${tool.install_supported ? "bg-sky-500/20 text-sky-300 border-sky-500/40" : "bg-violet-500/20 text-violet-300 border-violet-500/40"}`}>{tool.install_supported ? "sob demanda" : "manual/externa"}</span>
                </div>
                <p className="text-sm text-slate-300">{tool.requirements}</p>
                <a href={tool.url} target="_blank" rel="noreferrer" className="text-sm text-blue-300 underline decoration-cyan-500/40 underline-offset-4">
                  {tool.url || "sem url mapeada"}
                </a>
              </div>
            ))}
          </div>
        </div>
      </section>
    </main>
  );
}
