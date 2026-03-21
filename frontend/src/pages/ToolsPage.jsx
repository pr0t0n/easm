import { useEffect, useState } from "react";
import client from "../api/client";

export default function ToolsPage() {
  const [catalog, setCatalog] = useState({ unit: [], scheduled: [] });
  const [nessus, setNessus] = useState({ configured: false, enabled: false, pynessus_installed: false, url: "" });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const load = async () => {
    setLoading(true);
    setError("");
    try {
      const { data } = await client.get("/api/config/tools");
      setCatalog(data?.catalog || { unit: [], scheduled: [] });
      setNessus(data?.nessus || { configured: false, enabled: false, pynessus_installed: false, url: "" });
    } catch (err) {
      setError(err?.response?.data?.detail || "Falha ao carregar ferramentas.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
  }, []);

  return (
    <main className="mx-auto mt-6 w-[95%] max-w-7xl space-y-4 pb-10">
      <section className="panel p-5">
        <div className="flex items-center justify-between gap-2">
          <div>
            <h2 className="text-xl font-semibold">Tools</h2>
            <p className="mt-1 text-sm text-slate-300">Inventario real de ferramentas por grupo e modo de execucao.</p>
          </div>
          <button onClick={load} className="rounded-xl bg-brand-500 px-4 py-2 font-semibold text-slate-950">Atualizar</button>
        </div>
      </section>

      {error && <section className="rounded-xl border border-rose-500/30 bg-rose-500/10 px-4 py-2 text-sm text-rose-200">{error}</section>}

      <section className="panel p-5">
        {loading && <p className="text-sm text-slate-400">Carregando catalogo...</p>}

        <div className="grid gap-3 md:grid-cols-2">
          {["unit", "scheduled"].map((mode) => (
            <div key={mode} className="rounded-xl border border-slate-800 bg-slate-900/70 p-3">
              <h3 className="font-semibold uppercase">{mode}</h3>
              <div className="mt-2 space-y-2">
                {(catalog[mode] || []).map((group) => (
                  <div key={`${mode}-${group.group}`} className="rounded-lg border border-slate-800 bg-slate-950/60 p-2">
                    <p className="text-sm font-medium">{group.group} - fila {group.queue}</p>
                    <p className="text-xs text-slate-400">{group.description}</p>
                    <div className="mt-1 flex flex-wrap gap-1">
                      {(group.tools || []).map((tool) => (
                        <span key={`${group.group}-${tool.name}`} className={`rounded-md px-2 py-0.5 text-xs ${tool.installed ? "bg-emerald-500/20 text-emerald-300" : "bg-rose-500/20 text-rose-300"}`}>
                          {tool.name} {tool.installed ? "(ok)" : "(ausente)"}
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

      <section className="panel p-5">
        <h3 className="text-lg font-semibold">Nessus</h3>
        <div className="mt-2 grid gap-2 text-sm md:grid-cols-2">
          <p>Habilitado: <span className={nessus.enabled ? "text-emerald-300" : "text-slate-300"}>{String(nessus.enabled)}</span></p>
          <p>Configurado: <span className={nessus.configured ? "text-emerald-300" : "text-amber-300"}>{String(nessus.configured)}</span></p>
          <p>pynessus instalado: <span className={nessus.pynessus_installed ? "text-emerald-300" : "text-rose-300"}>{String(nessus.pynessus_installed)}</span></p>
          <p>URL: <span className="text-slate-200">{nessus.url || "nao definida"}</span></p>
        </div>
      </section>
    </main>
  );
}
