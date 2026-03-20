import { useEffect, useState } from "react";
import client from "../api/client";

export default function DashboardPage() {
  const [data, setData] = useState(null);

  useEffect(() => {
    client.get("/api/dashboard").then((res) => setData(res.data));
  }, []);

  if (!data) return <p className="p-6">Carregando...</p>;

  const frameworks = Object.entries(data.frameworks);

  return (
    <main className="mx-auto mt-6 grid w-[95%] max-w-6xl gap-4 pb-10 md:grid-cols-2">
      <section className="panel p-5">
        <h2 className="text-xl font-semibold">Visao Geral</h2>
        <div className="mt-4 grid grid-cols-2 gap-3 text-sm">
          <div className="rounded-xl bg-slate-800/70 p-3">Scans: {data.stats.scans}</div>
          <div className="rounded-xl bg-slate-800/70 p-3">Findings: {data.stats.findings_total}</div>
          <div className="rounded-xl bg-slate-800/70 p-3">Abertos: {data.stats.findings_open}</div>
          <div className="rounded-xl bg-slate-800/70 p-3">Triados: {data.stats.findings_triaged}</div>
        </div>
      </section>

      <section className="panel p-5">
        <h2 className="text-xl font-semibold">Maturidade por Framework</h2>
        <div className="mt-4 space-y-3">
          {frameworks.map(([name, info]) => (
            <div key={name}>
              <div className="mb-1 flex justify-between text-sm">
                <span className="uppercase">{name}</span>
                <span>{info.score}%</span>
              </div>
              <div className="h-2 rounded-full bg-slate-800">
                <div className="h-2 rounded-full bg-gradient-to-r from-cyan-400 to-emerald-400" style={{ width: `${info.score}%` }} />
              </div>
            </div>
          ))}
        </div>
      </section>
    </main>
  );
}
