import { useEffect, useState } from "react";
import client from "../api/client";
import { authStore } from "../store/auth";

export default function ReportsPage() {
  const me = authStore.me;
  const isAdmin = Boolean(me?.is_admin);
  const [scans, setScans] = useState([]);
  const [report, setReport] = useState(null);

  useEffect(() => {
    client.get("/api/scans").then((res) => setScans(res.data));
  }, []);

  const openReport = async (scanId) => {
    const { data } = await client.get(`/api/scans/${scanId}/report`);
    setReport(data);
  };

  const markFalsePositive = async (findingId) => {
    await client.post(`/api/findings/${findingId}/false-positive`);
    if (report) {
      openReport(report.scan_id);
    }
  };

  return (
    <main className="mx-auto mt-6 grid w-[95%] max-w-6xl gap-4 pb-10 lg:grid-cols-2">
      <section className="panel p-5">
        <h2 className="text-xl font-semibold">Relatorios</h2>
        <div className="mt-4 space-y-2">
          {scans.map((scan) => (
            <button
              key={scan.id}
              onClick={() => openReport(scan.id)}
              className="w-full rounded-xl border border-slate-800 bg-slate-900/70 p-3 text-left"
            >
              <p className="font-medium">Scan #{scan.id}</p>
              <p className="text-xs text-slate-300">{scan.target_query} | {scan.status}</p>
            </button>
          ))}
        </div>
      </section>

      <section className="panel p-5">
        {!report && <p>Escolha um scan para carregar o relatorio.</p>}
        {report && (
          <>
            <h3 className="text-lg font-semibold">Scan #{report.scan_id}</h3>
            <p className="text-sm text-slate-300">Status: {report.status}</p>
            <div className="mt-4 space-y-3">
              {report.findings.map((f) => (
                <div key={f.id} className="rounded-xl border border-slate-800 bg-slate-900/70 p-3">
                  <p className="font-medium">{f.title}</p>
                  <p className="text-xs uppercase text-slate-300">{f.severity} | score {f.risk_score}</p>
                  {isAdmin && (
                    <button
                      onClick={() => markFalsePositive(f.id)}
                      className="mt-2 rounded-lg bg-emerald-500/20 px-2 py-1 text-xs text-emerald-300"
                    >
                      Marcar como Falso Positivo
                    </button>
                  )}
                </div>
              ))}
            </div>
          </>
        )}
      </section>
    </main>
  );
}
