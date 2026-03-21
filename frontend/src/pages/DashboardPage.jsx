import { useEffect, useState } from "react";
import client from "../api/client";

// ─── Dados mock ──────────────────────────────────────────────────────────────
const MOCK = {
  stats: {
    scans: 14,
    findings_total: 87,
    findings_open: 52,
    findings_triaged: 23,
    findings_false_positive: 12,
    critical: 6,
    high: 17,
    medium: 29,
    low: 35,
  },
  frameworks: {
    "ISO 27001": { score: 72, controls: 114, ok: 82 },
    "NIST CSF": { score: 65, controls: 23, ok: 15 },
    "OWASP Top 10": { score: 55, controls: 10, ok: 5 },
    "CIS Controls": { score: 80, controls: 18, ok: 14 },
  },
  recent_scans: [
    { id: 12, target: "valid.com", status: "completed", mode: "unit", findings: 11, created_at: "2026-03-19T14:22:00Z" },
    { id: 13, target: "api.valid.com", status: "completed", mode: "unit", findings: 8, created_at: "2026-03-19T15:05:00Z" },
    { id: 14, target: "valid.com", status: "running", mode: "scheduled", findings: 4, created_at: "2026-03-20T09:00:00Z" },
    { id: 11, target: "cdn.valid.com", status: "completed", mode: "unit", findings: 3, created_at: "2026-03-18T11:30:00Z" },
    { id: 10, target: "auth.valid.com", status: "failed", mode: "unit", findings: 0, created_at: "2026-03-18T08:12:00Z" },
  ],
  top_vulns: [
    { title: "SQLi Time-based (campo search)", severity: "critical", count: 3 },
    { title: "JWT None-algorithm Bypass", severity: "critical", count: 2 },
    { title: "Exposicao de .env com credenciais", severity: "critical", count: 1 },
    { title: "IDOR na rota /api/users/{id}", severity: "high", count: 5 },
    { title: "CSRF sem token na troca de email", severity: "high", count: 4 },
    { title: "Header X-Frame-Options ausente", severity: "medium", count: 9 },
    { title: "Subdominio takeover detectado", severity: "high", count: 2 },
  ],
  assets: [
    { name: "valid.com", type: "domain", ports: [80, 443], risk: "critical" },
    { name: "api.valid.com", type: "subdomain", ports: [443, 8443], risk: "high" },
    { name: "auth.valid.com", type: "subdomain", ports: [443], risk: "medium" },
    { name: "cdn.valid.com", type: "subdomain", ports: [80, 443], risk: "low" },
    { name: "staging.valid.com", type: "subdomain", ports: [80, 443, 3000], risk: "high" },
  ],
  activity: [
    { day: "Seg", scans: 2, findings: 14 },
    { day: "Ter", scans: 3, findings: 22 },
    { day: "Qua", scans: 1, findings: 8 },
    { day: "Qui", scans: 4, findings: 31 },
    { day: "Sex", scans: 2, findings: 9 },
    { day: "Sab", scans: 1, findings: 3 },
    { day: "Dom", scans: 1, findings: 4 },
  ],
};

// ─── Utilitários de cor ────────────────────────────────────────────────────────
const SEV_COLOR = {
  critical: "text-red-400 bg-red-500/10 border-red-500/30",
  high: "text-orange-400 bg-orange-500/10 border-orange-500/30",
  medium: "text-yellow-400 bg-yellow-500/10 border-yellow-500/30",
  low: "text-emerald-400 bg-emerald-500/10 border-emerald-500/30",
};
const STATUS_COLOR = {
  completed: "text-emerald-400",
  running: "text-cyan-400 animate-pulse",
  failed: "text-red-400",
  queued: "text-yellow-400",
  blocked: "text-slate-400",
};
const BAR_COLOR = {
  "ISO 27001": "from-cyan-500 to-cyan-400",
  "NIST CSF": "from-violet-500 to-violet-400",
  "OWASP Top 10": "from-orange-500 to-yellow-400",
  "CIS Controls": "from-emerald-500 to-emerald-400",
};
const RISK_DOT = {
  critical: "bg-red-500",
  high: "bg-orange-500",
  medium: "bg-yellow-500",
  low: "bg-emerald-500",
};

function StatCard({ label, value, sub, color = "text-white" }) {
  return (
    <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-4">
      <p className="text-xs uppercase tracking-widest text-slate-400">{label}</p>
      <p className={`mt-1 text-3xl font-bold font-display ${color}`}>{value}</p>
      {sub && <p className="mt-1 text-xs text-slate-500">{sub}</p>}
    </div>
  );
}

export default function DashboardPage() {
  const [data, setData] = useState(null);
  const [useMock, setUseMock] = useState(false);

  useEffect(() => {
    client
      .get("/api/dashboard")
      .then((res) => setData(res.data))
      .catch(() => {
        // Fallback para dados mock quando o backend nao esta disponivel
        setData(MOCK);
        setUseMock(true);
      });
  }, []);

  if (!data) {
    return (
      <div className="flex h-64 items-center justify-center">
        <div className="h-8 w-8 animate-spin rounded-full border-2 border-brand-500 border-t-transparent" />
      </div>
    );
  }

  const frameworks = Object.entries(data.frameworks || MOCK.frameworks);
  const stats = data.stats || MOCK.stats;
  const recentScans = data.recent_scans || MOCK.recent_scans;
  const topVulns = data.top_vulns || MOCK.top_vulns;
  const assets = data.assets || MOCK.assets;
  const activity = data.activity || MOCK.activity;
  const maxFindings = Math.max(...activity.map((a) => a.findings), 1);

  return (
    <main className="mx-auto mt-6 w-[95%] max-w-7xl space-y-5 pb-12">
      {useMock && (
        <div className="rounded-xl border border-yellow-500/30 bg-yellow-500/10 px-4 py-2 text-xs text-yellow-300">
          Exibindo dados de demonstracao — backend nao disponivel
        </div>
      )}

      {/* ── Linha 1: KPIs ──────────────────────────────────────────────── */}
      <div className="grid grid-cols-2 gap-3 md:grid-cols-4 lg:grid-cols-8">
        <div className="col-span-2 md:col-span-2">
          <StatCard label="Total de Scans" value={stats.scans} sub="todos os modos" />
        </div>
        <div className="col-span-2 md:col-span-2">
          <StatCard label="Findings Totais" value={stats.findings_total} sub={`${stats.findings_open} abertos`} />
        </div>
        <StatCard label="Critico" value={stats.critical} color="text-red-400" />
        <StatCard label="Alto" value={stats.high} color="text-orange-400" />
        <StatCard label="Medio" value={stats.medium} color="text-yellow-400" />
        <StatCard label="Baixo" value={stats.low} color="text-emerald-400" />
      </div>

      {/* ── Linha 2: Frameworks + Atividade ────────────────────────────── */}
      <div className="grid gap-4 md:grid-cols-2">
        <section className="rounded-2xl border border-slate-800 bg-slate-900/60 p-5">
          <h2 className="font-display text-lg font-semibold">Maturidade por Framework</h2>
          <div className="mt-4 space-y-4">
            {frameworks.map(([name, info]) => (
              <div key={name}>
                <div className="mb-1 flex items-center justify-between text-sm">
                  <span className="font-medium">{name}</span>
                  <span className="text-slate-400">
                    {info.ok ?? "–"}/{info.controls ?? "–"} controles &nbsp;
                    <span className="font-bold text-white">{info.score}%</span>
                  </span>
                </div>
                <div className="h-2 overflow-hidden rounded-full bg-slate-800">
                  <div
                    className={`h-2 rounded-full bg-gradient-to-r transition-all duration-700 ${BAR_COLOR[name] || "from-brand-500 to-cyan-400"}`}
                    style={{ width: `${info.score}%` }}
                  />
                </div>
              </div>
            ))}
          </div>
        </section>

        <section className="rounded-2xl border border-slate-800 bg-slate-900/60 p-5">
          <h2 className="font-display text-lg font-semibold">Atividade (7 dias)</h2>
          <div className="mt-4 flex h-36 items-end gap-2">
            {activity.map((d) => (
              <div key={d.day} className="flex flex-1 flex-col items-center gap-1">
                <span className="text-[10px] text-slate-400">{d.findings}</span>
                <div
                  className="w-full rounded-t-sm bg-gradient-to-t from-brand-500 to-cyan-400"
                  style={{ height: `${Math.round((d.findings / maxFindings) * 100)}%`, minHeight: "4px" }}
                />
                <span className="text-[10px] text-slate-500">{d.day}</span>
              </div>
            ))}
          </div>
          <p className="mt-2 text-xs text-slate-500">Findings detectados por dia de execucao</p>
        </section>
      </div>

      {/* ── Linha 3: Scans recentes + Top vulnerabilidades ──────────────── */}
      <div className="grid gap-4 lg:grid-cols-2">
        <section className="rounded-2xl border border-slate-800 bg-slate-900/60 p-5">
          <h2 className="font-display text-lg font-semibold">Scans Recentes</h2>
          <div className="mt-3 divide-y divide-slate-800">
            {recentScans.map((scan) => (
              <div key={scan.id} className="flex items-center justify-between py-3 text-sm">
                <div>
                  <p className="font-medium">{scan.target}</p>
                  <p className="text-xs text-slate-400">
                    #{scan.id} &middot; {scan.mode === "unit" ? "Unitario" : "Agendado"} &middot;{" "}
                    {new Date(scan.created_at).toLocaleString("pt-BR")}
                  </p>
                </div>
                <div className="text-right">
                  <p className={`text-xs font-semibold uppercase ${STATUS_COLOR[scan.status] || "text-slate-300"}`}>
                    {scan.status}
                  </p>
                  <p className="text-xs text-slate-400">{scan.findings} findings</p>
                </div>
              </div>
            ))}
          </div>
        </section>

        <section className="rounded-2xl border border-slate-800 bg-slate-900/60 p-5">
          <h2 className="font-display text-lg font-semibold">Top Vulnerabilidades</h2>
          <div className="mt-3 space-y-2">
            {topVulns.map((v, i) => (
              <div key={i} className={`flex items-center justify-between rounded-xl border px-3 py-2 text-sm ${SEV_COLOR[v.severity]}`}>
                <span className="flex-1">{v.title}</span>
                <div className="ml-3 flex items-center gap-2">
                  <span className="text-xs uppercase font-semibold">{v.severity}</span>
                  <span className="rounded-full bg-slate-800 px-2 py-0.5 text-xs text-slate-300">
                    ×{v.count}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </section>
      </div>

      {/* ── Linha 4: Ativos descobertos ─────────────────────────────────── */}
      <section className="rounded-2xl border border-slate-800 bg-slate-900/60 p-5">
        <h2 className="font-display text-lg font-semibold">Ativos Externos Descobertos</h2>
        <div className="mt-3 grid gap-3 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-5">
          {assets.map((asset) => (
            <div key={asset.name} className="rounded-xl border border-slate-700 bg-slate-800/50 p-3">
              <div className="flex items-center gap-2">
                <span className={`mt-0.5 h-2.5 w-2.5 flex-shrink-0 rounded-full ${RISK_DOT[asset.risk]}`} />
                <p className="truncate font-mono text-sm font-medium">{asset.name}</p>
              </div>
              <p className="mt-1 text-xs text-slate-400 capitalize">{asset.type}</p>
              <div className="mt-2 flex flex-wrap gap-1">
                {asset.ports.map((p) => (
                  <span key={p} className="rounded-md bg-slate-700 px-1.5 py-0.5 text-[10px] font-mono text-slate-300">
                    :{p}
                  </span>
                ))}
              </div>
            </div>
          ))}
        </div>
      </section>
    </main>
  );
}

