export default function LogTerminal({ logs }) {
  const parseLogDate = (value) => {
    const raw = String(value || "").trim();
    if (!raw) return new Date();
    // Timestamps sem timezone vindos do backend representam UTC.
    const normalized = /z$|[+-]\d\d:\d\d$/i.test(raw) ? raw : `${raw}Z`;
    const parsed = new Date(normalized);
    return Number.isNaN(parsed.getTime()) ? new Date(raw) : parsed;
  };

  return (
    <div className="panel p-4">
      <h3 className="font-display text-lg font-semibold">Terminal de Logs</h3>
      <div className="mt-3 h-72 overflow-auto rounded-xl border border-slate-700/70 bg-slate-900 p-3 font-mono text-xs leading-5 text-slate-100">
        {logs.length === 0 && <p>Nenhum log ainda.</p>}
        {logs.map((log) => (
          <p key={log.id}>
            [{parseLogDate(log.created_at).toLocaleTimeString("pt-BR")}] {log.source}: {log.message}
          </p>
        ))}
      </div>
    </div>
  );
}
