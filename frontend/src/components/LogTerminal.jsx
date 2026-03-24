export default function LogTerminal({ logs }) {
  return (
    <div className="panel p-4">
      <h3 className="font-display text-lg font-semibold">Terminal de Logs</h3>
      <div className="mt-3 h-72 overflow-auto rounded-xl border border-slate-700/70 bg-slate-900 p-3 font-mono text-xs leading-5 text-slate-100">
        {logs.length === 0 && <p>Nenhum log ainda.</p>}
        {logs.map((log) => (
          <p key={log.id}>
            [{new Date(log.created_at).toLocaleTimeString()}] {log.source}: {log.message}
          </p>
        ))}
      </div>
    </div>
  );
}
