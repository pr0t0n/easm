export default function LogTerminal({ logs }) {
  return (
    <div className="panel p-4">
      <h3 className="font-display text-lg font-semibold">Terminal de Logs</h3>
      <div className="mt-3 h-72 overflow-auto rounded-xl bg-black/60 p-3 font-mono text-xs text-emerald-300">
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
