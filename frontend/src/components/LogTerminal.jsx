export default function LogTerminal({ logs }) {
  const parseLogDate = (value) => {
    const raw = String(value || "").trim();
    if (!raw) return new Date();
    // Timestamps do backend são gravados em -03 (America/Sao_Paulo), naive.
    // Ancorar explicitamente em -03 para exibir o relógio de parede correto
    // independente do fuso do navegador.
    const normalized = /z$|[+-]\d\d:\d\d$/i.test(raw) ? raw : `${raw.replace(" ", "T")}-03:00`;
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
            [{parseLogDate(log.created_at).toLocaleTimeString("pt-BR", { timeZone: "America/Sao_Paulo" })}] {log.source}: {log.message}
          </p>
        ))}
      </div>
    </div>
  );
}
