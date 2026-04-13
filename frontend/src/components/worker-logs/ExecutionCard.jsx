import { useState } from "react";
import { statusColor, toolColor } from "./utils";

export default function ExecutionCard({ run }) {
  const [open, setOpen] = useState(false);

  return (
    <div className={`rounded-xl border ${toolColor(run.tool)} mb-2`}>
      <button
        onClick={() => setOpen((value) => !value)}
        className="w-full flex flex-wrap items-center gap-2 px-4 py-2 text-left hover:bg-white/5 transition-colors"
      >
        <span className="font-mono text-sm font-bold">{run.tool}</span>
        <span className={`rounded border px-2 py-0.5 text-xs font-semibold ${statusColor(run.status)}`}>
          {run.status}
        </span>
        <span className="text-xs text-slate-400 font-mono">{run.target}</span>
        {run.execution_time_seconds != null && (
          <span className="ml-auto text-xs text-slate-500">{Number(run.execution_time_seconds).toFixed(1)}s</span>
        )}
        <span className="text-slate-600 text-xs ml-1">{open ? "▲" : "▼"}</span>
      </button>
      {open && (
        <div className="border-t border-white/10 px-4 pb-3 pt-2 space-y-2 text-xs">
          {run.error_message && (
            <div>
              <p className="text-slate-500 mb-1 font-semibold uppercase tracking-widest text-[10px]">Erro / saída</p>
              <pre className="whitespace-pre-wrap break-all bg-slate-950/70 rounded p-2 text-rose-300 font-mono leading-relaxed max-h-48 overflow-y-auto">
                {run.error_message}
              </pre>
            </div>
          )}
          <p className="text-slate-500">
            Iniciado em: <span className="text-slate-300">{run.created_at ? new Date(run.created_at).toLocaleString("pt-BR") : "-"}</span>
          </p>
        </div>
      )}
    </div>
  );
}