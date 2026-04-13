import LogSegments from "./LogSegments";
import { levelColor, toolColor, toolFromMsg } from "./utils";

export default function LogLine({ row }) {
  const tool = toolFromMsg(row.message);

  return (
    <div className="flex items-start gap-2 py-0.5 hover:bg-white/5 rounded px-1">
      <span className="shrink-0 text-slate-600 font-mono text-[10px] w-28 pt-0.5">
        {row.created_at ? new Date(row.created_at).toLocaleTimeString("pt-BR") : ""}
      </span>
      <span className={`shrink-0 text-[10px] w-14 font-bold uppercase pt-0.5 ${levelColor(row.level)}`}>
        {row.level}
      </span>
      {tool && (
        <span className={`shrink-0 text-[10px] rounded border px-1.5 py-0 font-mono ${toolColor(tool)}`}>
          {tool}
        </span>
      )}
      <span className={`text-xs font-mono flex-1 ${levelColor(row.level)}`}>
        <LogSegments msg={row.message} />
      </span>
    </div>
  );
}