import { segmentsFromMessage } from "./utils";

export default function LogSegments({ msg }) {
  const segments = segmentsFromMessage(msg);

  return (
    <span className="break-all">
      {segments.map((segment, index) => {
        if (segment.type === "plain") {
          return <span key={index}>{segment.text}</span>;
        }

        if (segment.type === "prefix") {
          return <span key={index} className="text-slate-500 mr-1">{segment.text}</span>;
        }

        const keyColor = {
          tool: "text-sky-400",
          status: "text-emerald-400",
          return_code: "text-yellow-400",
          cmd: "text-violet-400",
          stdout: "text-slate-300",
          stderr: "text-rose-400",
          dispatch_error: "text-rose-400",
          skipped: "text-amber-400",
        }[segment.key] || "text-slate-400";

        return (
          <span key={index} className="mr-2">
            <span className={`${keyColor} font-semibold`}>{segment.key}</span>
            <span className="text-slate-600">=</span>
            <span className="text-slate-200">{segment.val}</span>
          </span>
        );
      })}
    </span>
  );
}