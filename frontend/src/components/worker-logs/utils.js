import { toastError, toastSuccess } from "../../utils/toast";

export const STATUS_COLORS = {
  executed: "bg-emerald-500/20 text-emerald-300 border-emerald-500/40",
  success: "bg-emerald-500/20 text-emerald-300 border-emerald-500/40",
  skipped: "bg-amber-500/20  text-amber-300  border-amber-500/40",
  failed: "bg-rose-500/20   text-rose-300   border-rose-500/40",
  error: "bg-rose-500/20   text-rose-300   border-rose-500/40",
  unknown: "bg-slate-700/60  text-slate-400  border-slate-600",
};

export const LEVEL_COLORS = {
  DEBUG: "text-slate-400",
  INFO: "text-sky-300",
  WARNING: "text-amber-300",
  ERROR: "text-rose-400",
  CRITICAL: "text-rose-500 font-bold",
};

export const TOOL_PALETTE = {
  nmap: "border-purple-500/50 bg-purple-500/10 text-purple-300",
  "nmap-vulscan": "border-violet-500/50 bg-violet-500/10 text-violet-300",
  amass: "border-cyan-500/50   bg-cyan-500/10   text-cyan-300",
  massdns: "border-teal-500/50   bg-teal-500/10   text-teal-300",
  sublist3r: "border-sky-500/50    bg-sky-500/10    text-sky-300",
  "shodan-cli": "border-orange-500/50 bg-orange-500/10 text-orange-300",
  "burp-cli": "border-red-500/50    bg-red-500/10    text-red-300",
  nikto: "border-pink-500/50   bg-pink-500/10   text-pink-300",
  nuclei: "border-indigo-500/50 bg-indigo-500/10 text-indigo-300",
};

export const statusColor = (status) =>
  STATUS_COLORS[String(status || "unknown").toLowerCase()] || STATUS_COLORS.unknown;

export const levelColor = (level) =>
  LEVEL_COLORS[String(level || "INFO").toUpperCase()] || "text-slate-300";

export const toolColor = (tool) =>
  TOOL_PALETTE[String(tool || "").toLowerCase()] ||
  "border-slate-600 bg-slate-800/60 text-slate-300";

export const getMessageText = (value) => String(value ?? "");

export const toolFromMsg = (message) => {
  const match = /tool=([a-z0-9_\-.]+)/i.exec(getMessageText(message));
  return match ? match[1].toLowerCase() : null;
};

export const segmentsFromMessage = (message) => {
  const raw = getMessageText(message);
  const hasKeyValue = /(tool|status|return_code|cmd|stdout|stderr|dispatch_task|dispatch_error|dispatch_id|skipped|findings_extraidas|tool_findings)=/.test(raw);
  if (!hasKeyValue) {
    return [{ type: "plain", text: raw }];
  }

  const segments = [];
  let rest = raw;
  const firstKeyValue = rest.search(/(tool|status|return_code|cmd|stdout|stderr|dispatch_task|dispatch_error|dispatch_id|skipped)=/);
  if (firstKeyValue > 0) {
    segments.push({ type: "prefix", text: rest.slice(0, firstKeyValue).replace(/:\s*$/, "") });
    rest = rest.slice(firstKeyValue);
  }

  const expression = /\b(tool|status|return_code|cmd|stdout|stderr|dispatch_task|dispatch_error|dispatch_id|skipped|findings_extraidas|tool_findings)=([^\s]*)/g;
  let match;
  while ((match = expression.exec(rest)) !== null) {
    segments.push({ type: "kv", key: match[1], val: match[2] });
  }
  return segments;
};

export async function copyText(text, successMessage = "Conteudo copiado.") {
  const content = getMessageText(text);

  try {
    if (navigator?.clipboard?.writeText) {
      await navigator.clipboard.writeText(content);
    } else {
      const textarea = document.createElement("textarea");
      textarea.value = content;
      textarea.setAttribute("readonly", "");
      textarea.style.position = "absolute";
      textarea.style.left = "-9999px";
      document.body.appendChild(textarea);
      textarea.select();
      document.execCommand("copy");
      document.body.removeChild(textarea);
    }
    toastSuccess(successMessage);
  } catch {
    toastError("Falha ao copiar conteudo.");
  }
}