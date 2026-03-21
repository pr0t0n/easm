import { useEffect, useState } from "react";
import client from "../api/client";
import { authStore } from "../store/auth";

// ─── Dados mock ──────────────────────────────────────────────────────────────
const MOCK_SCANS = [
  { id: 13, target_query: "api.valid.com", status: "completed", mode: "unit", created_at: "2026-03-19T15:05:00Z" },
  { id: 12, target_query: "valid.com", status: "completed", mode: "unit", created_at: "2026-03-19T14:22:00Z" },
  { id: 11, target_query: "cdn.valid.com", status: "completed", mode: "unit", created_at: "2026-03-18T11:30:00Z" },
  { id: 10, target_query: "auth.valid.com", status: "failed", mode: "unit", created_at: "2026-03-18T08:12:00Z" },
  { id: 9, target_query: "valid.com", status: "completed", mode: "scheduled", created_at: "2026-03-17T03:00:00Z" },
];

const MOCK_REPORT = {
  scan_id: 12,
  target: "valid.com",
  mode: "unit",
  status: "completed",
  mission_progress: 100,
  created_at: "2026-03-19T14:22:00Z",
  completed_at: "2026-03-19T14:38:41Z",
  duration_min: 16,
  findings: [
    {
      id: 1,
      title: "SQLi Time-based no parametro 'search'",
      severity: "critical",
      risk_score: 9,
      source_worker: "vuln",
      scan_mode: "unit",
      false_positive: false,
      details: {
        url: "https://valid.com/search?q=1",
        payload: "1' AND SLEEP(5)-- -",
        evidence: "Resposta com atraso de 5.03s detectado",
        cve: "CWE-89",
        qwen_recomendacao_pt: {
          resumo: "Injecao SQL classica via parametro de busca sem sanitizacao.",
          impacto: "Exfiltracao completa do banco de dados, bypass de autenticacao.",
          mitigacoes: ["Usar prepared statements / ORM", "Validar e sanitizar todas as entradas", "Implementar WAF com regras de injecao"],
          prioridade: "CRITICA",
          validacoes: ["Testar novamente apos implantacao do fix", "Verificar outros endpoints com parametros similares"],
        },
        cloudcode_recomendacao_pt: {
          resumo: "Vulnerabilidade de injecao SQL confirmada com tecnica de time-delay.",
          impacto: "Comprometimento total do banco de dados relacional.",
          mitigacoes: ["Adotar ORM com binding de parametros (ex: SQLAlchemy)", "Habilitar log de queries lentas para deteccao continua"],
          prioridade: "CRITICA",
          validacoes: ["Executar suite de SQLMap para cobertura completa", "Revisar toda camada de acesso a dados"],
        },
      },
    },
    {
      id: 2,
      title: "JWT None-algorithm Bypass",
      severity: "critical",
      risk_score: 9,
      source_worker: "vuln",
      scan_mode: "unit",
      false_positive: false,
      details: {
        url: "https://valid.com/api/profile",
        evidence: "Token com alg=none aceito pela API sem verificacao de assinatura",
        cve: "CWE-347",
        qwen_recomendacao_pt: {
          resumo: "A API aceita tokens JWT com algoritmo 'none', permitindo forjar identidades.",
          impacto: "Qualquer usuario pode se autenticar como qualquer outro, incluindo administradores.",
          mitigacoes: ["Rejeitar explicitamente o algoritmo 'none'", "Fixar algoritmo esperado na validacao do token", "Revogar todos os tokens ativos e emitir novos"],
          prioridade: "CRITICA",
          validacoes: ["Verificar todas as rotas que aceitam JWT", "Adicionar teste automatizado na suite CI"],
        },
        cloudcode_recomendacao_pt: {
          resumo: "Falha critica de validacao JWT - algoritmo none aceito.",
          impacto: "Escalonamento de privilegios trivial sem necessidade de credenciais.",
          mitigacoes: ["Utilizar biblioteca jose com algoritmo fixo (RS256 ou ES256)", "Implementar lista branca de algoritmos aceitos"],
          prioridade: "CRITICA",
          validacoes: ["Testar com token manipulado pos-fix", "Auditoria de todas as dependencias JWT"],
        },
      },
    },
    {
      id: 3,
      title: "Exposicao de arquivo .env com credenciais",
      severity: "critical",
      risk_score: 8,
      source_worker: "recon",
      scan_mode: "unit",
      false_positive: false,
      details: {
        url: "https://valid.com/.env",
        evidence: "Arquivo .env acessivel publicamente com DB_PASSWORD, AWS_SECRET_KEY",
        cve: "CWE-200",
        qwen_recomendacao_pt: {
          resumo: "Arquivo de configuracao com segredos exposto publicamente via HTTP.",
          mitigacoes: ["Bloquear acesso a arquivos .env no servidor web", "Rotacionar imediatamente todas as credenciais expostas", "Adicionar .env ao .gitignore e revisar historico do repositorio"],
          prioridade: "CRITICA",
          validacoes: ["Confirmar bloqueio com curl -I https://valid.com/.env", "Monitorar acessos ao arquivo nos logs do servidor"],
        },
        cloudcode_recomendacao_pt: {
          resumo: "Credenciais sensiveis expostas em arquivo de ambiente publico.",
          mitigacoes: ["Configurar regra no Nginx/Apache para negar acesso a arquivos dotfiles", "Usar gerenciador de segredos (Vault, AWS Secrets Manager)"],
          prioridade: "CRITICA",
          validacoes: ["Scan de recon pos-correcao para verificar bloqueio"],
        },
      },
    },
    {
      id: 4,
      title: "IDOR na rota /api/users/{id}",
      severity: "high",
      risk_score: 7,
      source_worker: "fuzzing",
      scan_mode: "unit",
      false_positive: false,
      details: {
        url: "https://valid.com/api/users/1337",
        evidence: "Usuario autenticado como ID 42 conseguiu acessar dados do ID 1337 sem restricao",
        cve: "CWE-639",
        qwen_recomendacao_pt: {
          resumo: "Referencia direta a objeto insegura permite acesso a dados de outros usuarios.",
          mitigacoes: ["Verificar ownership do objeto no backend antes de retornar dados", "Usar identificadores opacos (UUID) ao inves de IDs sequenciais"],
          prioridade: "ALTA",
          validacoes: ["Testar todos os endpoints com IDs de recursos apos o fix"],
        },
        cloudcode_recomendacao_pt: {
          resumo: "IDOR confirmado - ausencia de controle de acesso no endpoint de usuarios.",
          mitigacoes: ["Implementar ABAC (Attribute-Based Access Control)", "Adicionar middleware de autorizacao centralizado"],
          prioridade: "ALTA",
          validacoes: ["Suite de testes automatizados para controle de acesso"],
        },
      },
    },
    {
      id: 5,
      title: "Header X-Frame-Options ausente",
      severity: "medium",
      risk_score: 4,
      source_worker: "scan",
      scan_mode: "unit",
      false_positive: false,
      details: {
        url: "https://valid.com",
        evidence: "Resposta HTTP nao inclui X-Frame-Options nem CSP frame-ancestors",
        cve: "CWE-1021",
        qwen_recomendacao_pt: {
          resumo: "Ausencia de protecao contra ataques de clickjacking.",
          mitigacoes: ["Adicionar header X-Frame-Options: DENY ou SAMEORIGIN", "Adicionar CSP com frame-ancestors 'none'"],
          prioridade: "MEDIA",
          validacoes: ["Verificar headers com curl -I https://valid.com"],
        },
        cloudcode_recomendacao_pt: {
          resumo: "Site vulneravel a clickjacking por ausencia de X-Frame-Options.",
          mitigacoes: ["Configurar header no reverse proxy (Nginx/Cloudflare)"],
          prioridade: "MEDIA",
          validacoes: ["Revalidar com scanner de headers pos-configuracao"],
        },
      },
    },
    {
      id: 6,
      title: "Servico externo identificado na porta 8443",
      severity: "low",
      risk_score: 2,
      source_worker: "scan",
      scan_mode: "unit",
      false_positive: false,
      details: {
        url: "https://valid.com:8443",
        evidence: "Porta 8443 aberta com servico HTTPS nao documentado",
        qwen_recomendacao_pt: {
          resumo: "Servico HTTPS em porta nao padrao exposto publicamente.",
          mitigacoes: ["Avaliar necessidade de exposicao da porta 8443", "Aplicar rate limiting e autenticacao no servico"],
          prioridade: "BAIXA",
          validacoes: ["Revisar firewall e regras de acesso"],
        },
        cloudcode_recomendacao_pt: {
          resumo: "Porta alternativa HTTPS precisa de justificativa de negocio.",
          mitigacoes: ["Documentar ou fechar servicos em portas nao padrao"],
          prioridade: "BAIXA",
          validacoes: ["Inventario de portas abertas pos-revisao"],
        },
      },
    },
  ],
};

// ─── Utilitários ──────────────────────────────────────────────────────────────
const SEV = {
  critical: { bar: "bg-red-500", badge: "border-red-500/40 bg-red-500/10 text-red-400" },
  high: { bar: "bg-orange-500", badge: "border-orange-500/40 bg-orange-500/10 text-orange-400" },
  medium: { bar: "bg-yellow-500", badge: "border-yellow-500/40 bg-yellow-500/10 text-yellow-400" },
  low: { bar: "bg-emerald-500", badge: "border-emerald-500/40 bg-emerald-500/10 text-emerald-400" },
};
const STATUS_COLOR = {
  completed: "text-emerald-400",
  running: "text-cyan-400",
  failed: "text-red-400",
  queued: "text-yellow-400",
};
const WORKER_LABEL = {
  recon: "Recon",
  scan: "Portscan",
  fuzzing: "Fuzzing",
  vuln: "Vuln",
  analista_ia: "Analista IA",
};

function RiskBar({ score }) {
  const pct = Math.min((score / 10) * 100, 100);
  const color = score >= 8 ? "bg-red-500" : score >= 6 ? "bg-orange-500" : score >= 4 ? "bg-yellow-500" : "bg-emerald-500";
  return (
    <div className="flex items-center gap-2">
      <div className="h-1.5 w-20 overflow-hidden rounded-full bg-slate-800">
        <div className={`h-1.5 rounded-full ${color}`} style={{ width: `${pct}%` }} />
      </div>
      <span className="text-xs text-slate-400">{score}/10</span>
    </div>
  );
}

function RecoSection({ data, model }) {
  if (!data) return null;
  return (
    <div className="mt-2 rounded-xl border border-slate-700 bg-slate-800/40 p-3 text-xs">
      <p className="mb-1 font-semibold text-slate-300 uppercase tracking-widest">{model}</p>
      <p className="text-slate-300 mb-2">{data.resumo}</p>
      {data.mitigacoes?.length > 0 && (
        <ul className="space-y-1 list-disc list-inside text-slate-400">
          {data.mitigacoes.map((m, i) => <li key={i}>{m}</li>)}
        </ul>
      )}
      {data.prioridade && (
        <p className="mt-2 font-semibold text-slate-400">
          Prioridade: <span className="text-white">{data.prioridade}</span>
        </p>
      )}
    </div>
  );
}

function FindingCard({ f, isAdmin, onFalsePositive }) {
  const [expanded, setExpanded] = useState(false);
  const sev = SEV[f.severity] || SEV.low;

  return (
    <div className={`rounded-2xl border ${f.false_positive ? "opacity-50 border-slate-700" : "border-slate-800"} bg-slate-900/60`}>
      <button
        className="flex w-full items-start gap-3 p-4 text-left"
        onClick={() => setExpanded((v) => !v)}
      >
        <span className={`mt-1 h-2.5 w-2.5 flex-shrink-0 rounded-full ${sev.bar}`} />
        <div className="flex-1 min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <p className="font-medium">{f.title}</p>
            {f.false_positive && (
              <span className="rounded-md bg-slate-700 px-1.5 py-0.5 text-[10px] text-slate-400">Falso Positivo</span>
            )}
          </div>
          <div className="mt-1 flex flex-wrap items-center gap-3 text-xs">
            <span className={`rounded-md border px-2 py-0.5 font-semibold uppercase ${sev.badge}`}>{f.severity}</span>
            <RiskBar score={f.risk_score} />
            <span className="text-slate-500">{WORKER_LABEL[f.source_worker] || f.source_worker}</span>
            <span className="text-slate-500">modo: {f.scan_mode || "–"}</span>
          </div>
        </div>
        <span className="text-slate-500 text-sm">{expanded ? "▲" : "▼"}</span>
      </button>

      {expanded && (
        <div className="border-t border-slate-800 px-4 pb-4 pt-3 space-y-3 text-sm">
          {f.details?.url && (
            <p className="font-mono text-xs text-slate-400 break-all">{f.details.url}</p>
          )}
          {f.details?.evidence && (
            <p className="rounded-lg bg-slate-800/60 px-3 py-2 text-xs text-slate-300">{f.details.evidence}</p>
          )}
          {f.details?.payload && (
            <p className="rounded-lg bg-slate-950 px-3 py-2 font-mono text-xs text-emerald-300">
              PAYLOAD: {f.details.payload}
            </p>
          )}
          {f.details?.cve && (
            <p className="text-xs text-slate-500">Referencia: <span className="text-sky-400">{f.details.cve}</span></p>
          )}

          {f.details?.qwen_recomendacao_pt && (
            <RecoSection data={f.details.qwen_recomendacao_pt} model="Qwen 2.5 — Recomendacao PT-BR" />
          )}
          {f.details?.cloudcode_recomendacao_pt && (
            <RecoSection data={f.details.cloudcode_recomendacao_pt} model="CloudCode (Llama) — Recomendacao PT-BR" />
          )}

          {isAdmin && !f.false_positive && (
            <button
              onClick={() => onFalsePositive(f.id)}
              className="rounded-lg bg-emerald-500/20 px-3 py-1.5 text-xs text-emerald-300 hover:bg-emerald-500/30"
            >
              Marcar como Falso Positivo
            </button>
          )}
        </div>
      )}
    </div>
  );
}

export default function ReportsPage() {
  const me = authStore.me;
  const isAdmin = Boolean(me?.is_admin);
  const [scans, setScans] = useState([]);
  const [report, setReport] = useState(null);
  const [loading, setLoading] = useState(false);
  const [useMock, setUseMock] = useState(false);
  const [filter, setFilter] = useState("all");

  useEffect(() => {
    client
      .get("/api/scans")
      .then((res) => setScans(res.data))
      .catch(() => {
        setScans(MOCK_SCANS);
        setUseMock(true);
      });
  }, []);

  const openReport = async (scanId) => {
    setLoading(true);
    try {
      const { data } = await client.get(`/api/scans/${scanId}/report`);
      setReport(data);
    } catch {
      // Fallback mock: usa o relatorio mock independente do ID selecionado
      setReport({ ...MOCK_REPORT, scan_id: scanId });
      setUseMock(true);
    } finally {
      setLoading(false);
    }
  };

  const markFalsePositive = async (findingId) => {
    try {
      await client.post(`/api/findings/${findingId}/false-positive`);
    } catch {
      /* demonstracao */
    }
    if (report) {
      setReport((r) => ({
        ...r,
        findings: r.findings.map((f) =>
          f.id === findingId ? { ...f, false_positive: true } : f
        ),
      }));
    }
  };

  const filteredFindings = (report?.findings || []).filter((f) => {
    if (filter === "all") return true;
    if (filter === "fp") return f.false_positive;
    if (filter === "open") return !f.false_positive;
    return f.severity === filter;
  });

  const sevCount = (sev) => (report?.findings || []).filter((f) => f.severity === sev && !f.false_positive).length;

  return (
    <main className="mx-auto mt-6 w-[95%] max-w-7xl space-y-5 pb-12">
      {useMock && (
        <div className="rounded-xl border border-yellow-500/30 bg-yellow-500/10 px-4 py-2 text-xs text-yellow-300">
          Exibindo dados de demonstracao — backend nao disponivel
        </div>
      )}

      <div className="grid gap-4 lg:grid-cols-[280px_1fr]">
        {/* ── Lista de scans ──────────────────────────────────────────── */}
        <section className="rounded-2xl border border-slate-800 bg-slate-900/60 p-4">
          <h2 className="font-display text-base font-semibold">Scans Executados</h2>
          <div className="mt-3 space-y-2">
            {scans.map((scan) => (
              <button
                key={scan.id}
                onClick={() => openReport(scan.id)}
                className={`w-full rounded-xl border p-3 text-left transition-colors ${
                  report?.scan_id === scan.id
                    ? "border-brand-500/60 bg-brand-500/10"
                    : "border-slate-800 bg-slate-800/40 hover:border-slate-700"
                }`}
              >
                <div className="flex items-center justify-between">
                  <p className="font-mono text-sm font-medium">{scan.target_query}</p>
                  <span className={`text-[10px] font-semibold uppercase ${STATUS_COLOR[scan.status] || "text-slate-400"}`}>
                    {scan.status}
                  </span>
                </div>
                <p className="mt-0.5 text-xs text-slate-400">
                  #{scan.id} &middot; {scan.mode === "unit" ? "Unitario" : "Agendado"} &middot;{" "}
                  {new Date(scan.created_at).toLocaleDateString("pt-BR")}
                </p>
              </button>
            ))}
          </div>
        </section>

        {/* ── Relatorio ──────────────────────────────────────────────── */}
        <section className="min-h-64">
          {loading && (
            <div className="flex h-48 items-center justify-center">
              <div className="h-8 w-8 animate-spin rounded-full border-2 border-brand-500 border-t-transparent" />
            </div>
          )}

          {!loading && !report && (
            <div className="flex h-48 items-center justify-center rounded-2xl border border-dashed border-slate-700 text-sm text-slate-500">
              Selecione um scan para visualizar o relatorio
            </div>
          )}

          {!loading && report && (
            <div className="space-y-4">
              {/* Header do relatorio */}
              <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-5">
                <div className="flex flex-wrap items-start justify-between gap-3">
                  <div>
                    <h2 className="font-display text-2xl font-bold">{report.target || `Scan #${report.scan_id}`}</h2>
                    <p className="mt-1 text-sm text-slate-400">
                      Scan #{report.scan_id} &middot;{" "}
                      {report.mode === "unit" ? "Execucao Unitaria" : "Execucao Agendada"} &middot;{" "}
                      <span className={STATUS_COLOR[report.status] || ""}>{report.status}</span>
                    </p>
                    {report.created_at && (
                      <p className="text-xs text-slate-500 mt-1">
                        Iniciado: {new Date(report.created_at).toLocaleString("pt-BR")}
                        {report.duration_min && ` &middot; Duracao: ~${report.duration_min} min`}
                      </p>
                    )}
                  </div>
                  <div className="text-right">
                    <p className="text-xs text-slate-400">Progresso da missao</p>
                    <p className="text-2xl font-bold font-display text-brand-500">{report.mission_progress ?? 100}%</p>
                  </div>
                </div>

                {/* Contadores por severidade */}
                <div className="mt-4 grid grid-cols-4 gap-3">
                  {["critical", "high", "medium", "low"].map((s) => (
                    <button
                      key={s}
                      onClick={() => setFilter(filter === s ? "all" : s)}
                      className={`rounded-xl border p-3 text-center transition-colors ${SEV[s].badge} ${filter === s ? "ring-1 ring-current" : ""}`}
                    >
                      <p className="text-2xl font-bold font-display">{sevCount(s)}</p>
                      <p className="text-[10px] uppercase font-semibold mt-0.5">{s}</p>
                    </button>
                  ))}
                </div>

                {/* Filtros */}
                <div className="mt-3 flex flex-wrap gap-2 text-xs">
                  {[
                    { key: "all", label: "Todos" },
                    { key: "open", label: "Abertos" },
                    { key: "fp", label: "Falsos Positivos" },
                  ].map(({ key, label }) => (
                    <button
                      key={key}
                      onClick={() => setFilter(key)}
                      className={`rounded-lg px-3 py-1.5 transition-colors ${
                        filter === key
                          ? "bg-brand-500 text-slate-950 font-semibold"
                          : "bg-slate-800 text-slate-300 hover:bg-slate-700"
                      }`}
                    >
                      {label}
                    </button>
                  ))}
                </div>
              </div>

              {/* Lista de findings */}
              <div className="space-y-3">
                {filteredFindings.length === 0 && (
                  <p className="rounded-xl border border-dashed border-slate-700 py-8 text-center text-sm text-slate-500">
                    Nenhum finding neste filtro
                  </p>
                )}
                {filteredFindings.map((f) => (
                  <FindingCard
                    key={f.id}
                    f={f}
                    isAdmin={isAdmin}
                    onFalsePositive={markFalsePositive}
                  />
                ))}
              </div>
            </div>
          )}
        </section>
      </div>
    </main>
  );
}

