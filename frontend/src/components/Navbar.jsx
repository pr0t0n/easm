import { Link, useLocation } from "react-router-dom";
import { useEffect, useState } from "react";
import client from "../api/client";
import { authStore } from "../store/auth";

const PAGE_META = {
  "/":               { eyebrow: "Overview · Dashboard", title: "Postura de risco, em tempo real.", sub: "Pipeline LangGraph · Kali Runner · análise contínua de vulnerabilidades" },
  "/targets":        { eyebrow: "Vulnerability Ops · Targets", title: "Alvos Autorizados",       sub: "Inventário de domínios e ativos sob escopo" },
  "/scan":           { eyebrow: "Vulnerability Ops · Scans",   title: "Scans e Agendamentos",    sub: "Execução unitária e recorrente em uma única operação" },
  "/phase-monitor":  { eyebrow: "Vulnerability Ops · Phases",  title: "Monitor de Fases",        sub: "Cobertura de tools por fase do pipeline 22-step" },
  "/agendamento":    { eyebrow: "Vulnerability Ops · Schedules", title: "Agendamentos",          sub: "Janelas e cadência de scans recorrentes" },
  "/operacional":    { eyebrow: "Operations · Runtime",       title: "Centro Operacional",       sub: "Fases, agentes, jobs, workers, logs e evolução de ataque" },
  "/vulnerabilidades": { eyebrow: "Security · Vulns",        title: "Vulnerabilidades",          sub: "Achados priorizados por severidade, FAIR e AGE" },
  "/evolucao":       { eyebrow: "Security · Evolution",      title: "Attack Evolution",          sub: "Trajetória da postura de segurança ao longo do tempo" },
  "/aprendizado":    { eyebrow: "Security · Learning",        title: "Aprendizado de Vulnerabilidades", sub: "Técnicas revisadas antes de entrar na missão dos agentes" },
  "/relatorios":     { eyebrow: "Security · Report",         title: "Relatório Único",           sub: "Executivo, técnico, escopo, revisão, BAS e evidências em uma única visão" },
  "/workers":        { eyebrow: "Management · Workers",      title: "Workers",                   sub: "Heartbeats e capacidade dos agentes especializados" },
  "/jobs":           { eyebrow: "Management · Jobs Registry", title: "Jobs Registry",            sub: "Trilha de tarefas Celery por scan" },
  "/worker-logs":    { eyebrow: "Management · Logs",         title: "Worker Logs",               sub: "Streaming de logs operacionais por worker" },
  "/usuarios":       { eyebrow: "Admin · Users",             title: "Usuários",                  sub: "Identidades, grupos e permissões" },
  "/conta":          { eyebrow: "Admin · Account",           title: "Minha Conta",               sub: "Dados de perfil e preferências" },
};

function metaFor(pathname) {
  const exact = PAGE_META[pathname];
  if (exact) return exact;
  const prefix = Object.keys(PAGE_META).find((p) => p !== "/" && pathname.startsWith(p));
  return prefix ? PAGE_META[prefix] : { eyebrow: "ScriptKidd.o", title: "Painel", sub: "Monitoramento, risco e operações de análise de vulnerabilidade" };
}

export default function Navbar() {
  const me = authStore.me;
  const { pathname } = useLocation();
  const meta = metaFor(pathname);
  const [kali, setKali] = useState(null);

  useEffect(() => {
    let cancelled = false;
    const tick = async () => {
      try {
        const r = await client.get("/api/kali-runner/health");
        if (!cancelled) setKali(r.data);
      } catch {
        if (!cancelled) setKali({ runner: { reachable: false } });
      }
    };
    tick();
    const t = setInterval(tick, 30000);
    return () => { cancelled = true; clearInterval(t); };
  }, []);

  const kaliState = (() => {
    if (!kali) return { color: "#9a9a9a", label: "Kali —", bg: "#f0ebe7" };
    const reachable = kali.runner?.reachable;
    const enabled = kali.use_kali_executor;
    if (!reachable) return { color: "#b03333", label: "Kali offline", bg: "rgba(214,69,69,0.1)" };
    if (enabled) return { color: "#1f8a59", label: "Kali ativo", bg: "rgba(34,145,96,0.1)" };
    const canary = (kali.canary_tools || []).length;
    if (canary > 0) return { color: "#c25500", label: `Kali canary (${canary})`, bg: "rgba(254,123,2,0.1)" };
    return { color: "#2d52e6", label: "Kali standby", bg: "rgba(75,115,255,0.1)" };
  })();

  const crumbs = String(meta.eyebrow || "").split(/\s*[·/]\s*/).filter(Boolean);

  return (
    <header className="app-hdr">
      <div>
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: 10,
            fontSize: 10.5,
            fontWeight: 600,
            letterSpacing: "0.18em",
            textTransform: "uppercase",
            color: "var(--ink-muted)",
          }}
        >
          <span style={{ width: 24, height: 1, background: "var(--brand-500)", display: "inline-block" }} />
          {crumbs.map((crumb, i) => (
            <span key={crumb} style={{ display: "inline-flex", alignItems: "center", gap: 10 }}>
              {i > 0 && <span style={{ color: "var(--line-strong)" }}>/</span>}
              <span>{crumb}</span>
            </span>
          ))}
        </div>
        <h1 className="app-hdr-title" style={{ marginTop: 8 }}>{meta.title}</h1>
        <div className="app-hdr-sub">{meta.sub}</div>
      </div>

      <div style={{ display: "flex", gap: 10, alignItems: "center" }}>
        <span
          title={kali?.runner?.error || `${kali?.tool_profile_mappings || 0} profiles mapeados`}
          style={{
            display: "inline-flex",
            alignItems: "center",
            gap: 6,
            padding: "4px 10px",
            borderRadius: 999,
            fontSize: 11,
            fontWeight: 600,
            letterSpacing: "0.04em",
            color: kaliState.color,
            background: kaliState.bg,
            border: `1px solid ${kaliState.color}33`,
          }}
        >
          <span
            style={{
              width: 6,
              height: 6,
              borderRadius: 999,
              background: kaliState.color,
              display: "inline-block",
            }}
          />
          {kaliState.label}
        </span>
        <Link
          to="/relatorios"
          className="rounded-lg px-3 py-2 text-sm font-semibold"
          style={{
            background: "#ffffff",
            color: "var(--ink-soft)",
            border: "1px solid var(--line)",
            textDecoration: "none",
            transition: "all 160ms ease",
          }}
          onMouseEnter={(e) => {
            e.currentTarget.style.borderColor = "var(--line-strong)";
            e.currentTarget.style.color = "var(--ink)";
          }}
          onMouseLeave={(e) => {
            e.currentTarget.style.borderColor = "var(--line)";
            e.currentTarget.style.color = "var(--ink-soft)";
          }}
        >
          Relatório único
        </Link>
        <Link
          to="/scan"
          className="rounded-lg px-3 py-2 text-sm font-semibold"
          style={{
            background: "var(--primary)",
            color: "#ffffff",
            border: "1px solid var(--primary)",
            boxShadow: "var(--shadow-cta)",
            textDecoration: "none",
            transition: "all 160ms ease",
          }}
          onMouseEnter={(e) => {
            e.currentTarget.style.background = "var(--primary-hover)";
            e.currentTarget.style.boxShadow = "var(--shadow-cta-hover)";
          }}
          onMouseLeave={(e) => {
            e.currentTarget.style.background = "var(--primary)";
            e.currentTarget.style.boxShadow = "var(--shadow-cta)";
          }}
        >
          + Scan
        </Link>
        {me?.email && (
          <div
            className="hidden rounded-lg px-3 py-2 text-xs sm:block"
            style={{ background: "#ffffff", color: "var(--ink-soft)", border: "1px solid var(--line)" }}
          >
            {me.email}
          </div>
        )}
      </div>
    </header>
  );
}
