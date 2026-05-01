import { Link, useLocation } from "react-router-dom";
import { authStore } from "../store/auth";

const PAGE_META = {
  "/":               { eyebrow: "Pentest.io · Enterprise Dashboard", title: "Visão Consolidada de Risco e Maturidade", sub: "Monitoramento contínuo de superfície externa" },
  "/targets":        { eyebrow: "Pentest · Targets",         title: "Alvos Autorizados",         sub: "Inventário de domínios e ativos sob escopo" },
  "/scan":           { eyebrow: "Pentest · Scans",           title: "Execuções Ativas",          sub: "Pipelines automatizados de pentest e estado em tempo real" },
  "/phase-monitor":  { eyebrow: "Pentest · Phase Monitor",   title: "Monitor de Fases",          sub: "Cobertura de tools por fase do pipeline 22-step" },
  "/agendamento":    { eyebrow: "Pentest · Schedules",       title: "Agendamentos",              sub: "Janelas e cadência de scans recorrentes" },
  "/vulnerabilidades": { eyebrow: "Security · Vulns",        title: "Vulnerabilidades",          sub: "Achados priorizados por severidade, FAIR e AGE" },
  "/evolucao":       { eyebrow: "Security · Evolution",      title: "Attack Evolution",          sub: "Trajetória da postura de segurança ao longo do tempo" },
  "/relatorios":     { eyebrow: "Security · Reports",        title: "Relatórios",                sub: "Documentação executiva e técnica gerada por scan" },
  "/ferramentas":    { eyebrow: "Management · Tools",        title: "Ferramentas",               sub: "Catálogo de ferramentas instaladas e cobertura" },
  "/workers":        { eyebrow: "Management · Workers",      title: "Workers",                   sub: "Heartbeats e capacidade dos agentes especializados" },
  "/jobs":           { eyebrow: "Management · Jobs Registry", title: "Jobs Registry",            sub: "Trilha de tarefas Celery por scan" },
  "/worker-logs":    { eyebrow: "Management · Logs",         title: "Worker Logs",               sub: "Streaming de logs operacionais por worker" },
  "/configuracao":   { eyebrow: "Management · Settings",     title: "Configuração",              sub: "Integrações, policies e parâmetros do produto" },
  "/usuarios":       { eyebrow: "Admin · Users",             title: "Usuários",                  sub: "Identidades, grupos e permissões" },
  "/conta":          { eyebrow: "Admin · Account",           title: "Minha Conta",               sub: "Dados de perfil e preferências" },
};

function metaFor(pathname) {
  const exact = PAGE_META[pathname];
  if (exact) return exact;
  const prefix = Object.keys(PAGE_META).find((p) => p !== "/" && pathname.startsWith(p));
  return prefix ? PAGE_META[prefix] : { eyebrow: "Pentest.io", title: "Painel", sub: "Monitoramento, risco e operações de superfície externa" };
}

export default function Navbar() {
  const me = authStore.me;
  const { pathname } = useLocation();
  const meta = metaFor(pathname);

  return (
    <header className="app-hdr">
      <div>
        <div className="app-hdr-eyebrow">{meta.eyebrow}</div>
        <h1 className="app-hdr-title">{meta.title}</h1>
        <div className="app-hdr-sub">{meta.sub}</div>
      </div>

      <div style={{ display: "flex", gap: 10, alignItems: "center" }}>
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
          Ver relatório
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
          + Novo Scan
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
