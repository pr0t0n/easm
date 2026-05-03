import { Link, useLocation } from "react-router-dom";
import { useEffect, useState } from "react";
import client from "../api/client";
import { authStore } from "../store/auth";

const PAGE_META = {
  "/":               { eyebrow: "Pentest.io · Enterprise Dashboard", title: "Visão Consolidada de Risco e Maturidade", sub: "Monitoramento contínuo de superfície externa" },
  "/targets":        { eyebrow: "Pentest · Targets",         title: "Alvos Autorizados",         sub: "Inventário de domínios e ativos sob escopo" },
  "/scan":           { eyebrow: "Pentest · Scans",           title: "Execuções Ativas",          sub: "Pipelines automatizados de pentest e estado em tempo real" },
  "/phase-monitor":  { eyebrow: "Pentest · Phase Monitor",   title: "Monitor de Fases",          sub: "Cobertura de tools por fase do pipeline 22-step" },
  "/agendamento":    { eyebrow: "Pentest · Schedules",       title: "Agendamentos",              sub: "Janelas e cadência de scans recorrentes" },
  "/vulnerabilidades": { eyebrow: "Security · Vulns",        title: "Vulnerabilidades",          sub: "Achados priorizados por severidade, FAIR e AGE" },
  "/evolucao":       { eyebrow: "Security · Evolution",      title: "Attack Evolution",          sub: "Trajetória da postura de segurança ao longo do tempo" },
  "/aprendizado":    { eyebrow: "Security · Learning",        title: "Aprendizado de Vulnerabilidades", sub: "Técnicas revisadas antes de entrar na missão dos agentes" },
  "/relatorios":     { eyebrow: "Security · Reports",        title: "Relatórios",                sub: "Documentação executiva e técnica gerada por scan" },
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

  return (
    <header className="app-hdr">
      <div>
        <span
          style={{
            display: "inline-flex",
            alignItems: "center",
            gap: 6,
            padding: "3px 10px",
            borderRadius: 999,
            background: "var(--brand-50)",
            border: "1px solid rgba(233,99,99,0.25)",
            color: "var(--brand-700)",
            fontSize: 10,
            fontWeight: 700,
            letterSpacing: "0.18em",
            textTransform: "uppercase",
          }}
        >
          <span
            style={{
              width: 6,
              height: 6,
              borderRadius: 999,
              background: "var(--brand-500)",
              display: "inline-block",
            }}
          />
          {meta.eyebrow}
        </span>
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
