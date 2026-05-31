import { useEffect, useState } from "react";
import client from "../api/client";

const STATUS_META = {
  disabled: {
    label: "Desativado",
    color: "var(--sev-critical-text)",
    bg: "var(--sev-critical-bg)",
    border: "var(--sev-critical-text)",
  },
  restricted: {
    label: "Restrito",
    color: "var(--sev-medium-text)",
    bg: "var(--sev-medium-bg)",
    border: "var(--sev-medium-text)",
  },
};

function StatusFlag({ status }) {
  const m = STATUS_META[status] || STATUS_META.disabled;
  return (
    <span
      style={{
        display: "inline-flex",
        alignItems: "center",
        gap: 6,
        padding: "4px 10px",
        borderRadius: 999,
        fontSize: 11.5,
        fontWeight: 800,
        letterSpacing: "0.04em",
        textTransform: "uppercase",
        color: m.color,
        background: m.bg,
        border: `1px solid ${m.color}`,
      }}
    >
      <span
        aria-hidden
        style={{ width: 7, height: 7, borderRadius: "50%", background: m.color }}
      />
      {m.label}
    </span>
  );
}

export default function GuardrailsPage() {
  const [policy, setPolicy] = useState(null);
  const [error, setError] = useState("");

  useEffect(() => {
    client
      .get("/api/guardrails")
      .then(({ data }) => setPolicy(data))
      .catch((e) => setError(e?.response?.data?.detail || "Falha ao carregar a política de guardrail."));
  }, []);

  const attacks = policy?.attacks || [];
  const summary = policy?.summary || { total: 0, disabled: 0, restricted: 0 };

  return (
    <main className="dpage">
      {/* Cabeçalho */}
      <section style={{ marginBottom: 20 }}>
        <p
          style={{
            margin: 0,
            fontSize: 11,
            fontWeight: 700,
            letterSpacing: "0.08em",
            textTransform: "uppercase",
            color: "var(--ink-muted)",
          }}
        >
          Segurança Ofensiva · Guardrails
        </p>
        <h2 style={{ margin: "4px 0 8px", color: "var(--ink)" }}>
          Ataques de Impacto — Execução Desativada
        </h2>
        <p style={{ margin: 0, maxWidth: 760, color: "var(--ink-soft)", fontSize: 13.5, lineHeight: 1.55 }}>
          {policy?.principle ||
            "A plataforma é um pentest automatizado. Ataques que causariam impacto real são permanentemente desativados: informamos a possibilidade de execução, nunca o efeito destrutivo."}
        </p>
      </section>

      {error && (
        <div
          style={{
            marginBottom: 16,
            padding: "12px 14px",
            borderRadius: 10,
            background: "var(--sev-critical-bg)",
            color: "var(--sev-critical-text)",
            border: "1px solid var(--sev-critical-text)",
            fontSize: 13,
          }}
        >
          {error}
        </div>
      )}

      {/* Resumo */}
      <section style={{ display: "flex", gap: 12, marginBottom: 22, flexWrap: "wrap" }}>
        {[
          { k: "Controles ativos", v: summary.total, c: "var(--ink)" },
          { k: "Desativados", v: summary.disabled, c: "var(--sev-critical-text)" },
          { k: "Restritos", v: summary.restricted, c: "var(--sev-medium-text)" },
        ].map((x) => (
          <div
            key={x.k}
            style={{
              flex: "1 1 160px",
              background: "var(--surface)",
              border: "1px solid var(--line)",
              borderRadius: 12,
              padding: "14px 16px",
              boxShadow: "var(--shadow-card)",
            }}
          >
            <div style={{ fontSize: 28, fontWeight: 800, color: x.c, lineHeight: 1 }}>{x.v}</div>
            <div style={{ marginTop: 6, fontSize: 12, color: "var(--ink-muted)" }}>{x.k}</div>
          </div>
        ))}
      </section>

      {/* Lista de ataques */}
      <section style={{ display: "grid", gap: 14 }}>
        {attacks.map((a) => (
          <article
            key={a.id}
            style={{
              background: "var(--surface)",
              border: "1px solid var(--line)",
              borderLeft: `3px solid ${(STATUS_META[a.status] || STATUS_META.disabled).color}`,
              borderRadius: 12,
              padding: "16px 18px",
              boxShadow: "var(--shadow-card)",
            }}
          >
            <header
              style={{
                display: "flex",
                alignItems: "flex-start",
                justifyContent: "space-between",
                gap: 12,
                marginBottom: 12,
              }}
            >
              <div>
                <div style={{ fontSize: 16, fontWeight: 700, color: "var(--ink)" }}>{a.name}</div>
                <div style={{ marginTop: 3, fontSize: 11.5, color: "var(--ink-muted)", textTransform: "uppercase", letterSpacing: "0.04em" }}>
                  {a.category}
                </div>
              </div>
              <StatusFlag status={a.status} />
            </header>

            {a.impact_if_executed && (
              <div style={{ marginBottom: 12, fontSize: 12.5, color: "var(--ink-soft)" }}>
                <b style={{ color: "var(--ink)" }}>Impacto se executado:</b> {a.impact_if_executed}
              </div>
            )}

            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10, marginBottom: 12 }}>
              <div
                style={{
                  background: "var(--sev-low-bg)",
                  border: "1px solid var(--sev-low-text)",
                  borderRadius: 9,
                  padding: "10px 12px",
                }}
              >
                <div style={{ fontSize: 11, fontWeight: 700, color: "var(--sev-low-text)", textTransform: "uppercase", letterSpacing: "0.04em", marginBottom: 4 }}>
                  ✓ O que fazemos
                </div>
                <div style={{ fontSize: 12.5, color: "var(--ink-soft)", lineHeight: 1.5 }}>{a.what_we_do}</div>
              </div>
              <div
                style={{
                  background: "var(--sev-critical-bg)",
                  border: "1px solid var(--sev-critical-text)",
                  borderRadius: 9,
                  padding: "10px 12px",
                }}
              >
                <div style={{ fontSize: 11, fontWeight: 700, color: "var(--sev-critical-text)", textTransform: "uppercase", letterSpacing: "0.04em", marginBottom: 4 }}>
                  ✕ O que NUNCA fazemos
                </div>
                <div style={{ fontSize: 12.5, color: "var(--ink-soft)", lineHeight: 1.5 }}>{a.what_we_never_do}</div>
              </div>
            </div>

            {a.enforcement && (
              <div style={{ fontSize: 12, color: "var(--ink-muted)", lineHeight: 1.5 }}>
                <b style={{ color: "var(--ink-soft)" }}>Como é aplicado:</b> {a.enforcement}
              </div>
            )}

            {Array.isArray(a.tools) && a.tools.length > 0 && (
              <div style={{ marginTop: 10, display: "flex", gap: 6, flexWrap: "wrap" }}>
                {a.tools.map((t) => (
                  <span
                    key={t}
                    style={{
                      fontFamily: "var(--font-mono)",
                      fontSize: 11,
                      color: "var(--ink-muted)",
                      background: "var(--canvas-soft, var(--canvas))",
                      border: "1px solid var(--line)",
                      borderRadius: 6,
                      padding: "2px 8px",
                    }}
                  >
                    {t}
                  </span>
                ))}
              </div>
            )}
          </article>
        ))}
      </section>

      {!policy && !error && (
        <div style={{ padding: 40, textAlign: "center", color: "var(--ink-muted)" }}>Carregando política…</div>
      )}
    </main>
  );
}
