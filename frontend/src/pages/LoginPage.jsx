import { useState } from "react";
import { useNavigate } from "react-router-dom";
import client from "../api/client";
import { authStore } from "../store/auth";

function normalizeApiError(err) {
  const detail = err?.response?.data?.detail;

  if (!detail) return "Falha ao autenticar.";

  if (typeof detail === "string") return detail;

  if (Array.isArray(detail)) {
    const messages = detail
      .map((item) => {
        if (typeof item === "string") return item;
        if (item && typeof item === "object") {
          const loc = Array.isArray(item.loc)
            ? item.loc.filter((v) => typeof v === "string" || typeof v === "number").join(".")
            : "";
          const msg = typeof item.msg === "string" ? item.msg : "entrada invalida";
          return loc ? `${loc}: ${msg}` : msg;
        }
        return "entrada invalida";
      })
      .filter(Boolean);

    return messages.length ? messages.join(" | ") : "Falha ao autenticar.";
  }

  if (typeof detail === "object") {
    if (typeof detail.msg === "string") return detail.msg;
    return JSON.stringify(detail);
  }

  return "Falha ao autenticar.";
}

export default function LoginPage() {
  const navigate = useNavigate();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [submitting, setSubmitting] = useState(false);

  const submit = async (e) => {
    e.preventDefault();
    setSubmitting(true);
    setError("");
    try {
      const { data } = await client.post("/api/auth/login", { email, password });
      authStore.setToken(data.access_token);
      if (data.refresh_token) {
        localStorage.setItem("refresh_token", data.refresh_token);
      }
      const me = await client.get("/api/auth/me");
      authStore.setMe(me.data);
      navigate("/");
    } catch (err) {
      setError(normalizeApiError(err));
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <main className="relative min-h-screen overflow-hidden px-4 py-8" style={{ background: "var(--bg-app-gradient)" }}>
      <div className="relative mx-auto grid min-h-[calc(100vh-4rem)] w-full max-w-7xl items-center gap-8 lg:grid-cols-[1.2fr_0.8fr]">
        <section className="rounded-2xl border p-8 lg:p-10" style={{ background: "#ffffff", borderColor: "var(--border)", boxShadow: "0 1px 2px rgba(28,28,28,0.04), 0 4px 12px rgba(28,28,28,0.04)" }}>
          <div className="inline-flex items-center gap-2 rounded-full border px-4 py-1 text-xs font-semibold uppercase tracking-[0.2em]" style={{ background: "rgba(254,123,2,0.08)", borderColor: "rgba(254,123,2,0.3)", color: "#c25500" }}>
            Pentest.io
          </div>
          <h1 className="mt-6 max-w-3xl font-display text-4xl font-semibold leading-tight lg:text-6xl" style={{ color: "var(--text-primary)" }}>
            Superficie de ataque externa com leitura executiva, operacao governada e evidencia acionavel.
          </h1>
          <p className="mt-5 max-w-2xl text-base leading-7 lg:text-lg" style={{ color: "var(--text-secondary)" }}>
            O Pentest.io identifica exposicoes em dominios, subdominios, portas, tecnologias publicadas, vulnerabilidades e achados priorizados por impacto operacional e financeiro. A plataforma cruza recon, varredura, compliance e trilha de execucao para transformar descoberta em decisao.
          </p>

          <div className="mt-8 grid gap-3 md:grid-cols-3">
            {[
              ["Descoberta", "Mapeamento de dominios, subdominios, portas, endpoints e exposicoes externas."],
              ["Prioridade", "Ranking de achados por severidade, FAIR, AGE e contexto do ambiente."],
              ["Governanca", "Gate de autorizacao, policy por cliente, auditoria e trilha supervisor-worker."],
            ].map(([t, d]) => (
              <div key={t} className="rounded-xl border p-4" style={{ borderColor: "var(--border)", background: "var(--bg-muted)" }}>
                <p className="text-xs uppercase tracking-[0.18em]" style={{ color: "var(--text-tertiary)" }}>{t}</p>
                <p className="mt-2 text-sm" style={{ color: "var(--text-primary)" }}>{d}</p>
              </div>
            ))}
          </div>

          <div className="mt-8 grid gap-3 rounded-xl border p-5 md:grid-cols-3" style={{ borderColor: "var(--border)", background: "var(--bg-muted)" }}>
            {[
              ["O que o Pentest.io encontra", "Portas expostas, frameworks, superfícies esquecidas, banners, fingerprints e ativos sem governanca."],
              ["Fontes de evidencia", "Recon DNS, HTTP probing, tecnologia web, scanners especializados e enriquecimento externo."],
              ["Saida executiva", "Dashboard consolidado, scans em andamento, top tecnologias e plano de correcao priorizado."],
            ].map(([t, d]) => (
              <div key={t}>
                <p className="text-xs uppercase tracking-[0.18em]" style={{ color: "var(--text-tertiary)" }}>{t}</p>
                <p className="mt-2 text-sm" style={{ color: "var(--text-primary)" }}>{d}</p>
              </div>
            ))}
          </div>
        </section>

        <section className="relative overflow-hidden rounded-2xl border p-6 lg:p-8" style={{ background: "#ffffff", borderColor: "var(--border)", boxShadow: "0 2px 6px rgba(28,28,28,0.06), 0 8px 24px rgba(28,28,28,0.06)" }}>
          <div className="absolute inset-x-0 top-0 h-1" style={{ background: "linear-gradient(90deg,#fe7b02,#ff66f4,#4b73ff)" }} />
          <p className="text-xs uppercase tracking-[0.2em]" style={{ color: "var(--text-tertiary)" }}>Acesso corporativo</p>
          <h2 className="mt-3 font-display text-3xl font-semibold" style={{ color: "var(--text-primary)" }}>Entrar na operacao</h2>
          <p className="mt-2 text-sm leading-6" style={{ color: "var(--text-secondary)" }}>
            Acompanhe execucoes, postura de risco e status das integrações em um painel único. O cadastro de usuarios é realizado exclusivamente por administradores.
          </p>

          <form onSubmit={submit} className="mt-6 space-y-3">
            <input
              type="email"
              required
              className="w-full rounded-xl px-4 py-3 outline-none"
              placeholder="email corporativo"
              onChange={(e) => setEmail(e.target.value)}
              style={{ border: "1px solid var(--border)" }}
            />
            <input
              type="password"
              required
              className="w-full rounded-xl px-4 py-3 outline-none"
              placeholder="senha"
              onChange={(e) => setPassword(e.target.value)}
              style={{ border: "1px solid var(--border)" }}
            />

            {error && (
              <div className="rounded-xl border px-4 py-3 text-sm" style={{ borderColor: "rgba(214,69,69,0.3)", background: "rgba(214,69,69,0.08)", color: "#b03333" }}>
                {error}
              </div>
            )}

            <button
              disabled={submitting}
              className="w-full rounded-xl px-4 py-3 font-semibold text-white disabled:opacity-50"
              style={{ background: "var(--primary)", boxShadow: "0 2px 8px rgba(254,123,2,0.25)" }}
            >
              {submitting ? "Processando..." : "Entrar"}
            </button>
          </form>

          <div className="mt-6 rounded-xl border p-4 text-sm" style={{ borderColor: "var(--border)", background: "var(--bg-muted)", color: "var(--text-secondary)" }}>
            <p className="font-semibold" style={{ color: "var(--text-primary)" }}>Fluxo recomendado</p>
            <p className="mt-2">1. Configure credenciais externas e ferramentas.</p>
            <p>2. Defina grupos, política e alvos autorizados.</p>
            <p>3. Execute scans com trilha de auditoria e acompanhamento em tempo real.</p>
          </div>
        </section>
      </div>
    </main>
  );
}
