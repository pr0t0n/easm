import { useState } from "react";
import { useNavigate } from "react-router-dom";
import client from "../api/client";
import { authStore } from "../store/auth";

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
      setError(err?.response?.data?.detail || "Falha ao autenticar.");
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <main className="relative min-h-screen overflow-hidden bg-[#0B0F14] px-4 py-8">
      <div className="absolute inset-0 bg-[radial-gradient(circle_at_10%_8%,rgba(37,99,235,0.18),transparent_25%),radial-gradient(circle_at_85%_3%,rgba(34,197,94,0.1),transparent_20%),linear-gradient(180deg,#0B0F14_0%,#0B0F14_100%)]" />

      <div className="relative mx-auto grid min-h-[calc(100vh-4rem)] w-full max-w-7xl items-center gap-8 lg:grid-cols-[1.2fr_0.8fr]">
        <section className="rounded-2xl border border-[#374151] bg-[#111827]/85 p-8 lg:p-10">
          <div className="inline-flex items-center gap-2 rounded-full border border-blue-500/30 bg-blue-500/10 px-4 py-1 text-xs font-semibold uppercase tracking-[0.2em] text-blue-200">
            Pentest.io
          </div>
          <h1 className="mt-6 max-w-3xl font-display text-4xl font-semibold leading-tight text-[#F9FAFB] lg:text-6xl">
            Superficie de ataque externa com leitura executiva, operacao governada e evidencia acionavel.
          </h1>
          <p className="mt-5 max-w-2xl text-base leading-7 text-[#9CA3AF] lg:text-lg">
            O Pentest.io identifica exposicoes em dominios, subdominios, portas, tecnologias publicadas, vulnerabilidades e achados priorizados por impacto operacional e financeiro. A plataforma cruza recon, varredura, compliance e trilha de execucao para transformar descoberta em decisao.
          </p>

          <div className="mt-8 grid gap-3 md:grid-cols-3">
            <div className="rounded-xl border border-[#374151] bg-[#1F2937]/80 p-4">
              <p className="text-xs uppercase tracking-[0.18em] text-[#9CA3AF]">Descoberta</p>
              <p className="mt-2 text-sm text-[#F3F4F6]">Mapeamento de dominios, subdominios, portas, endpoints e exposicoes externas.</p>
            </div>
            <div className="rounded-xl border border-[#374151] bg-[#1F2937]/80 p-4">
              <p className="text-xs uppercase tracking-[0.18em] text-[#9CA3AF]">Prioridade</p>
              <p className="mt-2 text-sm text-[#F3F4F6]">Ranking de achados por severidade, FAIR, AGE e contexto do ambiente.</p>
            </div>
            <div className="rounded-xl border border-[#374151] bg-[#1F2937]/80 p-4">
              <p className="text-xs uppercase tracking-[0.18em] text-[#9CA3AF]">Governanca</p>
              <p className="mt-2 text-sm text-[#F3F4F6]">Gate de autorizacao, policy por cliente, auditoria e trilha supervisor-worker.</p>
            </div>
          </div>

          <div className="mt-8 grid gap-3 rounded-xl border border-[#374151] bg-[#0F172A]/80 p-5 md:grid-cols-3">
            <div>
              <p className="text-xs uppercase tracking-[0.18em] text-[#9CA3AF]">O que o Pentest.io encontra</p>
              <p className="mt-2 text-sm text-[#F3F4F6]">Portas expostas, frameworks, superfícies esquecidas, banners, fingerprints e ativos sem governanca.</p>
            </div>
            <div>
              <p className="text-xs uppercase tracking-[0.18em] text-[#9CA3AF]">Fontes de evidencia</p>
              <p className="mt-2 text-sm text-[#F3F4F6]">Recon DNS, HTTP probing, tecnologia web, scanners especializados e enriquecimento externo.</p>
            </div>
            <div>
              <p className="text-xs uppercase tracking-[0.18em] text-[#9CA3AF]">Saida executiva</p>
              <p className="mt-2 text-sm text-[#F3F4F6]">Dashboard consolidado, scans em andamento, top tecnologias e plano de correcao priorizado.</p>
            </div>
          </div>
        </section>

        <section className="panel relative overflow-hidden border-slate-700 bg-slate-900 p-6 lg:p-8">
          <div className="absolute inset-x-0 top-0 h-1 bg-[linear-gradient(90deg,#2563EB,#1D4ED8,#2563EB)]" />
          <p className="text-xs uppercase tracking-[0.2em] text-slate-400">Acesso corporativo</p>
          <h2 className="mt-3 font-display text-3xl font-semibold text-slate-100">Entrar na operacao</h2>
          <p className="mt-2 text-sm leading-6 text-slate-400">
            Acompanhe execucoes, postura de risco e status das integrações em um painel único. O cadastro de usuarios é realizado exclusivamente por administradores.
          </p>

          <form onSubmit={submit} className="mt-6 space-y-3">
            <input
              className="w-full rounded-xl border border-slate-700 px-4 py-3 text-slate-100 placeholder-slate-500 outline-none"
              placeholder="email corporativo"
              onChange={(e) => setEmail(e.target.value)}
            />
            <input
              type="password"
              className="w-full rounded-xl border border-slate-700 px-4 py-3 text-slate-100 placeholder-slate-500 outline-none"
              placeholder="senha"
              onChange={(e) => setPassword(e.target.value)}
            />

            {error && <div className="rounded-xl border border-rose-800/50 bg-rose-900/30 px-4 py-3 text-sm text-rose-300">{error}</div>}

            <button disabled={submitting} className="w-full rounded-xl border border-blue-500/70 bg-blue-600 px-4 py-3 font-semibold text-white shadow-[0_0_20px_rgba(37,99,235,0.22)] disabled:opacity-50 hover:bg-blue-500">
              {submitting ? "Processando..." : "Entrar"}
            </button>
          </form>

          <div className="mt-6 rounded-xl border border-slate-700 bg-slate-800 p-4 text-sm text-slate-300">
            <p className="font-semibold text-slate-100">Fluxo recomendado</p>
            <p className="mt-2">1. Configure credenciais externas e ferramentas.</p>
            <p>2. Defina grupos, política e alvos autorizados.</p>
            <p>3. Execute scans com trilha de auditoria e acompanhamento em tempo real.</p>
          </div>
        </section>
      </div>
    </main>
  );
}
