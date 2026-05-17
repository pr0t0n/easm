import { useState } from "react";
import { useNavigate } from "react-router-dom";
import client from "../api/client";
import { authStore } from "../store/auth";
import "../styles/login.css";

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

const IconMail = () => (
  <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round">
    <rect width="20" height="16" x="2" y="4" rx="2" />
    <path d="m22 7-8.97 5.7a1.94 1.94 0 0 1-2.06 0L2 7" />
  </svg>
);

const IconLock = () => (
  <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round">
    <rect width="18" height="11" x="3" y="11" rx="2" ry="2" />
    <path d="M7 11V7a5 5 0 0 1 10 0v4" />
  </svg>
);

const IconArrowRight = () => (
  <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M5 12h14" />
    <path d="m12 5 7 7-7 7" />
  </svg>
);

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
    <div className="login-stage">

      {/* ===================== LEFT — PITCH ===================== */}
      <aside className="pitch">
        <div className="brand">
          <span className="mk" />
          <div>
            <b>ScriptKidd<span className="ext">.o</span></b>
            <span className="tag">Vulnerability analysis</span>
          </div>
        </div>

        <div className="headline">
          <div className="eb">Console operacional · v2.4</div>
          <h1>Sua superfície,<br /><em>observada continuamente.</em></h1>
          <p>
            Recon, OSINT e vuln scanning orquestrados em agentes governados —
            com trilha auditável de ponta a ponta. Apenas escopo autorizado.
          </p>

          <div className="console" aria-hidden="true">
            <div className="ch">
              <span className="dot"><i /><i /><i /></span>
              <span>scan · pipeline langgraph · kali runner</span>
            </div>
            <div className="body">
              <span className="ln"><span className="pmt">$</span> recon --scope authorized-targets</span>
              <span className="ln"><span className="key">[amass]</span> subdomínios <span className="ok">✓</span></span>
              <span className="ln"><span className="key">[nmap]</span> portas e serviços <span className="ok">✓</span></span>
              <span className="ln"><span className="key">[osint]</span> exposições <span className="warn">!</span></span>
              <span className="ln" style={{ marginTop: 6 }}><span className="pmt">$</span> vuln --priority crit</span>
              <span className="ln"><span className="key">nuclei</span> <span className="crit">cve</span> rce · api</span>
              <span className="ln"><span className="key">sqlmap</span> <span className="warn">idor</span> · auth</span>
              <span className="ln"><span className="pmt">$</span> <span className="cur">fair --weight crown</span></span>
            </div>
          </div>
        </div>

        <div className="foot">
          <span>ScriptKidd.o · console</span>
          <span>console seguro · TLS 1.3</span>
        </div>
      </aside>

      {/* ===================== RIGHT — FORM ===================== */}
      <main className="form-pane">
        <form className="form" onSubmit={submit}>
          <div className="s-eb">Acesso restrito</div>
          <h2>Bem-vindo de volta.</h2>
          <div className="h-sub">Faça login para acessar seus alvos, scans e findings.</div>

          <div className="row">
            <label>Email corporativo</label>
            <div className="input-wrap">
              <span className="ico"><IconMail /></span>
              <input
                type="email"
                required
                placeholder="alice@megacorp.com"
                autoComplete="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
              />
            </div>
          </div>

          <div className="row">
            <label>
              Senha
              <a href="#" className="helper" onClick={(e) => e.preventDefault()}>esqueci a senha</a>
            </label>
            <div className="input-wrap">
              <span className="ico"><IconLock /></span>
              <input
                type="password"
                required
                placeholder="••••••••"
                autoComplete="current-password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
              />
            </div>
          </div>

          <div className="between">
            <label className="remember">
              <input type="checkbox" defaultChecked />
              Lembrar deste dispositivo
            </label>
            <span className="twofa">2FA · TOTP</span>
          </div>

          <button type="submit" className="submit" disabled={submitting}>
            {submitting ? "Processando…" : "Entrar no console"}
            {!submitting && <IconArrowRight />}
          </button>

          {error && <div className="login-err">{error}</div>}

          <div className="divider">ou continue com</div>

          <div className="sso">
            <button type="button" title="SSO indisponível" onClick={() => setError("SSO corporativo não está habilitado neste ambiente.")}>
              <span className="sw" style={{ background: "linear-gradient(135deg,#007dc1,#003a6b)" }} />
              Okta SSO
            </button>
            <button type="button" title="SSO indisponível" onClick={() => setError("SSO corporativo não está habilitado neste ambiente.")}>
              <span className="sw" style={{ background: "linear-gradient(135deg,#0078d4,#004b8d)" }} />
              Azure AD
            </button>
          </div>

          <div className="audit-notice">
            <span className="pulse" />
            Todas as ações nesta sessão são auditadas
          </div>

          <div className="legal">
            Ao fazer login você concorda com os{" "}
            <a href="#" onClick={(e) => e.preventDefault()}>termos de uso</a> e a{" "}
            <a href="#" onClick={(e) => e.preventDefault()}>política de retenção</a>.
            O cadastro de usuários é feito exclusivamente por administradores.
          </div>
        </form>
      </main>

    </div>
  );
}
