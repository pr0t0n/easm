import { useEffect, useRef } from "react";
import { Link } from "react-router-dom";
import "../styles/landing.css";

const COMPLIANCE = [
  "SOC 2 Type II", "ISO 27001:2022", "LGPD · ANPD", "PCI DSS Level 1",
  "OWASP Top 10", "MITRE ATT&CK", "NIST 800-53", "CIS Controls v8",
  "CVE · CVSS · EPSS · KEV", "Hospedagem BR-SE1",
];

const PRIMITIVES = [
  {
    tag: "01 · recon",
    title: "Mapeamento contínuo de domínios, portas e tecnologias.",
    body: "Amass, Sublist3r, MassDNS e Nmap em workers dedicados. Inventário diferencial dispara webhook quando algo novo aparece.",
  },
  {
    tag: "02 · osint",
    title: "Credenciais vazadas e exposições, cruzadas com o escopo.",
    body: "h8mail, Shodan, GitHub dorks. Match automático com ativos descobertos — sem ruído de leaks fora do perímetro.",
  },
  {
    tag: "03 · vuln",
    title: "Nuclei, Nikto, SQLMap e mais, orquestrados.",
    body: "Achados deduplicados, enriquecidos com EPSS + KEV, priorizados por FAIR e AGE. Só o que move o número.",
  },
  {
    tag: "04 · governança",
    title: "Gate de autorização por escopo e policy ativa.",
    body: "Allowlist obrigatória. Toda decisão de agente gravada. Trilha supervisor-worker hash-encadeada — auditável em um clique.",
  },
];

const CHART = [38, 46, 41, 55, 49, 64, 58, 71, 65, 74, 78, 88];

export default function LandingPage() {
  const chartRef = useRef(null);

  useEffect(() => {
    const chart = chartRef.current;
    if (!chart) return;
    const bars = chart.querySelectorAll(".bar");
    const animate = () => bars.forEach((bar, i) => {
      setTimeout(() => { bar.style.height = `${CHART[i]}%`; }, i * 60);
    });
    const io = new IntersectionObserver((entries) => {
      entries.forEach((entry) => {
        if (entry.isIntersecting) { animate(); io.disconnect(); }
      });
    }, { threshold: 0.25 });
    io.observe(chart);
    return () => io.disconnect();
  }, []);

  return (
    <div className="lp">
      {/* NAV */}
      <header className="nav">
        <div className="nav-inner">
          <Link to="/" className="brand">
            <span className="mk" />
            ScriptKidd<span className="ext">.o</span>
          </Link>
          <nav className="nav-links">
            <a href="#plataforma">Plataforma</a>
            <a href="#operador">Operação</a>
            <a href="#compliance">Compliance</a>
          </nav>
          <div className="nav-cta">
            <Link className="btn btn-ghost" to="/login">Entrar</Link>
            <Link className="btn btn-primary" to="/login">Acessar console →</Link>
          </div>
        </div>
      </header>

      {/* HERO */}
      <section className="hero">
        <div>
          <span className="eyebrow"><span className="dot" />console operacional · v2.4 · 2026</span>
          <h1 className="h1">Pentest contínuo,<br /><em>antes deles.</em></h1>
          <p className="lede">
            ScriptKidd.o é a plataforma de pentest automatizado para times que precisam
            ver a superfície externa como o adversário vê — recon, OSINT e vuln scanning
            orquestrados em agentes governados, com trilha auditável de ponta a ponta.
          </p>
          <div className="hero-actions">
            <Link className="btn btn-primary" to="/login">Acessar console →</Link>
            <a className="btn btn-ghost" href="#plataforma">▶ Conhecer a plataforma</a>
          </div>
          <div className="hero-meta">
            <div><div className="num">22<em>×</em></div><div className="lab">Fases do pipeline</div></div>
            <div><div className="num">9<em></em></div><div className="lab">Workers especializados</div></div>
            <div><div className="num">A–F<em></em></div><div className="lab">Rating FAIR + AGE</div></div>
            <div><div className="num">100<em>%</em></div><div className="lab">Ações auditadas</div></div>
          </div>
        </div>

        <aside className="hero-console" aria-hidden="true">
          <div className="hc-head">
            <span className="dots"><i /><i /><i /></span>
            <span>scan · pipeline langgraph · run #4827</span>
          </div>
          <div className="hc-body">
            <span className="ln"><span className="pmpt">$</span> recon --scope authorized-targets</span>
            <span className="ln"><span className="key">[amass]</span> subdomínios <span className="ok">✓</span></span>
            <span className="ln"><span className="key">[nmap]</span> portas abertas <span className="ok">✓</span></span>
            <span className="ln"><span className="key">[osint]</span> exposições <span className="warn">!</span></span>
            <span className="ln" style={{ marginTop: 6 }}><span className="pmpt">$</span> vuln --priority crit</span>
            <span className="ln"><span className="key">nuclei</span> <span className="crit">cve</span> rce · api</span>
            <span className="ln"><span className="key">sqlmap</span> <span className="warn">idor</span> · auth</span>
            <span className="ln" style={{ marginTop: 6 }}><span className="pmpt">$</span> <span className="cur">fair --weight crown</span></span>
          </div>
        </aside>
      </section>

      {/* MARQUEE */}
      <div className="marquee" id="compliance">
        <div className="marquee-track">
          {[...COMPLIANCE, ...COMPLIANCE].map((item, i) => (
            <span className="marquee-item" key={i}><span className="pip" />{item}</span>
          ))}
        </div>
      </div>

      {/* BENTO */}
      <section className="section" id="plataforma">
        <div className="section-eyebrow">Plataforma · 04 primitivas</div>
        <div className="section-head">
          <h2>Uma plataforma.<br /><em>Toda a superfície.</em></h2>
          <p className="sub">
            Quatro primitivas compostas em um backoffice ofensivo. Orquestrado por
            agentes LangGraph, supervisionado por humanos, auditado por padrão.
          </p>
        </div>

        <div className="bento">
          <div className="cell cell-feature c-8">
            <div className="ico">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><path d="M3 3v18h18" /><path d="m19 9-5 5-4-4-3 3" /></svg>
            </div>
            <h3>Rating FAIR em <em>tempo real</em>, com curva temporal de exposição.</h3>
            <p>Decomponha a postura em pilares ponderados. Atribua peso por crown jewel. Veja o delta semanal antes da reunião de risco — não depois.</p>
            <div className="chart-wrap">
              <div className="chart-meta">
                <span><span className="km">fair_score</span> 73 → 81 <span className="delta-up">+8 · 7d</span></span>
                <span><span className="km">findings_open</span> 312 <span className="delta-up">−18 · 7d</span></span>
              </div>
              <div className="chart" ref={chartRef}>
                {CHART.map((_, i) => (
                  <div key={i} className={`bar${i === CHART.length - 1 ? " live" : ""}`} />
                ))}
              </div>
              <div className="chart-axis">
                {["S1", "S2", "S3", "S4", "S5", "S6", "S7", "S8", "S9", "S10", "S11", "agora"].map((s) => <span key={s}>{s}</span>)}
              </div>
            </div>
          </div>

          {PRIMITIVES.map((p) => (
            <div className="cell c-4" key={p.tag}>
              <span className="tag">{p.tag}</span>
              <div className="ico">
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><circle cx="12" cy="12" r="9" /><path d="M12 3v4M12 17v4M3 12h4M17 12h4" /></svg>
              </div>
              <h3>{p.title}</h3>
              <p>{p.body}</p>
            </div>
          ))}
        </div>
      </section>

      {/* OPERADOR */}
      <section className="section" id="operador" style={{ paddingTop: 0 }}>
        <div className="section-eyebrow">Para quem opera</div>
        <div className="section-head">
          <h2>Construído para o <em>operador,</em><br />não para o auditor.</h2>
          <p className="sub">API-first, workers isolados, trilha hash-encadeada e replay determinístico de qualquer execução.</p>
        </div>
        <div className="bento">
          {[
            ["API-first, por princípio.", "Toda ação do console é endpoint REST autenticado e webhook tipado — automatize escopo, scans e relatórios."],
            ["Workers especializados, sem cross-contamination.", "Pools RECON, OSINT e VULN separados. Logs por job, por worker, por agente LangGraph."],
            ["Trilha supervisor-worker, hash-encadeada.", "Cada decisão do agente gravada. Toda evidência com hash imutável. Auditoria forense em um clique."],
          ].map(([h, b]) => (
            <div className="cell c-4" key={h}>
              <div className="ico">
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><path d="M12 3 4 7v5c0 5 3.4 8.5 8 9 4.6-.5 8-4 8-9V7z" /></svg>
              </div>
              <h3>{h}</h3>
              <p>{b}</p>
            </div>
          ))}
        </div>
      </section>

      {/* CTA */}
      <section className="cta-tail">
        <div className="container">
          <h2>Sua superfície,<br /><em>observada continuamente.</em></h2>
          <p>Acesso restrito · todas as ações são auditadas. O cadastro de usuários é feito exclusivamente por administradores.</p>
          <div className="actions">
            <Link className="btn btn-primary" to="/login">Entrar no console →</Link>
          </div>
          <div className="sig">
            <span className="ln" />
            ScriptKidd.o · console seguro
            <span className="ln" />
          </div>
        </div>
      </section>

      {/* FOOTER */}
      <footer className="footnote">
        <div className="footnote-inner">
          <span className="brand"><span className="mk" />ScriptKidd<span className="ext">.o</span></span>
          <div className="links">
            <a href="#plataforma">Plataforma</a>
            <a href="#operador">Operação</a>
            <a href="#compliance">Compliance</a>
          </div>
          <div className="mono" style={{ fontSize: 11 }}>© 2026 ScriptKidd.o · Uso defensivo autorizado</div>
        </div>
      </footer>
    </div>
  );
}
