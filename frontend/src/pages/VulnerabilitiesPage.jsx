import { useEffect, useMemo, useState } from "react";
import client from "../api/client";
import CompanyScopeSelect from "../components/CompanyScopeSelect";
import ScanSelect from "../components/ScanSelect";
import DomainsPage from "./DomainsPage";
import "../styles/dashboard.css";

const SEV_LABEL = { critical: "Crítico", high: "Alto", medium: "Médio", low: "Baixo", info: "Info" };
const SEV_ORDER = ["critical", "high", "medium", "low", "info"];
const PAGE_SIZE = 100;
const KIND_LABEL = {
  validated_risk: "Risco validado",
  candidate_risk: "Risco candidato",
  bas_observation: "Observação BAS",
  observation: "Observação",
  false_positive: "Falso positivo",
};
const KIND_ORDER = ["validated_risk", "candidate_risk", "bas_observation", "observation", "false_positive"];
const SOURCE_LABEL = { api: "API", bas: "BAS", pentest: "Pentest", learning: "Aprendizado", osint: "OSINT", manual: "Manual" };
const SOURCE_ORDER = ["api", "bas", "pentest", "learning", "osint", "manual"];
const VSTATUS_LABEL = {
  confirmed: "Confirmado", candidate: "Candidato", hypothesis: "Hipótese", refuted: "Refutado",
  inconclusive: "Inconclusivo", blocked: "Bloqueado", not_applicable: "Não aplicável",
  invalid_evidence: "Evidência inválida", needs_human_review: "Revisão humana",
};

function mitreStr(m) {
  if (!m) return "—";
  if (typeof m === "string") return m;
  if (Array.isArray(m)) return m.map((x) => (typeof x === "string" ? x : x?.id || x?.technique_id || "")).filter(Boolean).join(", ") || "—";
  return m.id || m.technique_id || m.name || "—";
}

function apiObservationLabel(obs = {}) {
  if (!obs.visible) return "";
  const parts = [];
  if (obs.api_skill_priority != null) parts.push(`#${obs.api_skill_priority}`);
  if (obs.api_skill_name) parts.push(obs.api_skill_name);
  if (obs.tested_via) parts.push(String(obs.tested_via).toUpperCase());
  if (obs.imported_url_count != null) parts.push(`${obs.imported_url_count} URLs`);
  if (obs.alert_count != null) parts.push(`${obs.alert_count} alertas`);
  if (obs.zap_scan_type) parts.push(obs.zap_scan_type);
  return parts.join(" · ");
}

function currentUserIsAdmin() {
  try {
    return Boolean(JSON.parse(localStorage.getItem("me") || "{}").is_admin);
  } catch {
    return false;
  }
}

export default function VulnerabilitiesPage() {
  const [activeTab, setActiveTab] = useState("achados");
  const [items, setItems] = useState([]);
  const [counts, setCounts] = useState({});
  const [kindCounts, setKindCounts] = useState({});
  const [sourceCounts, setSourceCounts] = useState({});
  const [totalRows, setTotalRows] = useState(0);
  const [page, setPage] = useState(1);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [sevFilter, setSevFilter] = useState("todas");
  const [selected, setSelected] = useState(null);
  const [selectedIntel, setSelectedIntel] = useState(null);
  const [selectedAdjudication, setSelectedAdjudication] = useState(null);
  const [intelLoading, setIntelLoading] = useState(false);
  const [adjudicationLoading, setAdjudicationLoading] = useState(false);
  const [adjudicationAction, setAdjudicationAction] = useState("");
  const [adjudicationError, setAdjudicationError] = useState("");
  const [scanId, setScanId] = useState("");
  const [accessGroupId, setAccessGroupId] = useState("");
  const [kindFilter, setKindFilter] = useState("todos");
  const [sourceFilter, setSourceFilter] = useState("todos");

  useEffect(() => {
    setLoading(true);
    const params = { limit: PAGE_SIZE, offset: (page - 1) * PAGE_SIZE, sort: "severity" };
    if (sevFilter !== "todas") params.severity = sevFilter;
    if (kindFilter !== "todos") params.finding_kind = kindFilter;
    if (sourceFilter !== "todos") params.source_module = sourceFilter;
    if (scanId) params.scan_id = scanId;
    if (accessGroupId) params.access_group_id = accessGroupId;
    client
      .get("/api/findings/page", { params })
      .then(({ data }) => {
        setItems(Array.isArray(data?.items) ? data.items : []);
        setCounts(data?.severity_counts || {});
        setKindCounts(data?.kind_counts || {});
        setSourceCounts(data?.source_counts || {});
        setTotalRows(Number(data?.total || 0));
      })
      .catch(() => setError("Falha ao carregar achados."))
      .finally(() => setLoading(false));
  }, [sevFilter, kindFilter, sourceFilter, scanId, accessGroupId, page]);

  const total = useMemo(() => SEV_ORDER.reduce((a, k) => a + Number(counts[k] || 0), 0), [counts]);
  const actionableTotal = Number(kindCounts.validated_risk || 0) + Number(kindCounts.candidate_risk || 0);
  const observationTotal = Number(kindCounts.bas_observation || 0) + Number(kindCounts.observation || 0);
  const pageCount = Math.max(1, Math.ceil(totalRows / PAGE_SIZE));
  const safePage = Math.min(page, pageCount);
  const canAdjudicate = useMemo(() => currentUserIsAdmin(), []);

  useEffect(() => {
    setPage(1);
  }, [sevFilter, kindFilter, sourceFilter, scanId, accessGroupId]);

  useEffect(() => {
    if (!selected?.id) {
      setSelectedIntel(null);
      setSelectedAdjudication(null);
      return;
    }
    setIntelLoading(true);
    setSelectedIntel(null);
    client
      .get(`/api/findings/${selected.id}/intelligence`, { _skipToast: true })
      .then(({ data }) => setSelectedIntel(data || null))
      .catch(() => setSelectedIntel(null))
      .finally(() => setIntelLoading(false));
    setAdjudicationLoading(true);
    setAdjudicationError("");
    client
      .get(`/api/findings/${selected.id}/adjudication`, { _skipToast: true })
      .then(({ data }) => setSelectedAdjudication(data || null))
      .catch(() => {
        setSelectedAdjudication(null);
        setAdjudicationError("Adjudicação ainda não executada ou indisponível.");
      })
      .finally(() => setAdjudicationLoading(false));
  }, [selected?.id]);

  async function reAdjudicateFinding(refreshIntelligence = false) {
    if (!selected?.id || adjudicationAction) return;
    setAdjudicationAction(refreshIntelligence ? "intelligence" : "adjudicate");
    setAdjudicationError("");
    try {
      await client.post(`/api/findings/${selected.id}/adjudicate`, {
        force: true,
        refresh_intelligence: refreshIntelligence,
      });
      const { data } = await client.get(`/api/findings/${selected.id}/adjudication`, { _skipToast: true });
      setSelectedAdjudication(data || null);
      const verdict = data?.assessment?.answers?.does_it_make_sense?.verdict;
      if (verdict) setSelected((current) => current ? { ...current, verification_status: verdict } : current);
    } catch (err) {
      setAdjudicationError(err?.response?.data?.detail || "Não foi possível executar a reavaliação.");
    } finally {
      setAdjudicationAction("");
    }
  }

  if (loading) {
    return <main className="dash"><div className="content" style={{ padding: "32px 40px" }}><div className="dash-state"><div><div className="spin" /><p className="st-title">Carregando achados…</p></div></div></div></main>;
  }
  if (error) {
    return <main className="dash"><div className="content" style={{ padding: "32px 40px" }}><div className="dash-err">{error}</div></div></main>;
  }

  // ── Detalhe ───────────────────────────────────────────────────────────────
  if (selected) {
    const f = selected;
    const sev = String(f.severity || "info").toLowerCase();
    const target = f.target || f.domain || f.target_query || "—";
    const details = f.details || {};
    const proofPack = selectedIntel?.proof_pack || {};
    const experiment = selectedIntel?.experiment || {};
    const ledger = Array.isArray(selectedIntel?.confidence_ledger) ? selectedIntel.confidence_ledger : [];
    const contradictions = Array.isArray(selectedIntel?.contradictions) ? selectedIntel.contradictions : [];
    const apiObs = f.api_scan_observability || {};
    const apiObsLabel = apiObservationLabel(apiObs);
    const evidenceArtifacts = Array.isArray(f.evidence_artifacts) ? f.evidence_artifacts : [];
    const adjudication = selectedAdjudication?.current || null;
    const answers = selectedAdjudication?.assessment?.answers || {};
    const fpAnswer = answers.false_positive || {};
    const pocAnswer = answers.poc || {};
    const exploitAnswer = answers.public_exploit || {};
    const cveAnswer = answers.cve || {};
    const cvssAnswer = answers.cvss || {};
    const attackPathAnswer = answers.attack_path || {};
    const wireRows = Array.isArray(adjudication?.wires) ? adjudication.wires : [];
    const evidence = details.evidence || details.payload || details.command || details.proof || details.raw_output || details.request || "";
    const reproSteps = Array.isArray(details.repro_steps) ? details.repro_steps : (Array.isArray(details.reproduction_steps) ? details.reproduction_steps : []);
    const vrank = { hypothesis: 1, candidate: 2, confirmed: 3 };
    const reached = vrank[String(f.verification_status || "").toLowerCase()] || 0;
    const chain = [
      { label: "Descoberta", desc: `Identificado por ${f.tool || "ferramenta"}`, done: true },
      { label: "Hipótese", desc: "Sinal inicial registrado pelo agente", done: reached >= 1 },
      { label: "Candidato", desc: "Evidência parcial coletada", done: reached >= 2 },
      { label: "Confirmado", desc: "Evidência suficiente — risco validado", done: reached >= 3 },
    ];
    return (
      <main className="dash">
        <div className="content report-shell">
          <button className="vuln-back sk-mono" onClick={() => { setSelected(null); setSelectedIntel(null); setSelectedAdjudication(null); }} type="button">← voltar para a lista</button>
          <header className="vuln-detail-head">
            <div className="vuln-detail-badges">
              <span className={`sk-badge sk-badge--${sev}`}><span className={`sk-dot sk-dot--${sev}`} />{SEV_LABEL[sev]}</span>
              {f.verification_status && <span className="evidence-pill">{VSTATUS_LABEL[f.verification_status] || f.verification_status}</span>}
              {f.vuln_family_label && <span className="sk-badge sk-badge--neutral">{f.vuln_family_label}</span>}
              {f.finding_kind_label && <span className="sk-badge sk-badge--neutral">{f.finding_kind_label}</span>}
              {f.source_label && <span className="sk-badge sk-badge--neutral">{f.source_label}</span>}
            </div>
            <h1>{f.title}</h1>
            <p className="report-meta sk-mono">
              {target}{f.cve ? ` · ${f.cve}` : ""}{mitreStr(f.mitre_attack) !== "—" ? ` · MITRE ${mitreStr(f.mitre_attack)}` : ""}{f.tool ? ` · ${f.tool}` : ""} · scan #{f.scan_job_id}
            </p>
          </header>

          <div className="report-two-col">
            <div>
              <section className="report-section">
                <div className="sk-eyebrow">Descrição técnica</div>
                <p className="report-narrative">{f.cve_description || details.description || "Sem descrição técnica registrada para este achado."}</p>
              </section>

              <section className="report-section">
                <div className="sk-eyebrow">Observado</div>
                <p className="report-narrative">{f.observation_summary || "Sem resumo observado para este achado."}</p>
              </section>

              {apiObs.visible && (
                <section className="report-section">
                  <div className="sk-eyebrow">Observabilidade API</div>
                  <div className="vuln-experiment-grid">
                    <div><b>Executor</b><span>{apiObs.tested_via || f.tool || "—"}</span></div>
                    <div><b>Skill</b><span>{apiObs.api_skill_name || apiObs.api_skill_id || "—"}</span></div>
                    <div><b>Tipo</b><span>{apiObs.zap_scan_type || "—"}</span></div>
                    <div><b>URLs importadas</b><span className="sk-mono">{apiObs.imported_url_count ?? "—"}</span></div>
                    <div><b>Alertas brutos</b><span className="sk-mono">{apiObs.alert_count ?? "—"}</span></div>
                    <div><b>Swagger/OpenAPI</b><span className="sk-mono">{apiObs.openapi_url || "—"}</span></div>
                    <div><b>Artifact principal</b><span className="sk-mono">{apiObs.evidence_artifact_id || f.evidence_artifact_id || "—"}</span></div>
                  </div>
                  {apiObsLabel && <div className="vuln-code sk-mono" style={{ marginTop: 10 }}>{apiObsLabel}</div>}
                </section>
              )}

              <section className="report-section">
                <div style={{ display: "flex", justifyContent: "space-between", gap: 12, alignItems: "center", flexWrap: "wrap" }}>
                  <div className="sk-eyebrow">P21 · Adjudicação e retorno por wire</div>
                  {canAdjudicate ? (
                    <div style={{ display: "flex", gap: 8 }}>
                      <button type="button" className="btn-secondary" disabled={Boolean(adjudicationAction)} onClick={() => reAdjudicateFinding(false)}>
                        {adjudicationAction === "adjudicate" ? "Reavaliando…" : "Reavaliar"}
                      </button>
                      {f.cve && (
                        <button type="button" className="btn-secondary" disabled={Boolean(adjudicationAction)} onClick={() => reAdjudicateFinding(true)}>
                          {adjudicationAction === "intelligence" ? "Consultando…" : "Atualizar CVE/exploit"}
                        </button>
                      )}
                    </div>
                  ) : <span className="sk-mono" style={{ fontSize: 11, color: "var(--ink-muted)" }}>somente leitura</span>}
                </div>
                {adjudicationLoading ? (
                  <div className="report-empty">Carregando dossier e wires...</div>
                ) : adjudication ? (
                  <>
                    <div className="vuln-experiment-grid" style={{ marginTop: 10 }}>
                      <div><b>Veredito final</b><span>{VSTATUS_LABEL[adjudication.final_verdict] || adjudication.final_verdict}</span></div>
                      <div><b>Causa</b><span>{adjudication.reason_code || "—"}</span></div>
                      <div><b>Falso positivo?</b><span>{fpAnswer.answer === true ? "Sim" : fpAnswer.answer === false ? "Não" : "Ainda não decidido"}</span></div>
                      <div><b>Tipo da pendência/FP</b><span>{fpAnswer.cause || "—"}</span></div>
                      <div><b>Informação faltante</b><span>{(answers.missing_evidence || []).join(", ") || "nenhuma"}</span></div>
                      <div><b>Proposta da LLM</b><span>{adjudication.proposed_verdict || "não utilizada"}</span></div>
                    </div>
                    <div style={{ marginTop: 12 }}>
                      <b style={{ fontSize: 12 }}>Wires executados/pendentes</b>
                      {wireRows.length ? wireRows.map((wire) => (
                        <div key={wire.id} className="vuln-code sk-mono" style={{ marginTop: 6 }}>
                          #{wire.id} · {wire.action_id} · {wire.status} · {wire.tool_name || "ação interna"}<br />
                          {wire.target_ref}{wire.parameter_ref ? ` · parâmetro=${wire.parameter_ref}` : ""}
                          {wire.identity_key ? ` · identidade=${wire.identity_key}` : ""}
                          {wire.secondary_identity_key ? ` → ${wire.secondary_identity_key}` : ""}
                        </div>
                      )) : <div className="report-empty">Nenhum wire necessário ou materializado.</div>}
                    </div>
                  </>
                ) : <div className="report-empty">{adjudicationError || "Sem adjudicação persistida."}</div>}
                {adjudicationError && adjudication && <div className="dash-err" style={{ marginTop: 10 }}>{adjudicationError}</div>}
              </section>

              <section className="report-section">
                <div className="sk-eyebrow">Resposta técnica completa</div>
                <div className="vuln-experiment-grid">
                  <div><b>PoC</b><span>{pocAnswer.status || "—"}</span></div>
                  <div><b>Alvo exato</b><span className="sk-mono">{pocAnswer.exact_target || "—"}</span></div>
                  <div><b>CVE</b><span>{cveAnswer.exists ? `${cveAnswer.id} · ${cveAnswer.applicability}` : "Sem CVE aplicável"}</span></div>
                  <div><b>CVSS</b><span className="sk-mono">{cvssAnswer.score ?? "—"}{cvssAnswer.vector ? ` · ${cvssAnswer.vector}` : ""}</span></div>
                  <div><b>Exploit público</b><span>{exploitAnswer.status || "unknown"}</span></div>
                  <div><b>Attack path</b><span>{attackPathAnswer.mounted ? "Montado" : attackPathAnswer.needs_rebuild ? "Requer reconstrução" : "Não demonstrado"}</span></div>
                </div>
                {(pocAnswer.steps || []).length > 0 && (
                  <ol className="vuln-repro">{pocAnswer.steps.slice(0, 10).map((step, idx) => <li key={idx}>{String(step)}</li>)}</ol>
                )}
                {(exploitAnswer.urls || []).length > 0 && (
                  <div style={{ marginTop: 10 }}>
                    {(exploitAnswer.urls || []).map((url) => <div key={url}><a href={url} target="_blank" rel="noreferrer">{url}</a></div>)}
                  </div>
                )}
              </section>

              <section className="report-section">
                <div className="sk-eyebrow">Evidência reproduzível</div>
                {(experiment.target || f.url) && <div className="vuln-code sk-mono" style={{ marginBottom: evidence ? 8 : 0 }}>{experiment.target || f.url}</div>}
                {(proofPack.evidence || evidence) ? (
                  <pre className="vuln-evidence sk-mono">{String(proofPack.evidence || evidence).slice(0, 4000)}</pre>
                ) : (!f.url && (
                  <div className="report-empty">Sem evidência técnica capturada para este achado.</div>
                ))}
                {(proofPack.reproduction?.steps?.length > 0 || reproSteps.length > 0) && (
                  <ol className="vuln-repro">
                    {(proofPack.reproduction?.steps || reproSteps).slice(0, 8).map((s, i) => <li key={i}>{String(s)}</li>)}
                  </ol>
                )}
                {evidenceArtifacts.length > 0 && (
                  <div style={{ marginTop: 12 }}>
                    <b style={{ fontSize: 12 }}>Artifacts vinculados</b>
                    {evidenceArtifacts.slice(0, 8).map((artifact) => (
                      <div key={artifact.id} className="vuln-code sk-mono" style={{ marginTop: 6 }}>
                        #{artifact.id} · {artifact.tool_name || "ferramenta"} · {artifact.validation_status || "—"} · {artifact.artifact_type || "artifact"}
                        {artifact.workspace_path ? <><br />{artifact.workspace_path}</> : null}
                      </div>
                    ))}
                  </div>
                )}
              </section>

              <section className="report-section">
                <div className="sk-eyebrow">Experimento formal</div>
                {intelLoading ? (
                  <div className="report-empty">Carregando inteligência do achado...</div>
                ) : selectedIntel ? (
                  <div className="vuln-experiment-grid">
                    <div><b>Claim</b><span>{experiment.claim || "—"}</span></div>
                    <div><b>Resultado seguro esperado</b><span>{experiment.expected_secure_result || "—"}</span></div>
                    <div><b>Resultado observado</b><span>{experiment.observed_result || "—"}</span></div>
                    <div><b>Veredito</b><span>{experiment.verdict || "—"} · confiança final {selectedIntel.final_confidence ?? "—"}%</span></div>
                  </div>
                ) : (
                  <div className="report-empty">Inteligência formal indisponível para este achado.</div>
                )}
              </section>

              <section className="sk-panel vuln-chain-panel">
                <div className="sk-eyebrow">Cadeia de validação</div>
                <div className="vuln-chain">
                  {chain.map((step, i) => (
                    <div key={step.label} className={`vuln-chain-step${step.done ? " done" : ""}`}>
                      <span className="vuln-chain-dot" />
                      {i < chain.length - 1 && <span className="vuln-chain-line" />}
                      <div>
                        <b>{step.label}</b>
                        <span>{step.desc}</span>
                      </div>
                    </div>
                  ))}
                </div>
              </section>
            </div>
            <div>
              <section className="sk-panel vuln-score-panel">
                <div className="sk-eyebrow">Pontuação</div>
                <div className="vuln-score-row"><span>CVSS</span><b className="sk-mono">{f.cvss ? Number(f.cvss).toFixed(1) : "—"}</b></div>
                <div className="vuln-score-row"><span>Confiança</span><b className="sk-mono">{f.confidence_score != null ? `${f.confidence_score}%` : "—"}</b></div>
                <div className="vuln-score-row"><span>Risk score</span><b className="sk-mono">{f.risk_score ?? "—"}</b></div>
                <div className="vuln-score-row"><span>Família</span><b>{f.vuln_family_label || "—"}</b></div>
                <div className="vuln-score-row"><span>Tipo</span><b>{f.finding_kind_label || "—"}</b></div>
                <div className="vuln-score-row"><span>Origem</span><b>{f.source_label || f.tool || "—"}</b></div>
                <div className="vuln-score-row"><span>Evidência</span><b>{VSTATUS_LABEL[f.verification_status] || f.verification_status || "—"}</b></div>
              </section>
              {f.recommendation && (
                <section className="sk-panel vuln-reco-panel">
                  <div className="sk-eyebrow">Recomendação</div>
                  <p className="report-narrative" style={{ fontSize: 12.5 }}>{f.recommendation}</p>
                </section>
              )}
              <section className="sk-panel vuln-reco-panel">
                <div className="sk-eyebrow">Confidence ledger</div>
                {intelLoading ? (
                  <div className="report-empty">Carregando ledger...</div>
                ) : ledger.length ? (
                  <div className="vuln-ledger">
                    {ledger.map((entry, idx) => (
                      <div key={`${entry.signal}-${idx}`} className={Number(entry.delta || 0) >= 0 ? "pos" : "neg"}>
                        <b className="sk-mono">{Number(entry.delta || 0) >= 0 ? "+" : ""}{entry.delta}</b>
                        <span>{entry.reason}</span>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="report-empty">Sem ledger calculado.</div>
                )}
              </section>
              {contradictions.length > 0 && (
                <section className="sk-panel vuln-reco-panel">
                  <div className="sk-eyebrow">Contradições</div>
                  <div className="vuln-contradictions">
                    {contradictions.map((item) => (
                      <div key={item.type}>
                        <b>{item.message}</b>
                        <span>{item.recommended_action}</span>
                      </div>
                    ))}
                  </div>
                </section>
              )}
            </div>
          </div>
        </div>
      </main>
    );
  }

  // ── Por Subdomínio ────────────────────────────────────────────────────────
  if (activeTab === "subdominios") {
    return (
      <div style={{ display: "flex", flexDirection: "column", height: "100%" }}>
        <div style={{ padding: "24px 40px 0", background: "var(--surface)", borderBottom: "1px solid var(--line)" }}>
          <div className="sk-eyebrow" style={{ marginBottom: 4 }}>Finds / Achados</div>
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 12, flexWrap: "wrap" }}>
            <div className="vuln-tabs">
              <button type="button" className="vuln-tab" onClick={() => setActiveTab("achados")}>Lista de achados</button>
              <button type="button" className="vuln-tab active">Por Subdomínio</button>
            </div>
            <div style={{ paddingBottom: 8 }}>
              <div className="cockpit-actions">
                <CompanyScopeSelect value={accessGroupId} onChange={(value) => { setAccessGroupId(value); setScanId(""); }} />
                <ScanSelect value={scanId} onChange={setScanId} accessGroupId={accessGroupId} />
              </div>
            </div>
          </div>
        </div>
        <DomainsPage embedded scanId={scanId} accessGroupId={accessGroupId} />
      </div>
    );
  }

  // ── Lista ─────────────────────────────────────────────────────────────────
  return (
    <main className="dash">
      <div className="content cockpit-shell">
        <section className="cockpit-page-head" style={{ paddingBottom: 0 }}>
          <div>
            <div className="sk-eyebrow">Finds / Achados</div>
            <h1>Achados do ambiente</h1>
            <p className="cockpit-sub">{total} achado(s) · {totalRows} no filtro atual · {actionableTotal} risco(s) · {observationTotal} observação(ões)</p>
          </div>
          <div className="cockpit-actions">
            <CompanyScopeSelect value={accessGroupId} onChange={(value) => { setAccessGroupId(value); setScanId(""); }} />
            <ScanSelect value={scanId} onChange={setScanId} accessGroupId={accessGroupId} />
          </div>
        </section>

        <div className="vuln-tabs" style={{ marginBottom: 16 }}>
          <button type="button" className="vuln-tab active">Lista de achados</button>
          <button type="button" className="vuln-tab" onClick={() => setActiveTab("subdominios")}>Por Subdomínio</button>
        </div>

        <section style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))", gap: 10, marginBottom: 16 }}>
          <div className="sk-panel" style={{ padding: 14 }}><div className="sk-eyebrow">Total no filtro</div><strong className="sk-mono" style={{ fontSize: 24 }}>{totalRows}</strong></div>
          <div className="sk-panel" style={{ padding: 14 }}><div className="sk-eyebrow">Riscos</div><strong className="sk-mono" style={{ fontSize: 24 }}>{actionableTotal}</strong></div>
          <div className="sk-panel" style={{ padding: 14 }}><div className="sk-eyebrow">Observações</div><strong className="sk-mono" style={{ fontSize: 24 }}>{observationTotal}</strong></div>
          <div className="sk-panel" style={{ padding: 14 }}><div className="sk-eyebrow">BAS</div><strong className="sk-mono" style={{ fontSize: 24 }}>{Number(sourceCounts.bas || 0)}</strong></div>
        </section>

        <section className="surface-filter-strip">
          <button className={`surface-chip${sevFilter === "todas" ? " active" : ""}`} onClick={() => setSevFilter("todas")} type="button">Todas</button>
          {SEV_ORDER.map((s) => (
            <button key={s} className={`surface-chip${sevFilter === s ? " active" : ""}`} onClick={() => setSevFilter(s)} type="button">
              <span className={`sk-dot sk-dot--${s}`} style={{ marginRight: 6 }} />{SEV_LABEL[s]} {Number(counts[s] || 0)}
            </button>
          ))}
          <span className="surface-count-note">{items.length} de {totalRows} no filtro atual</span>
        </section>

        <section className="surface-filter-strip">
          <button className={`surface-chip${kindFilter === "todos" ? " active" : ""}`} onClick={() => setKindFilter("todos")} type="button">Todos os tipos</button>
          {KIND_ORDER.map((kind) => (
            <button key={kind} className={`surface-chip${kindFilter === kind ? " active" : ""}`} onClick={() => setKindFilter(kind)} type="button">
              {KIND_LABEL[kind]} {Number(kindCounts[kind] || 0)}
            </button>
          ))}
        </section>

        <section className="surface-filter-strip">
          <button className={`surface-chip${sourceFilter === "todos" ? " active" : ""}`} onClick={() => setSourceFilter("todos")} type="button">Todas as origens</button>
          {SOURCE_ORDER.map((source) => (
            <button key={source} className={`surface-chip${sourceFilter === source ? " active" : ""}`} onClick={() => setSourceFilter(source)} type="button">
              {SOURCE_LABEL[source]} {Number(sourceCounts[source] || 0)}
            </button>
          ))}
        </section>

        <section className="sk-panel surface-table-panel">
          <div className="attack-table-wrap">
            <table className="attack-table">
              <thead>
                <tr><th>Severidade</th><th>Achado</th><th>Tipo</th><th>Origem</th><th>Alvo</th><th>Observado</th><th>Evidência</th></tr>
              </thead>
              <tbody>
                {items.length === 0 && <tr><td colSpan={7}>Nenhum achado no filtro atual.</td></tr>}
                {items.map((f) => {
                  const sev = String(f.severity || "info").toLowerCase();
                  const apiObs = f.api_scan_observability || {};
                  const apiLabel = apiObservationLabel(apiObs);
                  return (
                    <tr key={f.id} onClick={() => setSelected(f)} style={{ cursor: "pointer" }}>
                      <td><span className={`sk-badge sk-badge--${sev}`}><span className={`sk-dot sk-dot--${sev}`} />{SEV_LABEL[sev]}</span></td>
                      <td>
                        <b>{f.title}</b>
                        <small style={{ display: "block", color: "var(--ink-muted)" }}>{f.vuln_family_label || f.tool || ""}</small>
                        {apiLabel && <small className="sk-mono" style={{ display: "block", color: "var(--brand-700)", marginTop: 3 }}>{apiLabel}</small>}
                      </td>
                      <td>{f.finding_kind_label || "Achado"}</td>
                      <td>
                        <span>{f.source_label || f.tool || "—"}</span>
                        {f.tool && <small className="sk-mono" style={{ display: "block", color: "var(--ink-muted)" }}>{f.tool}</small>}
                      </td>
                      <td className="sk-mono">{f.target || f.domain || f.target_query || "—"}</td>
                      <td className="sk-mono" style={{ maxWidth: 420 }}>{f.observation_summary || f.cve || mitreStr(f.mitre_attack)}</td>
                      <td>
                        <span className="evidence-pill">{VSTATUS_LABEL[f.verification_status] || f.verification_status || "—"}</span>
                        {(f.evidence_artifacts?.length || f.evidence_artifact_id) ? <small className="sk-mono" style={{ display: "block", color: "var(--ink-muted)", marginTop: 4 }}>artifact #{f.evidence_artifacts?.[0]?.id || f.evidence_artifact_id}</small> : null}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
          {totalRows > PAGE_SIZE && (
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 12, padding: "12px 14px", borderTop: "1px solid var(--line)" }}>
              <span className="sk-mono" style={{ fontSize: 12, color: "var(--ink-muted)" }}>Página {safePage} de {pageCount}</span>
              <div style={{ display: "flex", gap: 8 }}>
                <button className="sk-btn-ghost" type="button" disabled={safePage <= 1} onClick={() => setPage((p) => Math.max(1, p - 1))}>Anterior</button>
                <button className="sk-btn-ghost" type="button" disabled={safePage >= pageCount} onClick={() => setPage((p) => Math.min(pageCount, p + 1))}>Próxima</button>
              </div>
            </div>
          )}
        </section>
      </div>
    </main>
  );
}
