import { useEffect, useMemo, useState } from "react";
import client from "../api/client";

const statusLabel = {
  pending_review: "Pendente",
  accepted: "Aceito",
  rejected: "Rejeitado",
};

const statusClass = {
  pending_review: "ds-badge ds-badge--medium",
  accepted: "ds-badge ds-badge--low",
  rejected: "ds-badge ds-badge--critical",
};

function formatDate(value) {
  if (!value) return "-";
  try {
    return new Date(value).toLocaleString("pt-BR", { timeZone: "America/Sao_Paulo" });
  } catch {
    return "-";
  }
}

function Counter({ label, value }) {
  return (
    <div className="rounded-lg border px-4 py-3" style={{ borderColor: "var(--line)", background: "var(--surface-soft)" }}>
      <p className="text-xs font-semibold uppercase tracking-wider" style={{ color: "var(--ink-muted)" }}>{label}</p>
      <p className="mt-1 text-2xl font-semibold" style={{ color: "var(--ink)" }}>{value ?? 0}</p>
    </div>
  );
}

function LearningIndex({ index, onLearn }) {
  const items = index?.items || [];
  if (!items.length) return null;
  return (
    <section className="panel p-5">
      <div className="flex flex-col gap-2 lg:flex-row lg:items-center lg:justify-between">
        <div>
          <p className="ds-eyebrow">Índice por ataque / skill</p>
          <h2 className="mt-1 text-lg font-semibold" style={{ color: "var(--ink)" }}>
            Cobertura de aprendizado para análise de vulnerabilidade
          </h2>
        </div>
        <div className="rounded-lg border px-4 py-2 text-sm font-semibold" style={{ borderColor: "var(--line)", background: "var(--surface-soft)", color: "var(--ink)" }}>
          {index.families_total || items.length} famílias
        </div>
      </div>
      <div className="mt-4 grid gap-3 md:grid-cols-2 xl:grid-cols-3">
        {items.map((item) => {
          const trainings = Number(item.total_learnings || 0);
          const accepted = Number(item.accepted_learnings || 0);
          const pending = Number(item.pending_learnings || 0);
          const target = Math.max(1, Number(item.target_techniques || 1));
          const learningPct = Math.min(100, Math.round((accepted / target) * 100));
          return (
            <div key={item.id} className="rounded-lg border p-4" style={{ borderColor: "var(--line)", background: "#fff" }}>
              <div className="flex items-start justify-between gap-3">
                <div>
                  <h3 className="text-sm font-semibold" style={{ color: "var(--ink)" }}>{item.label}</h3>
                  <p className="mt-1 text-2xl font-bold" style={{ color: "var(--brand-700)" }}>
                    {trainings}
                    <span className="ml-2 text-xs font-normal" style={{ color: "var(--ink-muted)" }}>
                      treinamento{trainings === 1 ? "" : "s"} recebido{trainings === 1 ? "" : "s"}
                    </span>
                  </p>
                  <p className="mt-1 text-[11px]" style={{ color: "var(--ink-muted)" }}>
                    {accepted} aceito{accepted === 1 ? "" : "s"} · {pending} pendente{pending === 1 ? "" : "s"} · meta {target}
                  </p>
                </div>
                <button className="btn-secondary" type="button" onClick={() => onLearn?.(item.id)}>
                  Aprender
                </button>
              </div>
              <div className="mt-3 h-2 w-full overflow-hidden rounded-full" style={{ background: "var(--surface-soft)" }}>
                <div
                  className="h-full rounded-full"
                  style={{
                    width: `${learningPct}%`,
                    background: "linear-gradient(90deg, var(--brand-500), var(--brand-700))",
                  }}
                />
              </div>
              <p className="mt-1 text-[10px]" style={{ color: "var(--ink-muted)" }}>
                Aprendizado da skill: {learningPct}%
              </p>
              <p className="mt-3 text-xs leading-5" style={{ color: "var(--ink-soft)" }}>
                Skills: {(item.skills || []).join(", ") || "-"}
              </p>
              <p className="mt-2 text-xs leading-5" style={{ color: "var(--ink-muted)" }}>
                Fases: {(item.phases || []).join(", ") || "-"}
              </p>
              <p className="mt-2 text-xs leading-5" style={{ color: "var(--ink-muted)" }}>
                Ferramentas: {(item.tools || []).join(", ") || "-"}
              </p>
            </div>
          );
        })}
      </div>
    </section>
  );
}

function PhaseKnowledgeIndex({ index, onLearn }) {
  const items = index?.items || [];
  if (!items.length) return null;
  return (
    <section className="panel p-5">
      <div className="flex flex-col gap-2 lg:flex-row lg:items-center lg:justify-between">
        <div>
          <p className="ds-eyebrow">Conhecimento por fase P01-P22</p>
          <h2 className="mt-1 text-lg font-semibold" style={{ color: "var(--ink)" }}>
            Missão, ferramentas e técnicas por momento da Cyber Kill Chain
          </h2>
        </div>
        <div className="rounded-lg border px-4 py-2 text-sm font-semibold" style={{ borderColor: "var(--line)", background: "var(--surface-soft)", color: "var(--ink)" }}>
          {index.phases_with_accepted_learning || 0}/{index.phases_total || items.length} fases com aceite
        </div>
      </div>
      <div className="mt-4 grid gap-3 md:grid-cols-2 xl:grid-cols-3">
        {items.map((item) => (
          <div key={item.id} className="rounded-lg border p-4" style={{ borderColor: "var(--line)", background: "#fff" }}>
            <div className="flex items-start justify-between gap-3">
              <div>
                <p className="text-xs font-semibold" style={{ color: "var(--brand-600)" }}>{item.id}</p>
                <h3 className="mt-1 text-sm font-semibold" style={{ color: "var(--ink)" }}>{item.title}</h3>
                <p className="mt-1 text-xs" style={{ color: "var(--ink-muted)" }}>{item.node}</p>
              </div>
              <button className="btn-secondary" type="button" onClick={() => onLearn?.(item.id)}>
                Ensinar fase
              </button>
            </div>
            <div className="mt-3 grid grid-cols-3 gap-2 text-center text-xs">
              <div className="rounded-lg border px-2 py-2" style={{ borderColor: "var(--line)", background: "var(--surface-soft)" }}>
                <b style={{ color: "var(--ink)" }}>{item.accepted_learnings || 0}</b>
                <span className="block" style={{ color: "var(--ink-muted)" }}>aceitos</span>
              </div>
              <div className="rounded-lg border px-2 py-2" style={{ borderColor: "var(--line)", background: "var(--surface-soft)" }}>
                <b style={{ color: "var(--ink)" }}>{item.pending_learnings || 0}</b>
                <span className="block" style={{ color: "var(--ink-muted)" }}>pendentes</span>
              </div>
              <div className="rounded-lg border px-2 py-2" style={{ borderColor: "var(--line)", background: "var(--surface-soft)" }}>
                <b style={{ color: "var(--ink)" }}>{item.techniques_accepted || 0}</b>
                <span className="block" style={{ color: "var(--ink-muted)" }}>técnicas</span>
              </div>
            </div>
            <p className="mt-3 text-xs leading-5" style={{ color: "var(--ink-soft)" }}>
              Skills: {(item.skills || []).join(", ") || "-"}
            </p>
            <p className="mt-2 text-xs leading-5" style={{ color: "var(--ink-muted)" }}>
              Workers: {(item.worker_groups || []).join(", ") || "-"}
            </p>
            <p className="mt-2 text-xs leading-5" style={{ color: "var(--ink-muted)" }}>
              Ferramentas: {(item.tools || []).join(", ") || "-"}
            </p>
          </div>
        ))}
      </div>
    </section>
  );
}

function TechniqueList({ techniques }) {
  if (!techniques?.length) {
    return <p className="text-sm" style={{ color: "var(--ink-muted)" }}>Nenhuma técnica detalhada.</p>;
  }
  return (
    <div className="space-y-2">
      {techniques.map((technique, idx) => (
        <div key={`${technique.name || "tech"}-${idx}`} className="rounded-lg border p-3" style={{ borderColor: "var(--line)", background: "#fff" }}>
          <div className="flex flex-wrap items-center justify-between gap-2">
            <h4 className="text-sm font-semibold" style={{ color: "var(--ink)" }}>{technique.name || `Técnica ${idx + 1}`}</h4>
            <div className="flex flex-wrap gap-1">
              {(technique.affected_phases || []).slice(0, 5).map((phase) => (
                <span key={phase} className="ds-badge" style={{ borderColor: "var(--line)", background: "var(--surface-soft)" }}>{phase}</span>
              ))}
            </div>
          </div>
          {technique.objective && <p className="mt-2 text-sm" style={{ color: "var(--ink-soft)" }}>{technique.objective}</p>}
          {technique.prompt_instruction && (
            <p className="mt-2 rounded-lg border px-3 py-2 text-xs" style={{ borderColor: "var(--line)", background: "var(--surface-soft)", color: "var(--ink-soft)" }}>
              {technique.prompt_instruction}
            </p>
          )}
        </div>
      ))}
    </div>
  );
}

function WorkerKnowledgeList({ items }) {
  if (!items?.length) {
    return <p className="text-sm" style={{ color: "var(--ink-muted)" }}>Nenhum worker vinculado.</p>;
  }
  return (
    <div className="grid gap-3 lg:grid-cols-2">
      {items.map((item) => (
        <div key={item.worker_group} className="rounded-lg border p-3" style={{ borderColor: "var(--line)", background: "#fff" }}>
          <div className="flex flex-wrap items-center justify-between gap-2">
            <h4 className="text-sm font-semibold" style={{ color: "var(--ink)" }}>{item.worker_group}</h4>
            <span className="ds-badge" style={{ borderColor: "var(--line)", background: "var(--surface-soft)" }}>
              {(item.phases || []).join(", ") || "-"}
            </span>
          </div>
          <p className="mt-2 text-xs leading-5" style={{ color: "var(--ink-soft)" }}>{item.mission || "-"}</p>
          <p className="mt-2 text-xs leading-5" style={{ color: "var(--ink-muted)" }}>
            Ferramentas: {(item.tools || []).join(", ") || "-"}
          </p>
          <p className="mt-1 text-xs leading-5" style={{ color: "var(--ink-muted)" }}>
            Técnicas: {(item.techniques || []).join(", ") || "-"}
          </p>
        </div>
      ))}
    </div>
  );
}

function ManualLearningForm({
  attackOptions,
  phaseOptions,
  attackId,
  setAttackId,
  phaseId,
  setPhaseId,
  instruction,
  setInstruction,
  urlsText,
  setUrlsText,
  onSubmit,
  busy,
}) {
  return (
    <section className="panel p-5">
      <div className="flex flex-col gap-1">
        <p className="ds-eyebrow">Ensinar técnica manualmente</p>
        <h2 className="text-lg font-semibold" style={{ color: "var(--ink)" }}>Aprendizado por skill e fase P01-P22</h2>
      </div>
      <div className="mt-4 grid gap-4 lg:grid-cols-2">
        <div>
          <label className="text-xs font-semibold uppercase tracking-wider" style={{ color: "var(--ink-muted)" }}>Ataque / skill</label>
          <select
            value={attackId}
            onChange={(event) => setAttackId(event.target.value)}
            className="mt-2 w-full rounded-lg border px-3 py-2 text-sm"
            style={{ borderColor: "var(--line)", color: "var(--ink)" }}
          >
            {attackOptions.map((item) => (
              <option key={item.id} value={item.id}>{item.label}</option>
            ))}
          </select>
        </div>
        <div>
          <label className="text-xs font-semibold uppercase tracking-wider" style={{ color: "var(--ink-muted)" }}>Fase Cyber Kill Chain</label>
          <select
            value={phaseId}
            onChange={(event) => setPhaseId(event.target.value)}
            className="mt-2 w-full rounded-lg border px-3 py-2 text-sm"
            style={{ borderColor: "var(--line)", color: "var(--ink)" }}
          >
            {phaseOptions.map((item) => (
              <option key={item.id} value={item.id}>{item.id} - {item.title}</option>
            ))}
          </select>
        </div>
      </div>
      <div className="mt-4">
        <label className="text-xs font-semibold uppercase tracking-wider" style={{ color: "var(--ink-muted)" }}>Como a técnica deve ser reproduzida</label>
        <textarea
          value={instruction}
          onChange={(event) => setInstruction(event.target.value)}
          className="mt-2 min-h-36 w-full rounded-lg border px-3 py-2 text-sm"
          style={{ borderColor: "var(--line)" }}
          placeholder="Descreva precondições, sinais, passos seguros, evidências esperadas, impacto e remediação. A LLM transformará isso em proposta para aceite."
        />
      </div>
      <div className="mt-4 grid gap-4 lg:grid-cols-[1fr_auto] lg:items-end">
        <div>
          <label className="text-xs font-semibold uppercase tracking-wider" style={{ color: "var(--ink-muted)" }}>URLs de apoio</label>
          <textarea
            value={urlsText}
            onChange={(event) => setUrlsText(event.target.value)}
            className="mt-2 min-h-20 w-full rounded-lg border px-3 py-2 text-sm"
            style={{ borderColor: "var(--line)" }}
            placeholder="Opcional: https://hackerone.com/reports/...; https://github.com/..."
          />
        </div>
        <button type="button" className="btn-primary" onClick={onSubmit} disabled={busy || !attackId || !phaseId || instruction.trim().length < 20}>
          {busy ? "Analisando..." : "Analisar e aprender"}
        </button>
      </div>
      <p className="mt-3 text-xs" style={{ color: "var(--ink-muted)" }}>
        A proposta aparece em revisão. Só após o aceite ela entra no conhecimento da fase e do worker.
      </p>
    </section>
  );
}

function ReviewPanel({ item, notes, setNotes, onAccept, onReject, onDelete, busy }) {
  if (!item) return null;
  return (
    <section className="panel p-5">
      <div className="flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between">
        <div>
          <p className="ds-eyebrow">Revisão do aprendizado</p>
          <h2 className="mt-1 text-xl font-semibold" style={{ color: "var(--ink)" }}>{item.title || "Aprendizado sem título"}</h2>
          <div className="mt-2 flex flex-wrap gap-2">
            <span className={statusClass[item.status] || "ds-badge"}>{statusLabel[item.status] || item.status}</span>
            <span className="ds-badge" style={{ borderColor: "var(--line)", background: "var(--surface-soft)" }}>
              {item.technique_count || 0} técnicas
            </span>
            {item.vulnerability_type && (
              <span className="ds-badge" style={{ borderColor: "var(--line)", background: "var(--surface-soft)" }}>{item.vulnerability_type}</span>
            )}
          </div>
        </div>
        <div className="flex flex-wrap gap-2">
          <button className="btn-secondary" type="button" onClick={onDelete} disabled={busy}>
            Retirar aprendizado
          </button>
          <button className="btn-secondary" type="button" onClick={onReject} disabled={busy || item.status === "rejected"}>
            Rejeitar
          </button>
          <button className="btn-primary" type="button" onClick={onAccept} disabled={busy || item.status === "accepted"}>
            Aceitar aprendizado
          </button>
        </div>
      </div>

      <div className="mt-5 grid gap-4 lg:grid-cols-[1.25fr_0.9fr_0.9fr]">
        <div>
          <label className="text-xs font-semibold uppercase tracking-wider" style={{ color: "var(--ink-muted)" }}>Steps to reproduce</label>
          <textarea
            readOnly
            value={item.steps_to_reproduce || ""}
            className="mt-2 min-h-56 w-full rounded-lg border px-3 py-2 text-sm font-mono"
            style={{ borderColor: "var(--line)", color: "var(--ink)", background: "var(--surface-soft)" }}
          />
        </div>
        <div>
          <label className="text-xs font-semibold uppercase tracking-wider" style={{ color: "var(--ink-muted)" }}>Impact</label>
          <textarea
            readOnly
            value={item.impact || ""}
            className="mt-2 min-h-56 w-full rounded-lg border px-3 py-2 text-sm"
            style={{ borderColor: "var(--line)", color: "var(--ink)", background: "var(--surface-soft)" }}
          />
        </div>
        <div>
          <label className="text-xs font-semibold uppercase tracking-wider" style={{ color: "var(--ink-muted)" }}>Remediation</label>
          <textarea
            readOnly
            value={item.remediation || ""}
            className="mt-2 min-h-56 w-full rounded-lg border px-3 py-2 text-sm"
            style={{ borderColor: "var(--line)", color: "var(--ink)", background: "var(--surface-soft)" }}
          />
        </div>
      </div>

      <div className="mt-5 grid gap-4 lg:grid-cols-2">
        <div>
          <label className="text-xs font-semibold uppercase tracking-wider" style={{ color: "var(--ink-muted)" }}>Missão aprendida</label>
          <textarea readOnly value={item.learned_mission || ""} className="mt-2 min-h-48 w-full rounded-lg border px-3 py-2 text-sm" style={{ borderColor: "var(--line)" }} />
        </div>
        <div>
          <label className="text-xs font-semibold uppercase tracking-wider" style={{ color: "var(--ink-muted)" }}>Prompt aprendido</label>
          <textarea readOnly value={item.learned_prompt || ""} className="mt-2 min-h-48 w-full rounded-lg border px-3 py-2 text-sm font-mono" style={{ borderColor: "var(--line)" }} />
        </div>
      </div>

      <div className="mt-4">
        <label className="text-xs font-semibold uppercase tracking-wider" style={{ color: "var(--ink-muted)" }}>Notas da revisão</label>
        <textarea
          value={notes}
          onChange={(event) => setNotes(event.target.value)}
          className="mt-2 min-h-20 w-full rounded-lg border px-3 py-2 text-sm"
          placeholder="Critério de aceite, ajuste esperado ou motivo da rejeição."
        />
      </div>

      <div className="mt-5">
        <h3 className="text-sm font-semibold" style={{ color: "var(--ink)" }}>Técnicas recebidas</h3>
        <div className="mt-3">
          <TechniqueList techniques={item.learned_techniques || []} />
        </div>
      </div>

      <div className="mt-5">
        <h3 className="text-sm font-semibold" style={{ color: "var(--ink)" }}>Conhecimento por worker/agente</h3>
        <div className="mt-3">
          <WorkerKnowledgeList items={item.worker_knowledge || []} />
        </div>
      </div>
    </section>
  );
}

export default function LearningPage() {
  const [urlsText, setUrlsText] = useState("");
  const [summary, setSummary] = useState({});
  const [skillIndex, setSkillIndex] = useState(null);
  const [phaseIndex, setPhaseIndex] = useState(null);
  const [missionPrompt, setMissionPrompt] = useState("");
  const [items, setItems] = useState([]);
  const [reviewItem, setReviewItem] = useState(null);
  const [notes, setNotes] = useState("");
  const [manualAttackId, setManualAttackId] = useState("");
  const [manualPhaseId, setManualPhaseId] = useState("");
  const [manualInstruction, setManualInstruction] = useState("");
  const [manualUrlsText, setManualUrlsText] = useState("");
  const [selectedIds, setSelectedIds] = useState([]);
  const [loading, setLoading] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [manualSubmitting, setManualSubmitting] = useState(false);
  const [seeding, setSeeding] = useState(false);
  const [crawlerRunning, setCrawlerRunning] = useState(false);
  const [reviewing, setReviewing] = useState(false);
  const [generatingPrompt, setGeneratingPrompt] = useState(false);
  const [error, setError] = useState("");
  const [taskStatus, setTaskStatus] = useState("");

  const parsedUrlCount = useMemo(
    () => urlsText.split(/[;\s]+/).map((item) => item.trim()).filter(Boolean).length,
    [urlsText],
  );

  const pendingItemIds = useMemo(
    () => items.filter((item) => item.status === "pending_review").map((item) => item.id),
    [items],
  );

  const allPendingSelected = pendingItemIds.length > 0 && pendingItemIds.every((id) => selectedIds.includes(id));

  const attackOptions = useMemo(() => skillIndex?.items || [], [skillIndex]);
  const phaseOptions = useMemo(() => phaseIndex?.items || [], [phaseIndex]);

  const load = async () => {
    setLoading(true);
    setError("");
    try {
      const [{ data }, indexResponse, phaseResponse] = await Promise.all([
        client.get("/api/learning/vulnerabilities"),
        client.get("/api/learning/vulnerabilities/attack-index").catch(() => ({ data: null })),
        client.get("/api/learning/vulnerabilities/phase-index").catch(() => ({ data: null })),
      ]);
      const nextItems = data.items || [];
      setSummary(data.summary || {});
      if (indexResponse?.data) setSkillIndex(indexResponse.data);
      if (phaseResponse?.data) setPhaseIndex(phaseResponse.data);
      setItems(nextItems);
      if (!manualAttackId && indexResponse?.data?.items?.length) setManualAttackId(indexResponse.data.items[0].id);
      if (!manualPhaseId && phaseResponse?.data?.items?.length) setManualPhaseId(phaseResponse.data.items[0].id);
      setSelectedIds((current) => current.filter((id) => nextItems.some((item) => item.id === id && item.status === "pending_review")));
      if (!reviewItem) {
        const pending = nextItems.find((item) => item.status === "pending_review");
        setReviewItem(pending || nextItems[0] || null);
      }
    } catch (err) {
      setError(err?.response?.data?.detail || "Falha ao carregar aprendizados.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
  }, []);

  const wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

  const pollLearningTask = async (taskId) => {
    for (let attempt = 0; attempt < 45; attempt += 1) {
      await wait(2000);
      const { data } = await client.get(`/api/learning/vulnerabilities/task/${taskId}`);
      const status = data.status || "PENDING";
      setSummary(data.summary || {});
      setTaskStatus(status === "PENDING" || status === "STARTED" ? "Processando aprendizado..." : "");

      if (status === "SUCCESS") {
        if (data.result?.success && data.result?.item) {
          setReviewItem(data.result.item);
          setNotes("");
          setUrlsText("");
          await load();
          return;
        }
        if (data.result?.success) {
          await load();
          setTaskStatus(
            `Crawler finalizado: ${data.result.created || 0} criados, ${data.result.purged || 0} removidos, ${data.result.mcp_ingested || 0} indexados no RAG.`,
          );
          return data.result;
        }
        throw new Error(data.result?.error || "A task terminou sem criar aprendizado.");
      }
      if (status === "FAILURE" || status === "REVOKED") {
        throw new Error(data.result?.error || "A task de aprendizado falhou.");
      }
    }
    throw new Error("Aprendizado ainda em processamento. Atualize a página em alguns segundos.");
  };

  const submit = async () => {
    setSubmitting(true);
    setError("");
    setTaskStatus("");
    try {
      const { data } = await client.post("/api/learning/vulnerabilities", { urls_text: urlsText });
      if (data.task_id) {
        setTaskStatus(data.message || "Processando aprendizado...");
        await pollLearningTask(data.task_id);
      } else {
        setSummary(data.summary || {});
        setReviewItem(data.item || null);
        setNotes("");
        setUrlsText("");
        const created = Number(data.items_count || 0);
        if (created > 1) {
          // Granular catalog ingest (e.g. juice-shop walkthrough → 14 rows).
          // Tell the operator there are N pending learnings to review.
          setTaskStatus(
            `${created} aprendizados criados em pending_review. Cada técnica pode ser aceita/rejeitada individualmente abaixo.`,
          );
        } else if (data.novelty?.summary) {
          setTaskStatus(data.novelty.summary);
        }
        await load();
      }
    } catch (err) {
      const detail = err?.response?.data?.detail;
      if (err?.response?.status === 409 && detail?.reason === "already_learned") {
        const matchTitles = (detail.matches || [])
          .map((m) => `#${m.existing_learning_id} ${m.existing_title || ""}`.trim())
          .filter(Boolean)
          .join(", ");
        setError(
          `URL já aprendida anteriormente: ${matchTitles}. Marque "force" para reaprender.`,
        );
      } else if (typeof detail === "object") {
        setError(detail.message || JSON.stringify(detail));
      } else {
        setError(detail || err?.message || "Falha ao enviar URLs para aprendizagem.");
      }
    } finally {
      setTaskStatus("");
      setSubmitting(false);
    }
  };

  const submitManualLearning = async () => {
    setManualSubmitting(true);
    setError("");
    setTaskStatus("");
    try {
      const { data } = await client.post("/api/learning/vulnerabilities/manual-analyze", {
        attack_id: manualAttackId,
        phase_id: manualPhaseId,
        instruction_text: manualInstruction,
        urls_text: manualUrlsText,
      });
      setSummary(data.summary || {});
      setReviewItem(data.item || null);
      setNotes("");
      setManualInstruction("");
      setManualUrlsText("");
      setTaskStatus(data.message || "Proposta criada para revisão.");
      await load();
    } catch (err) {
      setError(err?.response?.data?.detail || "Falha ao analisar aprendizado manual.");
    } finally {
      setManualSubmitting(false);
    }
  };

  const selectAttackForLearning = (attackId) => {
    setManualAttackId(attackId);
    setTaskStatus("Ataque selecionado para ensino manual. Escolha a fase P01-P22 e descreva a técnica.");
  };

  const selectPhaseForLearning = (phaseId) => {
    setManualPhaseId(phaseId);
    setTaskStatus("Fase selecionada para ensino manual. Escolha a skill e descreva a técnica.");
  };

  const seedCatalog = async () => {
    setSeeding(true);
    setError("");
    setTaskStatus("");
    try {
      const { data } = await client.post("/api/learning/vulnerabilities/seed-catalog");
      setSummary(data.summary || {});
      if ((data.items || []).length) {
        setReviewItem(data.items[0]);
      }
      await load();
      setTaskStatus(`${data.created || 0} aprendizados antecipados criados para revisão.`);
    } catch (err) {
      setError(err?.response?.data?.detail || "Falha ao antecipar catálogo de aprendizado.");
    } finally {
      setSeeding(false);
    }
  };

  const runGithubCrawler = async () => {
    setCrawlerRunning(true);
    setError("");
    setTaskStatus("");
    try {
      const { data } = await client.post("/api/learning/vulnerabilities/github-crawler", {
        min_per_phase: 50,
        min_per_skill: 150,
        max_created: 5000,
        purge_source: true,
      });
      setTaskStatus(data.message || "Crawler GitHub/HackerOne em execução.");
      if (data.task_id) {
        await pollLearningTask(data.task_id);
      }
    } catch (err) {
      setError(err?.response?.data?.detail || err?.message || "Falha ao executar crawler GitHub/HackerOne.");
    } finally {
      setCrawlerRunning(false);
    }
  };

  const toggleSelected = (id) => {
    setSelectedIds((current) => (
      current.includes(id)
        ? current.filter((item) => item !== id)
        : [...current, id]
    ));
  };

  const toggleAllPending = () => {
    setSelectedIds(allPendingSelected ? [] : pendingItemIds);
  };

  const review = async (action) => {
    if (!reviewItem?.id) return;
    setReviewing(true);
    setError("");
    try {
      const { data } = await client.put(`/api/learning/vulnerabilities/${reviewItem.id}/${action}`, { review_notes: notes });
      setReviewItem(data.item || null);
      setNotes("");
      await load();
    } catch (err) {
      setError(err?.response?.data?.detail || "Falha ao revisar aprendizado.");
    } finally {
      setReviewing(false);
    }
  };

  const deleteLearning = async () => {
    if (!reviewItem?.id) return;
    setReviewing(true);
    setError("");
    try {
      const { data } = await client.delete(`/api/learning/vulnerabilities/${reviewItem.id}`);
      setSummary(data.summary || {});
      setReviewItem(null);
      setNotes("");
      setTaskStatus(`Aprendizado ${data.deleted_id} retirado. Atualize ou ensine novamente para reaprender.`);
      await load();
    } catch (err) {
      setError(err?.response?.data?.detail || "Falha ao retirar aprendizado.");
    } finally {
      setReviewing(false);
    }
  };

  const bulkReview = async (action) => {
    if (!selectedIds.length) return;
    setReviewing(true);
    setError("");
    setTaskStatus("");
    try {
      const { data } = await client.post("/api/learning/vulnerabilities/bulk-review", {
        ids: selectedIds,
        action,
        review_notes: notes,
      });
      setSummary(data.summary || {});
      setSelectedIds([]);
      setNotes("");
      if ((data.items || []).length) {
        setReviewItem(data.items[0]);
      }
      setTaskStatus(`${data.reviewed_count || 0} aprendizados ${action === "accept" ? "aceitos" : "rejeitados"}.`);
      await load();
    } catch (err) {
      setError(err?.response?.data?.detail || "Falha ao revisar aprendizados em lote.");
    } finally {
      setReviewing(false);
    }
  };

  const generateMissionPrompt = async () => {
    setGeneratingPrompt(true);
    setError("");
    setTaskStatus("");
    try {
      const { data } = await client.post("/api/learning/vulnerabilities/mission-prompt");
      setSkillIndex(data.attack_index || skillIndex);
      setPhaseIndex(data.phase_index || phaseIndex);
      setMissionPrompt(data.prompt || "");
      setTaskStatus(`Prompt consolidado com ${data.learning_count || 0} aprendizados aceitos e conhecimento separado por P01-P22.`);
    } catch (err) {
      setError(err?.response?.data?.detail || "Falha ao consolidar prompt/missão.");
    } finally {
      setGeneratingPrompt(false);
    }
  };

  return (
    <main className="dpage space-y-4">
      <section className="panel p-5">
        <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
          <div>
            <p className="ds-eyebrow">Aprendizado operacional</p>
            <h1 className="mt-1 text-2xl font-semibold" style={{ color: "var(--ink)" }}>Vulnerability Learning</h1>
            <p className="mt-1 text-sm" style={{ color: "var(--ink-muted)" }}>
              Reports públicos entram como proposta; somente o aceite libera o conteúdo para os agentes.
            </p>
          </div>
          <div className="flex flex-wrap gap-2">
            <button type="button" className="btn-primary" onClick={generateMissionPrompt} disabled={generatingPrompt}>
              {generatingPrompt ? "Formalizando..." : "Formalizar prompt/missão"}
            </button>
            <button type="button" className="btn-secondary" onClick={seedCatalog} disabled={seeding}>
              {seeding ? "Antecipando..." : "Antecipar catálogo"}
            </button>
            <button type="button" className="btn-secondary" onClick={runGithubCrawler} disabled={crawlerRunning}>
              {crawlerRunning ? "Crawleando..." : "Crawler GitHub/HackerOne"}
            </button>
            <button type="button" className="btn-secondary" onClick={load} disabled={loading}>
              {loading ? "Atualizando..." : "Atualizar"}
            </button>
          </div>
        </div>
      </section>

      <section className="grid gap-3 md:grid-cols-5">
        <Counter label="Recebidos" value={summary.total} />
        <Counter label="Pendentes" value={summary.pending_review} />
        <Counter label="Aceitos" value={summary.accepted} />
        <Counter label="Técnicas recebidas" value={summary.techniques_received} />
        <Counter label="Técnicas aceitas" value={summary.techniques_accepted} />
      </section>

      <LearningIndex index={skillIndex} onLearn={selectAttackForLearning} />

      <PhaseKnowledgeIndex index={phaseIndex} onLearn={selectPhaseForLearning} />

      {error && (
        <section className="rounded-lg border px-4 py-3 text-sm" style={{ borderColor: "var(--sev-critical-border)", background: "var(--sev-critical-bg)", color: "var(--sev-critical-text)" }}>
          {error}
        </section>
      )}
      {taskStatus && !error && (
        <section className="rounded-lg border px-4 py-3 text-sm" style={{ borderColor: "var(--line)", background: "var(--surface-soft)", color: "var(--ink-soft)" }}>
          {taskStatus}
        </section>
      )}

      <section className="panel p-5">
        <div className="grid gap-4 lg:grid-cols-[1fr_auto] lg:items-end">
          <div>
            <label className="text-xs font-semibold uppercase tracking-wider" style={{ color: "var(--ink-muted)" }}>
              URLs HackerOne ou reports públicos
            </label>
            <textarea
              value={urlsText}
              onChange={(event) => setUrlsText(event.target.value)}
              className="mt-2 min-h-28 w-full rounded-lg border px-3 py-2 text-sm"
              placeholder="https://hackerone.com/reports/2586641; https://hackerone.com/reports/..."
            />
            <p className="mt-2 text-xs" style={{ color: "var(--ink-muted)" }}>{parsedUrlCount} URLs detectadas</p>
          </div>
          <button type="button" className="btn-primary" onClick={submit} disabled={submitting || parsedUrlCount === 0}>
            {submitting ? "Aprendendo..." : "Enviar para LLM"}
          </button>
        </div>
      </section>

      <ManualLearningForm
        attackOptions={attackOptions}
        phaseOptions={phaseOptions}
        attackId={manualAttackId}
        setAttackId={setManualAttackId}
        phaseId={manualPhaseId}
        setPhaseId={setManualPhaseId}
        instruction={manualInstruction}
        setInstruction={setManualInstruction}
        urlsText={manualUrlsText}
        setUrlsText={setManualUrlsText}
        onSubmit={submitManualLearning}
        busy={manualSubmitting}
      />

      <ReviewPanel
        item={reviewItem}
        notes={notes}
        setNotes={setNotes}
        busy={reviewing}
        onAccept={() => review("accept")}
        onReject={() => review("reject")}
        onDelete={deleteLearning}
      />

      {missionPrompt && (
        <section className="panel p-5">
          <div className="flex flex-col gap-2 lg:flex-row lg:items-center lg:justify-between">
            <div>
              <p className="ds-eyebrow">Prompt operacional consolidado</p>
              <h2 className="mt-1 text-lg font-semibold" style={{ color: "var(--ink)" }}>
                Missão de análise de vulnerabilidade por Cyber Kill Chain
              </h2>
            </div>
            <span className="ds-badge" style={{ borderColor: "var(--line)", background: "var(--surface-soft)" }}>
              IF / SE por ataque e skill
            </span>
          </div>
          <textarea
            readOnly
            value={missionPrompt}
            className="mt-4 min-h-96 w-full rounded-lg border px-3 py-2 text-xs font-mono leading-5"
            style={{ borderColor: "var(--line)", color: "var(--ink)", background: "var(--surface-soft)" }}
          />
        </section>
      )}

      <section className="panel p-5">
        <div className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
          <div>
            <h2 className="text-lg font-semibold" style={{ color: "var(--ink)" }}>Histórico</h2>
            <p className="mt-1 text-xs" style={{ color: "var(--ink-muted)" }}>
              {selectedIds.length} selecionados para revisão em lote
            </p>
          </div>
          <div className="flex flex-wrap gap-2">
            {loading && <span className="self-center text-xs" style={{ color: "var(--ink-muted)" }}>Carregando...</span>}
            <button type="button" className="btn-secondary" onClick={() => bulkReview("reject")} disabled={reviewing || selectedIds.length === 0}>
              Rejeitar selecionados
            </button>
            <button type="button" className="btn-primary" onClick={() => bulkReview("accept")} disabled={reviewing || selectedIds.length === 0}>
              Aceitar selecionados
            </button>
          </div>
        </div>
        <div className="mt-4 overflow-x-auto">
          <table className="w-full min-w-[820px] text-left text-sm">
            <thead>
              <tr className="border-b">
                <th className="px-3 py-2">
                  <input
                    type="checkbox"
                    checked={allPendingSelected}
                    onChange={toggleAllPending}
                    aria-label="Selecionar pendentes"
                  />
                </th>
                <th className="px-3 py-2">Status</th>
                <th className="px-3 py-2">Título</th>
                <th className="px-3 py-2">Tipo</th>
                <th className="px-3 py-2">URLs</th>
                <th className="px-3 py-2">Técnicas</th>
                <th className="px-3 py-2">Criado</th>
              </tr>
            </thead>
            <tbody>
              {items.map((item) => (
                <tr key={item.id} className="cursor-pointer border-b hover:bg-[var(--table-row-hover)]" onClick={() => { setReviewItem(item); setNotes(item.review_notes || ""); }}>
                  <td className="px-3 py-3" onClick={(event) => event.stopPropagation()}>
                    <input
                      type="checkbox"
                      checked={selectedIds.includes(item.id)}
                      disabled={item.status !== "pending_review"}
                      onChange={() => toggleSelected(item.id)}
                      aria-label={`Selecionar aprendizado ${item.id}`}
                    />
                  </td>
                  <td className="px-3 py-3"><span className={statusClass[item.status] || "ds-badge"}>{statusLabel[item.status] || item.status}</span></td>
                  <td className="max-w-xs px-3 py-3 font-medium" style={{ color: "var(--ink)" }}>{item.title || "-"}</td>
                  <td className="px-3 py-3" style={{ color: "var(--ink-soft)" }}>{item.vulnerability_type || "-"}</td>
                  <td className="px-3 py-3" style={{ color: "var(--ink-soft)" }}>{item.url_count || 0}</td>
                  <td className="px-3 py-3" style={{ color: "var(--ink-soft)" }}>{item.technique_count || 0}</td>
                  <td className="px-3 py-3" style={{ color: "var(--ink-soft)" }}>{formatDate(item.created_at)}</td>
                </tr>
              ))}
              {!items.length && (
                <tr>
                  <td colSpan={7} className="px-3 py-8 text-center" style={{ color: "var(--ink-muted)" }}>
                    Nenhum aprendizado registrado.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </section>
    </main>
  );
}
