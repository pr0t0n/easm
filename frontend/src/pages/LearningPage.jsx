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
    return new Date(value).toLocaleString();
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

function readinessLabel(value) {
  if (value === "operational") return "Operacional";
  if (value === "partial") return "Parcial";
  if (value === "initial") return "Inicial";
  return "Sem aprendizado";
}

function LearningIndex({ index }) {
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
          {index.overall_learning_percent || 0}% global
        </div>
      </div>
      <div className="mt-4 grid gap-3 md:grid-cols-2 xl:grid-cols-3">
        {items.map((item) => (
          <div key={item.id} className="rounded-lg border p-4" style={{ borderColor: "var(--line)", background: "#fff" }}>
            <div className="flex items-start justify-between gap-3">
              <div>
                <h3 className="text-sm font-semibold" style={{ color: "var(--ink)" }}>{item.label}</h3>
                <p className="mt-1 text-xs" style={{ color: "var(--ink-muted)" }}>
                  {item.accepted_learnings} aceitos · {item.techniques_accepted}/{item.target_techniques} técnicas
                </p>
              </div>
              <span className="ds-badge" style={{ borderColor: "var(--line)", background: "var(--surface-soft)" }}>
                {readinessLabel(item.readiness)}
              </span>
            </div>
            <div className="mt-3 h-2 overflow-hidden rounded-full" style={{ background: "var(--surface-soft)" }}>
              <div
                className="h-full rounded-full"
                style={{
                  width: `${Math.min(100, Math.max(0, item.learning_percent || 0))}%`,
                  background: item.learning_percent >= 85 ? "var(--sev-low-text)" : item.learning_percent >= 45 ? "var(--sev-medium-text)" : "var(--brand-500)",
                }}
              />
            </div>
            <div className="mt-2 flex items-center justify-between text-xs" style={{ color: "var(--ink-muted)" }}>
              <span>{item.learning_percent || 0}% aprendido</span>
              <span>{(item.phases || []).join(", ")}</span>
            </div>
            <p className="mt-3 text-xs leading-5" style={{ color: "var(--ink-soft)" }}>
              Skills: {(item.skills || []).join(", ") || "-"}
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

function ReviewPanel({ item, notes, setNotes, onAccept, onReject, busy }) {
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
    </section>
  );
}

export default function LearningPage() {
  const [urlsText, setUrlsText] = useState("");
  const [summary, setSummary] = useState({});
  const [skillIndex, setSkillIndex] = useState(null);
  const [missionPrompt, setMissionPrompt] = useState("");
  const [items, setItems] = useState([]);
  const [reviewItem, setReviewItem] = useState(null);
  const [notes, setNotes] = useState("");
  const [selectedIds, setSelectedIds] = useState([]);
  const [loading, setLoading] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [seeding, setSeeding] = useState(false);
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

  const load = async () => {
    setLoading(true);
    setError("");
    try {
      const [{ data }, indexResponse] = await Promise.all([
        client.get("/api/learning/vulnerabilities"),
        client.get("/api/learning/vulnerabilities/attack-index").catch(() => ({ data: null })),
      ]);
      const nextItems = data.items || [];
      setSummary(data.summary || {});
      if (indexResponse?.data) setSkillIndex(indexResponse.data);
      setItems(nextItems);
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
        await load();
      }
    } catch (err) {
      setError(err?.response?.data?.detail || err?.message || "Falha ao enviar URLs para aprendizagem.");
    } finally {
      setTaskStatus("");
      setSubmitting(false);
    }
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
      setMissionPrompt(data.prompt || "");
      setTaskStatus(`Prompt consolidado com ${data.learning_count || 0} aprendizados aceitos e ${data.overall_learning_percent || 0}% de cobertura global.`);
    } catch (err) {
      setError(err?.response?.data?.detail || "Falha ao consolidar prompt/missão.");
    } finally {
      setGeneratingPrompt(false);
    }
  };

  return (
    <main className="mx-auto mt-6 w-[95%] max-w-7xl space-y-4 pb-10">
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

      <LearningIndex index={skillIndex} />

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

      <ReviewPanel
        item={reviewItem}
        notes={notes}
        setNotes={setNotes}
        busy={reviewing}
        onAccept={() => review("accept")}
        onReject={() => review("reject")}
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
