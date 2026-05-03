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
  const [items, setItems] = useState([]);
  const [reviewItem, setReviewItem] = useState(null);
  const [notes, setNotes] = useState("");
  const [loading, setLoading] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [reviewing, setReviewing] = useState(false);
  const [error, setError] = useState("");

  const parsedUrlCount = useMemo(
    () => urlsText.split(";").map((item) => item.trim()).filter(Boolean).length,
    [urlsText],
  );

  const load = async () => {
    setLoading(true);
    setError("");
    try {
      const { data } = await client.get("/api/learning/vulnerabilities");
      setSummary(data.summary || {});
      setItems(data.items || []);
      if (!reviewItem) {
        const pending = (data.items || []).find((item) => item.status === "pending_review");
        setReviewItem(pending || (data.items || [])[0] || null);
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

  const submit = async () => {
    setSubmitting(true);
    setError("");
    try {
      const { data } = await client.post("/api/learning/vulnerabilities", { urls_text: urlsText });
      setSummary(data.summary || {});
      setReviewItem(data.item || null);
      setNotes("");
      setUrlsText("");
      await load();
    } catch (err) {
      setError(err?.response?.data?.detail || "Falha ao enviar URLs para aprendizagem.");
    } finally {
      setSubmitting(false);
    }
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
          <button type="button" className="btn-secondary" onClick={load} disabled={loading}>
            {loading ? "Atualizando..." : "Atualizar"}
          </button>
        </div>
      </section>

      <section className="grid gap-3 md:grid-cols-5">
        <Counter label="Recebidos" value={summary.total} />
        <Counter label="Pendentes" value={summary.pending_review} />
        <Counter label="Aceitos" value={summary.accepted} />
        <Counter label="Técnicas recebidas" value={summary.techniques_received} />
        <Counter label="Técnicas aceitas" value={summary.techniques_accepted} />
      </section>

      {error && (
        <section className="rounded-lg border px-4 py-3 text-sm" style={{ borderColor: "var(--sev-critical-border)", background: "var(--sev-critical-bg)", color: "var(--sev-critical-text)" }}>
          {error}
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

      <section className="panel p-5">
        <div className="flex items-center justify-between gap-3">
          <h2 className="text-lg font-semibold" style={{ color: "var(--ink)" }}>Histórico</h2>
          {loading && <span className="text-xs" style={{ color: "var(--ink-muted)" }}>Carregando...</span>}
        </div>
        <div className="mt-4 overflow-x-auto">
          <table className="w-full min-w-[760px] text-left text-sm">
            <thead>
              <tr className="border-b">
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
                  <td colSpan={6} className="px-3 py-8 text-center" style={{ color: "var(--ink-muted)" }}>
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
