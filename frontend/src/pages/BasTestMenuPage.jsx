import { useEffect, useMemo, useState } from "react";
import client from "../api/client";
import { toastError, toastSuccess } from "../utils/toast";

const fieldStyle = {
  width: "100%", padding: "9px 12px", borderRadius: 8,
  border: "1px solid var(--line)", background: "var(--canvas)",
  fontSize: 13, color: "var(--ink)",
};

const AVAILABILITY_LABEL = {
  available: "disponível",
  simulated: "simulado (tráfego real, resultado simulado)",
  planned: "planejado — ferramenta ainda não integrada",
  disabled: "desabilitado",
  future_agent_required: "requer agente real (fase futura)",
};

const RISK_BADGE = { safe: "b-low", elevated: "b-medium", high_risk: "b-critical" };

const emptyForm = {
  name: "", agent_id: "", target_hint: "", technique_keys: [],
  frequency: "daily", run_time: "00:00", day_of_week: "monday", day_of_month: 1,
  max_authorized_risk_tier: "safe", authorization_attested: false,
};

export default function BasTestMenuPage() {
  const [agents, setAgents] = useState([]);
  const [techniques, setTechniques] = useState([]);
  const [schedules, setSchedules] = useState([]);
  const [form, setForm] = useState(emptyForm);
  const [editingId, setEditingId] = useState(null);

  const load = async () => {
    try {
      const [{ data: a }, { data: t }, { data: s }] = await Promise.all([
        client.get("/api/bas/agents"),
        client.get("/api/bas/techniques"),
        client.get("/api/bas/schedules"),
      ]);
      setAgents(a);
      setTechniques(t);
      setSchedules(s);
    } catch (error) {
      const detail = error?.response?.data?.detail;
      toastError(typeof detail === "string" ? detail : "Falha ao carregar testes BAS.");
    }
  };

  useEffect(() => { load(); }, []);

  const grouped = useMemo(() => {
    const byCategory = {};
    for (const t of techniques) {
      byCategory[t.category] = byCategory[t.category] || [];
      byCategory[t.category].push(t);
    }
    return byCategory;
  }, [techniques]);

  const maxTierOrder = { safe: 0, elevated: 1, high_risk: 2 };
  const techniqueSelectable = (t) => {
    if (!["available", "simulated"].includes(t.availability)) return false;
    if (maxTierOrder[t.risk_tier] === 0) return true;
    return maxTierOrder[t.risk_tier] <= maxTierOrder[form.max_authorized_risk_tier] && form.authorization_attested;
  };

  const toggleTechnique = (key) => {
    setForm((prev) => ({
      ...prev,
      technique_keys: prev.technique_keys.includes(key)
        ? prev.technique_keys.filter((k) => k !== key)
        : [...prev.technique_keys, key],
    }));
  };

  const submit = async (e) => {
    e.preventDefault();
    try {
      if (editingId) {
        await client.patch(`/api/bas/schedules/${editingId}`, form);
        toastSuccess("Agendamento BAS atualizado.");
      } else {
        await client.post("/api/bas/schedules", form);
        toastSuccess("Agendamento BAS criado.");
      }
      setForm(emptyForm);
      setEditingId(null);
      await load();
    } catch (error) {
      const detail = error?.response?.data?.detail;
      toastError(typeof detail === "string" ? detail : "Falha ao salvar agendamento BAS.");
    }
  };

  const editRow = (row) => {
    setEditingId(row.id);
    setForm({
      name: row.name || "", agent_id: row.agent_id, target_hint: row.target_hint || "",
      technique_keys: row.technique_keys || [], frequency: row.frequency, run_time: row.run_time,
      day_of_week: row.day_of_week || "monday", day_of_month: row.day_of_month || 1,
      max_authorized_risk_tier: row.max_authorized_risk_tier, authorization_attested: row.authorization_attested,
    });
  };

  const deleteRow = async (id) => {
    try {
      await client.delete(`/api/bas/schedules/${id}`);
      await load();
      toastSuccess("Agendamento BAS removido.");
    } catch (error) {
      const detail = error?.response?.data?.detail;
      toastError(typeof detail === "string" ? detail : "Falha ao excluir agendamento BAS.");
    }
  };

  const runNow = async (id) => {
    try {
      const { data } = await client.post(`/api/bas/schedules/${id}/run-now`);
      const skippedCount = (data?.skipped || []).length;
      toastSuccess(`Execução disparada · ${(data?.job_ids || []).length} job(s)${skippedCount ? ` · ${skippedCount} técnica(s) pulada(s)` : ""}`);
      await load();
    } catch (error) {
      const detail = error?.response?.data?.detail;
      toastError(typeof detail === "string" ? (detail.message || JSON.stringify(detail)) : "Falha ao executar agora.");
    }
  };

  return (
    <main className="dpage space-y-4">
      <div className="page-intro">
        <h2>BAS — Testes e Agendamento.</h2>
        <div className="sub">escolha o agente, as técnicas e a periodicidade</div>
      </div>

      <section className="card">
        <div className="card-h"><div><h3>{editingId ? "Editar agendamento" : "Novo agendamento"}</h3><div className="sub">selecione agente + técnicas + recorrência</div></div></div>

        <form onSubmit={submit} style={{ display: "grid", gap: 10, gridTemplateColumns: "1fr 1fr" }}>
          <input style={fieldStyle} placeholder="Nome do agendamento" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} />
          <select style={fieldStyle} value={form.agent_id} onChange={(e) => setForm({ ...form, agent_id: Number(e.target.value) })}>
            <option value="">Selecione o agente</option>
            {agents.map((a) => <option key={a.id} value={a.id}>{a.label || a.hostname || `agente #${a.id}`} ({a.status})</option>)}
          </select>
          <input
            style={{ ...fieldStyle, gridColumn: "1 / -1" }}
            placeholder="Alvo interno (IP recomendado nesta fase — ex: 10.10.10.5)"
            value={form.target_hint}
            onChange={(e) => setForm({ ...form, target_hint: e.target.value })}
          />

          <div style={{ gridColumn: "1 / -1" }}>
            <div className="mono-sm muted" style={{ marginBottom: 6 }}>Nível de risco autorizado neste agendamento</div>
            <select style={fieldStyle} value={form.max_authorized_risk_tier} onChange={(e) => setForm({ ...form, max_authorized_risk_tier: e.target.value })}>
              <option value="safe">Safe (padrão — só leitura/enumeração)</option>
              <option value="elevated">Elevated (Kerberoasting, etc.)</option>
              <option value="high_risk">High risk (NTLM relay, etc.)</option>
            </select>
            {form.max_authorized_risk_tier !== "safe" && (
              <label style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 13, marginTop: 8, color: "var(--ink-soft)" }}>
                <input type="checkbox" checked={form.authorization_attested} onChange={(e) => setForm({ ...form, authorization_attested: e.target.checked })} />
                Atesto autorização explícita para rodar técnicas deste nível de risco
              </label>
            )}
          </div>

          <div style={{ gridColumn: "1 / -1" }}>
            <div className="mono-sm muted" style={{ marginBottom: 8 }}>Técnicas</div>
            {Object.entries(grouped).map(([category, items]) => (
              <div key={category} style={{ marginBottom: 12 }}>
                <div style={{ fontSize: 11.5, fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.06em", color: "var(--ink-soft)", marginBottom: 6 }}>{category}</div>
                <div style={{ display: "grid", gap: 6 }}>
                  {items.map((t) => {
                    const selectable = techniqueSelectable(t);
                    return (
                      <label key={t.technique_key} style={{
                        display: "flex", alignItems: "center", gap: 10, padding: "8px 10px",
                        borderRadius: 8, border: "1px solid var(--line)",
                        opacity: selectable ? 1 : 0.55,
                      }}>
                        <input
                          type="checkbox"
                          disabled={!selectable}
                          checked={form.technique_keys.includes(t.technique_key)}
                          onChange={() => toggleTechnique(t.technique_key)}
                        />
                        <span style={{ flex: 1, fontSize: 13 }}>{t.display_name}</span>
                        <span className={`b ${RISK_BADGE[t.risk_tier] || "b-neutral"}`}>{t.risk_tier}</span>
                        <span className="mono-sm muted">{AVAILABILITY_LABEL[t.availability] || t.availability}</span>
                      </label>
                    );
                  })}
                </div>
              </div>
            ))}
          </div>

          <select style={fieldStyle} value={form.frequency} onChange={(e) => setForm({ ...form, frequency: e.target.value })}>
            <option value="daily">Diário</option>
            <option value="weekly">Semanal</option>
            <option value="monthly">Mensal</option>
            <option value="every_3_hours">A cada 3 horas</option>
            <option value="every_6_hours">A cada 6 horas</option>
            <option value="every_12_hours">A cada 12 horas</option>
          </select>
          <input type="time" style={fieldStyle} value={form.run_time} onChange={(e) => setForm({ ...form, run_time: e.target.value })} />

          <div style={{ gridColumn: "1 / -1", display: "flex", gap: 8 }}>
            <button className="btn btn-primary" type="submit" disabled={!form.agent_id || form.technique_keys.length === 0}>
              {editingId ? "Salvar edição" : "Criar agendamento"}
            </button>
            {editingId && (
              <button className="btn btn-ghost" type="button" onClick={() => { setEditingId(null); setForm(emptyForm); }}>Cancelar</button>
            )}
          </div>
        </form>
      </section>

      <section className="t-wrap">
        <div className="t-head"><div><h3>Agendamentos</h3><div className="sub">{schedules.length} agendamento(s)</div></div></div>
        {schedules.length === 0 && <div className="empty">Nenhum agendamento BAS configurado.</div>}
        {schedules.map((row) => (
          <div key={row.id} style={{ padding: "14px 22px", borderBottom: "1px solid var(--line-soft)" }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 10 }}>
              <span className="mono" style={{ fontWeight: 600 }}>
                #{row.id} · {row.name || "sem nome"} · {row.frequency}
                {!row.enabled && <span className="b b-neutral" style={{ marginLeft: 8 }}>desativado</span>}
              </span>
              <div style={{ display: "flex", gap: 6 }}>
                <button className="btn btn-ghost" style={{ padding: "5px 10px", fontSize: 12 }} onClick={() => editRow(row)}>Editar</button>
                <button className="btn btn-primary" style={{ padding: "5px 10px", fontSize: 12 }} onClick={() => runNow(row.id)}>Executar agora</button>
                <button className="btn btn-danger" style={{ padding: "5px 10px", fontSize: 12 }} onClick={() => deleteRow(row.id)}>Excluir</button>
              </div>
            </div>
            <div className="mono-sm muted" style={{ marginTop: 5 }}>
              alvo: {row.target_hint || "—"} · técnicas: {(row.technique_keys || []).join(", ") || "—"}
            </div>
            <div className="mono-sm muted" style={{ marginTop: 3 }}>
              horário {row.run_time} · último disparo: {row.last_run_at || "nunca"}
            </div>
          </div>
        ))}
      </section>
    </main>
  );
}
