import { useEffect, useState } from "react";
import client from "../api/client";
import { toastError, toastSuccess } from "../utils/toast";

const emptyForm = {
  access_group_id: "",
  access_group_name: "",
  targets_text: "",
  scan_type: "full",
  frequency: "daily",
  run_time: "00:00",
  day_of_week: "monday",
  day_of_month: 1,
  enabled: true,
};

const fieldStyle = {
  width: "100%", padding: "9px 12px", borderRadius: 8,
  border: "1px solid var(--line)", background: "var(--canvas)",
  fontSize: 13, color: "var(--ink)",
};

export default function SchedulingPage({ embedded = false }) {
  const [form, setForm] = useState(emptyForm);
  const [schedules, setSchedules] = useState([]);
  const [groups, setGroups] = useState([]);
  const [editingId, setEditingId] = useState(null);
  const [executionInfo, setExecutionInfo] = useState(null);

  const loadSchedules = async () => {
    const { data } = await client.get("/api/schedules");
    setSchedules(data);
  };

  useEffect(() => {
    loadSchedules();
    client.get("/api/access-groups").then((res) => setGroups(res.data));
  }, []);

  useEffect(() => {
    if (!form.access_group_id && !form.access_group_name && groups.length === 1) {
      setForm((prev) => ({ ...prev, access_group_id: groups[0].id }));
    }
  }, [form.access_group_id, form.access_group_name, groups]);

  const submit = async (e) => {
    e.preventDefault();
    try {
      if (editingId) {
        await client.put(`/api/schedules/${editingId}`, form);
        toastSuccess("Agendamento atualizado com sucesso.");
      } else {
        await client.post("/api/schedules", form);
        toastSuccess("Agendamento criado com sucesso.");
      }
      setForm(emptyForm);
      setEditingId(null);
      await loadSchedules();
    } catch (error) {
      const detail = error?.response?.data?.detail;
      toastError(typeof detail === "string" ? detail : "Falha ao salvar agendamento.");
    }
  };

  const editRow = (row) => {
    setEditingId(row.id);
    setForm({
      access_group_id: row.access_group_id || "",
      access_group_name: "",
      targets_text: row.targets_text,
      scan_type: row.scan_type,
      frequency: row.frequency,
      run_time: row.run_time,
      day_of_week: row.day_of_week || "monday",
      day_of_month: row.day_of_month || 1,
      enabled: row.enabled,
    });
  };

  const deleteRow = async (id) => {
    try {
      await client.delete(`/api/schedules/${id}`);
      await loadSchedules();
      toastSuccess("Agendamento removido.");
    } catch (error) {
      const detail = error?.response?.data?.detail;
      toastError(typeof detail === "string" ? detail : "Falha ao excluir agendamento.");
    }
  };

  const runNow = async (id) => {
    try {
      const { data } = await client.post(`/api/schedules/${id}/execute`);
      const count = Array.isArray(data?.created_scans) ? data.created_scans.length : 0;
      setExecutionInfo({
        total_targets: data.total_targets || 0,
        batch_size: data.batch_size || 25,
        batches_created: data.batches_created || count,
        created_scans: data.created_scans || [],
        validated_domains: data.validated_domains || [],
      });
      await loadSchedules();
      toastSuccess(`Execução iniciada · ${data.batches_created || count} jobs para ${data.total_targets || 0} alvo(s)`);
    } catch (error) {
      const detail = error?.response?.data?.detail;
      toastError(typeof detail === "string" ? detail : "Falha ao executar agendamento agora.");
    }
  };

  const Shell = embedded ? "div" : "main";
  const shellClassName = embedded ? "space-y-4" : "dpage space-y-4";

  return (
    <Shell className={shellClassName}>
      {!embedded && (
        <div className="page-intro">
          <h2>Agendamentos.</h2>
          <div className="sub">janelas e cadência de scans recorrentes</div>
        </div>
      )}

      <section className="card">
        <div className="card-h">
          <div>
            <h3>{editingId ? "Editar agendamento" : "Novo agendamento"}</h3>
            <div className="sub">informe alvos separados por ; e configure a recorrência</div>
          </div>
        </div>

        {executionInfo && (
          <div style={{ marginBottom: 16, padding: "14px 16px", borderRadius: 10, border: "1px solid var(--sev-low-border)", background: "var(--sev-low-bg)" }}>
            <h4 style={{ margin: 0, fontSize: 13, fontWeight: 700, color: "var(--sev-low-text)" }}>Última execução</h4>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 12, marginTop: 10 }}>
              <div><div className="mono-sm muted">alvos</div><div style={{ fontWeight: 700, color: "var(--ink)" }}>{executionInfo.total_targets}</div></div>
              <div><div className="mono-sm muted">lote</div><div style={{ fontWeight: 700, color: "var(--ink)" }}>{executionInfo.batch_size}</div></div>
              <div><div className="mono-sm muted">jobs criados</div><div style={{ fontWeight: 700, color: "var(--ink)" }}>{executionInfo.batches_created}</div></div>
            </div>
            <div className="mono-sm muted" style={{ marginTop: 8 }}>scans: {executionInfo.created_scans.join(", ") || "—"}</div>
          </div>
        )}

        <form onSubmit={submit} style={{ display: "grid", gap: 10, gridTemplateColumns: "1fr 1fr" }}>
          <textarea
            style={{ ...fieldStyle, gridColumn: "1 / -1", fontFamily: "var(--font-mono)" }}
            rows={3}
            placeholder="alvo1.com; alvo2.com; api.alvo3.com"
            value={form.targets_text}
            onChange={(e) => setForm({ ...form, targets_text: e.target.value })}
          />
          <select style={{ ...fieldStyle, gridColumn: "1 / -1" }} value={form.access_group_id}
            onChange={(e) => setForm({ ...form, access_group_id: e.target.value ? Number(e.target.value) : "", access_group_name: e.target.value ? "" : form.access_group_name })}>
            <option value="">Selecione a empresa</option>
            {groups.map((g) => <option key={g.id} value={g.id}>{g.name}</option>)}
          </select>
          <input
            style={{ ...fieldStyle, gridColumn: "1 / -1" }}
            placeholder="Ou digite o nome do grupo de acesso"
            value={form.access_group_name}
            onChange={(e) => setForm({ ...form, access_group_name: e.target.value, access_group_id: e.target.value.trim() ? "" : form.access_group_id })}
            list="schedule-access-groups"
          />
          <datalist id="schedule-access-groups">
            {groups.map((g) => <option key={g.id} value={g.name} />)}
          </datalist>
          <select style={fieldStyle} value={form.scan_type} onChange={(e) => setForm({ ...form, scan_type: e.target.value })}>
            <option value="full">Full</option>
            <option value="recon">Recon</option>
            <option value="quick">Quick</option>
          </select>
          <select style={fieldStyle} value={form.frequency} onChange={(e) => setForm({ ...form, frequency: e.target.value })}>
            <option value="daily">Diário</option>
            <option value="weekly">Semanal</option>
            <option value="monthly">Mensal</option>
            <option value="every_3_hours">A cada 3 horas</option>
            <option value="every_6_hours">A cada 6 horas</option>
            <option value="every_12_hours">A cada 12 horas</option>
          </select>
          <input type="time" style={fieldStyle} value={form.run_time} onChange={(e) => setForm({ ...form, run_time: e.target.value })} />
          {form.frequency === "weekly" && (
            <select style={fieldStyle} value={form.day_of_week} onChange={(e) => setForm({ ...form, day_of_week: e.target.value })}>
              <option value="monday">Segunda</option>
              <option value="tuesday">Terça</option>
              <option value="wednesday">Quarta</option>
              <option value="thursday">Quinta</option>
              <option value="friday">Sexta</option>
              <option value="saturday">Sábado</option>
              <option value="sunday">Domingo</option>
            </select>
          )}
          {form.frequency === "monthly" && (
            <input type="number" min={1} max={31} style={fieldStyle} value={form.day_of_month}
              onChange={(e) => setForm({ ...form, day_of_month: Number(e.target.value) })} />
          )}
          <label style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 13, color: "var(--ink-soft)" }}>
            <input type="checkbox" checked={form.enabled} onChange={(e) => setForm({ ...form, enabled: e.target.checked })} />
            Habilitado
          </label>
          <div style={{ gridColumn: "1 / -1", display: "flex", gap: 8 }}>
            <button className="btn btn-primary" type="submit" disabled={!form.access_group_id && !form.access_group_name.trim()}>{editingId ? "Salvar edição" : "Criar agendamento"}</button>
            {editingId && (
              <button className="btn btn-ghost" type="button" onClick={() => { setEditingId(null); setForm(emptyForm); }}>
                Cancelar
              </button>
            )}
          </div>
        </form>
      </section>

      <section className="t-wrap">
        <div className="t-head"><div><h3>Agendamentos ativos</h3><div className="sub">{schedules.length} schedules</div></div></div>
        {schedules.length === 0 && <div className="empty">Nenhum agendamento configurado.</div>}
        {schedules.map((row) => (
          <div key={row.id} style={{ padding: "14px 22px", borderBottom: "1px solid var(--line-soft)" }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 10 }}>
              <span className="mono" style={{ fontWeight: 600 }}>
                #{row.id} · {row.scan_type} · {row.frequency}
                {!row.enabled && <span className="b b-neutral" style={{ marginLeft: 8 }}>desativado</span>}
              </span>
              <div style={{ display: "flex", gap: 6 }}>
                <button className="btn btn-ghost" style={{ padding: "5px 10px", fontSize: 12 }} onClick={() => editRow(row)}>Editar</button>
                <button className="btn btn-primary" style={{ padding: "5px 10px", fontSize: 12 }} onClick={() => runNow(row.id)}>Executar agora</button>
                <button className="btn btn-danger" style={{ padding: "5px 10px", fontSize: 12 }} onClick={() => deleteRow(row.id)}>Excluir</button>
              </div>
            </div>
            <div className="mono-sm muted" style={{ marginTop: 5 }}>
              empresa: {row.access_group_name || (row.access_group_id ? `#${row.access_group_id}` : "—")} ·{" "}
              domínios: {(row.targets || []).join("; ") || row.targets_text || "—"}
            </div>
            <div className="mono-sm muted" style={{ marginTop: 3 }}>
              horário {row.run_time}
              {row.day_of_week ? ` · dia ${row.day_of_week}` : ""}
              {row.day_of_month ? ` · dia ${row.day_of_month}` : ""}
            </div>
          </div>
        ))}
      </section>
    </Shell>
  );
}
