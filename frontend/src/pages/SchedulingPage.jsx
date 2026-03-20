import { useEffect, useState } from "react";
import client from "../api/client";

const emptyForm = {
  access_group_id: "",
  authorization_code: "",
  targets_text: "",
  scan_type: "full",
  frequency: "daily",
  run_time: "00:00",
  day_of_week: "monday",
  day_of_month: 1,
  enabled: true,
};

export default function SchedulingPage() {
  const [form, setForm] = useState(emptyForm);
  const [schedules, setSchedules] = useState([]);
  const [groups, setGroups] = useState([]);
  const [editingId, setEditingId] = useState(null);

  const loadSchedules = async () => {
    const { data } = await client.get("/api/schedules");
    setSchedules(data);
  };

  useEffect(() => {
    loadSchedules();
    client.get("/api/access-groups").then((res) => setGroups(res.data));
  }, []);

  const submit = async (e) => {
    e.preventDefault();
    if (editingId) {
      await client.put(`/api/schedules/${editingId}`, form);
    } else {
      await client.post("/api/schedules", form);
    }
    setForm(emptyForm);
    setEditingId(null);
    await loadSchedules();
  };

  const editRow = (row) => {
    setEditingId(row.id);
    setForm({
      access_group_id: row.access_group_id || "",
      authorization_code: row.authorization_code || "",
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
    await client.delete(`/api/schedules/${id}`);
    await loadSchedules();
  };

  const runNow = async (id) => {
    await client.post(`/api/schedules/${id}/execute`);
    await loadSchedules();
  };

  return (
    <main className="mx-auto mt-6 w-[95%] max-w-6xl space-y-4 pb-10">
      <section className="panel p-5">
        <h2 className="text-xl font-semibold">Agendamento</h2>
        <p className="mt-1 text-sm text-slate-300">Informe alvos separados por ; e configure recorrencia.</p>

        <form onSubmit={submit} className="mt-4 grid gap-3 md:grid-cols-2">
          <textarea
            className="rounded-xl border border-slate-700 bg-slate-950 px-3 py-2 md:col-span-2"
            rows={3}
            placeholder="alvo1.com; alvo2.com; api.alvo3.com"
            value={form.targets_text}
            onChange={(e) => setForm({ ...form, targets_text: e.target.value })}
          />

          <input
            className="rounded-xl border border-slate-700 bg-slate-950 px-3 py-2 md:col-span-2"
            placeholder="Codigo de autorizacao para este agendamento"
            value={form.authorization_code}
            onChange={(e) => setForm({ ...form, authorization_code: e.target.value })}
          />

          <select
            className="rounded-xl border border-slate-700 bg-slate-950 px-3 py-2 md:col-span-2"
            value={form.access_group_id}
            onChange={(e) => setForm({ ...form, access_group_id: e.target.value ? Number(e.target.value) : "" })}
          >
            <option value="">Sem grupo</option>
            {groups.map((g) => (
              <option key={g.id} value={g.id}>{g.name}</option>
            ))}
          </select>

          <select
            className="rounded-xl border border-slate-700 bg-slate-950 px-3 py-2"
            value={form.scan_type}
            onChange={(e) => setForm({ ...form, scan_type: e.target.value })}
          >
            <option value="full">Full</option>
            <option value="recon">Recon</option>
            <option value="quick">Quick</option>
          </select>

          <select
            className="rounded-xl border border-slate-700 bg-slate-950 px-3 py-2"
            value={form.frequency}
            onChange={(e) => setForm({ ...form, frequency: e.target.value })}
          >
            <option value="daily">Diario</option>
            <option value="weekly">Semanal</option>
            <option value="monthly">Mensal</option>
          </select>

          <input
            type="time"
            className="rounded-xl border border-slate-700 bg-slate-950 px-3 py-2"
            value={form.run_time}
            onChange={(e) => setForm({ ...form, run_time: e.target.value })}
          />

          {form.frequency === "weekly" && (
            <select
              className="rounded-xl border border-slate-700 bg-slate-950 px-3 py-2"
              value={form.day_of_week}
              onChange={(e) => setForm({ ...form, day_of_week: e.target.value })}
            >
              <option value="monday">Segunda</option>
              <option value="tuesday">Terca</option>
              <option value="wednesday">Quarta</option>
              <option value="thursday">Quinta</option>
              <option value="friday">Sexta</option>
              <option value="saturday">Sabado</option>
              <option value="sunday">Domingo</option>
            </select>
          )}

          {form.frequency === "monthly" && (
            <input
              type="number"
              min={1}
              max={31}
              className="rounded-xl border border-slate-700 bg-slate-950 px-3 py-2"
              value={form.day_of_month}
              onChange={(e) => setForm({ ...form, day_of_month: Number(e.target.value) })}
            />
          )}

          <label className="flex items-center gap-2 text-sm">
            <input
              type="checkbox"
              checked={form.enabled}
              onChange={(e) => setForm({ ...form, enabled: e.target.checked })}
            />
            Habilitado
          </label>

          <button className="rounded-xl bg-brand-500 px-4 py-2 font-semibold text-slate-950">
            {editingId ? "Salvar Edicao" : "Criar Agendamento"}
          </button>
        </form>
      </section>

      <section className="panel p-5">
        <h3 className="text-lg font-semibold">Agendamentos Ativos</h3>
        <div className="mt-3 space-y-2">
          {schedules.map((row) => (
            <div key={row.id} className="rounded-xl border border-slate-800 bg-slate-900/70 p-3">
              <p className="font-medium">#{row.id} | {row.scan_type} | {row.frequency}</p>
              <p className="text-xs text-slate-300">grupo {row.access_group_id || "-"} | auth {row.authorization_code || "-"} | {row.targets_text}</p>
              <p className="text-xs text-slate-400">
                Horario: {row.run_time} {row.day_of_week ? `| Dia semana: ${row.day_of_week}` : ""}
                {row.day_of_month ? ` | Dia mes: ${row.day_of_month}` : ""}
              </p>
              <div className="mt-2 flex gap-2">
                <button onClick={() => editRow(row)} className="rounded-lg bg-cyan-500/20 px-2 py-1 text-xs text-cyan-300">Editar</button>
                <button onClick={() => runNow(row.id)} className="rounded-lg bg-emerald-500/20 px-2 py-1 text-xs text-emerald-300">Executar Agora</button>
                <button onClick={() => deleteRow(row.id)} className="rounded-lg bg-rose-500/20 px-2 py-1 text-xs text-rose-300">Excluir</button>
              </div>
            </div>
          ))}
        </div>
      </section>
    </main>
  );
}
