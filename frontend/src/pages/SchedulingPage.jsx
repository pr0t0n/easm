import { useEffect, useState } from "react";
import client from "../api/client";
import { toastError, toastSuccess } from "../utils/toast";

const emptyForm = {
  access_group_id: "",
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
  const [executionInfo, setExecutionInfo] = useState(null);

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
      });
      await loadSchedules();
      toastSuccess(`✓ Execucao iniciada com sucesso\n${data.batches_created || count} jobs criados para ${data.total_targets || 0} alvo(s)`);
    } catch (error) {
      const detail = error?.response?.data?.detail;
      toastError(typeof detail === "string" ? detail : "Falha ao executar agendamento agora.");
    }
  };

  return (
    <main className="mx-auto mt-6 w-[95%] max-w-6xl space-y-4 pb-10">
      <section className="panel p-5">
        <h2 className="text-xl font-semibold">Agendamento</h2>
        <p className="mt-1 text-sm text-slate-300">Informe alvos separados por ; e configure recorrencia.</p>

        {executionInfo && (
          <div className="mt-4 rounded-xl border border-emerald-500/30 bg-emerald-500/10 p-4">
            <h3 className="font-semibold text-emerald-300">Ultima Execucao</h3>
            <div className="mt-3 grid gap-3 text-sm md:grid-cols-2">
              <div>
                <p className="text-slate-400">Total de alvos</p>
                <p className="text-lg font-semibold text-white">{executionInfo.total_targets}</p>
              </div>
              <div>
                <p className="text-slate-400">Tamanho do lote</p>
                <p className="text-lg font-semibold text-white">{executionInfo.batch_size}</p>
              </div>
              <div>
                <p className="text-slate-400">Lotes criados</p>
                <p className="text-lg font-semibold text-white">{executionInfo.batches_created}</p>
              </div>
              <div>
                <p className="text-slate-400">Scans (IDs)</p>
                <p className="text-sm text-slate-200">{executionInfo.created_scans.join(", ") || "-"}</p>
              </div>
            </div>
            <p className="mt-3 text-xs text-slate-400">
              <strong>Como funciona:</strong> Com {executionInfo.total_targets} alvo(s) e lotes de {executionInfo.batch_size} alvos, foram criados {executionInfo.batches_created} job(s) de scans distribuidos entre os workers unificados (recon, vuln, osint). Cada job processa seu lote em paralelo com escalamento automatico de CPU.
            </p>
          </div>
        )}

        <form onSubmit={submit} className="mt-4 grid gap-3 md:grid-cols-2">
          <textarea
            className="rounded-xl border border-slate-700 bg-slate-950 px-3 py-2 md:col-span-2"
            rows={3}
            placeholder="alvo1.com; alvo2.com; api.alvo3.com"
            value={form.targets_text}
            onChange={(e) => setForm({ ...form, targets_text: e.target.value })}
          />

          <div className="md:col-span-2 rounded-xl border border-sky-200 bg-sky-50 px-4 py-3 text-sm text-slate-700 shadow-sm">
            <p className="font-semibold text-slate-800">Execucao do Agendamento com Batching Inteligente</p>
            <p className="mt-1 leading-relaxed text-slate-700">
              O agendamento executa scans nos alvos informados em lotes de ~25 alvos. Cada lote gera um ScanJob distribuido para o pool unificado de workers (recon, vuln, osint) com autoscalagem dinamica baseada em CPU. Exemplo: 100 alvos → 4 jobs em paralelo.
            </p>
          </div>

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

          <button className="rounded-xl bg-blue-600 px-4 py-2 font-semibold text-white">
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
              <p className="text-xs text-slate-300">
                grupo {row.access_group_id || "-"} | {row.targets_text}
              </p>
              <p className="text-xs text-slate-400">
                Horario: {row.run_time} {row.day_of_week ? `| Dia semana: ${row.day_of_week}` : ""}
                {row.day_of_month ? ` | Dia mes: ${row.day_of_month}` : ""}
              </p>
              <div className="mt-2 flex gap-2">
                <button onClick={() => editRow(row)} className="rounded-lg bg-blue-500/15 px-2 py-1 text-xs text-blue-300">Editar</button>
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
