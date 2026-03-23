import { useEffect, useState } from "react";
import client from "../api/client";

export default function UserManagementPage() {
  const [users, setUsers] = useState([]);
  const [groups, setGroups] = useState([]);
  const [newUser, setNewUser] = useState({ email: "", password: "", is_admin: false, group_ids: [] });
  const [passwordForm, setPasswordForm] = useState({ userId: "", newPassword: "" });
  const [groupForm, setGroupForm] = useState({ name: "", description: "" });
  const [drafts, setDrafts] = useState({});
  const [feedback, setFeedback] = useState("");
  const [error, setError] = useState("");
  const [busyUserId, setBusyUserId] = useState(null);

  const loadData = async () => {
    const [usersRes, groupsRes] = await Promise.all([client.get("/api/users"), client.get("/api/access-groups")]);
    setUsers(usersRes.data);
    setGroups(groupsRes.data);
    setDrafts(
      Object.fromEntries(
        (usersRes.data || []).map((user) => [
          user.id,
          {
            email: user.email,
            is_admin: Boolean(user.is_admin),
            is_active: Boolean(user.is_active),
            group_ids: user.group_ids || [],
          },
        ]),
      ),
    );
  };

  useEffect(() => {
    loadData();
  }, []);

  const createUser = async () => {
    setError("");
    setFeedback("");
    try {
      await client.post("/api/users", newUser);
      setNewUser({ email: "", password: "", is_admin: false, group_ids: [] });
      setFeedback("Usuario criado com sucesso.");
      await loadData();
    } catch (err) {
      setError(err?.response?.data?.detail || "Falha ao criar usuario.");
    }
  };

  const toggleGroupOnNewUser = (groupId) => {
    const exists = newUser.group_ids.includes(groupId);
    setNewUser({
      ...newUser,
      group_ids: exists ? newUser.group_ids.filter((id) => id !== groupId) : [...newUser.group_ids, groupId],
    });
  };

  const createGroup = async () => {
    setError("");
    setFeedback("");
    try {
      await client.post("/api/access-groups", groupForm);
      setGroupForm({ name: "", description: "" });
      setFeedback("Grupo criado com sucesso.");
      await loadData();
    } catch (err) {
      setError(err?.response?.data?.detail || "Falha ao criar grupo.");
    }
  };

  const resetPassword = async () => {
    if (!passwordForm.userId) return;
    setError("");
    setFeedback("");
    try {
      await client.put(`/api/users/${passwordForm.userId}/password`, { new_password: passwordForm.newPassword });
      setPasswordForm({ userId: "", newPassword: "" });
      setFeedback("Senha alterada com sucesso.");
    } catch (err) {
      setError(err?.response?.data?.detail || "Falha ao alterar senha.");
    }
  };

  const updateDraft = (userId, field, value) => {
    setDrafts((prev) => ({
      ...prev,
      [userId]: {
        ...prev[userId],
        [field]: value,
      },
    }));
  };

  const toggleDraftGroup = (userId, groupId) => {
    const current = drafts[userId] || { group_ids: [] };
    const hasGroup = (current.group_ids || []).includes(groupId);
    updateDraft(
      userId,
      "group_ids",
      hasGroup ? current.group_ids.filter((id) => id !== groupId) : [...(current.group_ids || []), groupId],
    );
  };

  const saveUser = async (userId) => {
    const draft = drafts[userId];
    if (!draft) return;

    setBusyUserId(userId);
    setError("");
    setFeedback("");
    try {
      await client.put(`/api/users/${userId}`, draft);
      setFeedback("Usuario atualizado com sucesso.");
      await loadData();
    } catch (err) {
      setError(err?.response?.data?.detail || "Falha ao atualizar usuario.");
    } finally {
      setBusyUserId(null);
    }
  };

  const deleteUser = async (userId) => {
    const confirmed = window.confirm("Deseja realmente excluir este usuario?");
    if (!confirmed) return;

    setBusyUserId(userId);
    setError("");
    setFeedback("");
    try {
      await client.delete(`/api/users/${userId}`);
      setFeedback("Usuario excluido com sucesso.");
      await loadData();
    } catch (err) {
      setError(err?.response?.data?.detail || "Falha ao excluir usuario.");
    } finally {
      setBusyUserId(null);
    }
  };

  return (
    <main className="mx-auto mt-6 w-[95%] max-w-6xl space-y-4 pb-10">
      {error && <section className="rounded-xl border border-rose-500/30 bg-rose-500/10 px-4 py-2 text-sm text-rose-200">{error}</section>}
      {feedback && <section className="rounded-xl border border-emerald-500/30 bg-emerald-500/10 px-4 py-2 text-sm text-emerald-200">{feedback}</section>}

      <section className="panel p-5">
        <h2 className="text-xl font-semibold">Gestao de Usuarios</h2>
        <div className="mt-3 grid gap-2 md:grid-cols-4">
          <input className="rounded-xl border border-slate-700 bg-slate-950 px-3 py-2" placeholder="email" value={newUser.email} onChange={(e) => setNewUser({ ...newUser, email: e.target.value })} />
          <input type="password" className="rounded-xl border border-slate-700 bg-slate-950 px-3 py-2" placeholder="senha" value={newUser.password} onChange={(e) => setNewUser({ ...newUser, password: e.target.value })} />
          <label className="flex items-center gap-2 text-sm">
            <input type="checkbox" checked={newUser.is_admin} onChange={(e) => setNewUser({ ...newUser, is_admin: e.target.checked })} />
            Administrador
          </label>
          <button onClick={createUser} className="rounded-xl bg-blue-600 px-4 py-2 font-semibold text-white">Criar usuario</button>
        </div>
        <div className="mt-3 flex flex-wrap gap-2 text-sm">
          {groups.map((g) => (
            <label key={g.id} className="flex items-center gap-1 rounded-lg border border-slate-700 px-2 py-1">
              <input type="checkbox" checked={newUser.group_ids.includes(g.id)} onChange={() => toggleGroupOnNewUser(g.id)} />
              {g.name}
            </label>
          ))}
        </div>
      </section>

      <section className="panel p-5">
        <h3 className="text-lg font-semibold">Grupos de Acesso</h3>
        <div className="mt-3 grid gap-2 md:grid-cols-3">
          <input className="rounded-xl border border-slate-700 bg-slate-950 px-3 py-2" placeholder="Nome do grupo" value={groupForm.name} onChange={(e) => setGroupForm({ ...groupForm, name: e.target.value })} />
          <input className="rounded-xl border border-slate-700 bg-slate-950 px-3 py-2" placeholder="Descricao" value={groupForm.description} onChange={(e) => setGroupForm({ ...groupForm, description: e.target.value })} />
          <button onClick={createGroup} className="rounded-xl bg-blue-600 px-4 py-2 font-semibold text-white">Criar grupo</button>
        </div>
        <div className="mt-3 space-y-1 text-sm text-slate-200">
          {groups.map((g) => <p key={g.id}>#{g.id} - {g.name} ({g.description || "sem descricao"})</p>)}
        </div>
      </section>

      <section className="panel p-5">
        <h3 className="text-lg font-semibold">Reset de Senha (Admin)</h3>
        <div className="mt-3 grid gap-2 md:grid-cols-3">
          <select className="rounded-xl border border-slate-700 bg-slate-950 px-3 py-2" value={passwordForm.userId} onChange={(e) => setPasswordForm({ ...passwordForm, userId: e.target.value })}>
            <option value="">Selecione usuario</option>
            {users.map((u) => <option key={u.id} value={u.id}>{u.email}</option>)}
          </select>
          <input type="password" className="rounded-xl border border-slate-700 bg-slate-950 px-3 py-2" placeholder="nova senha" value={passwordForm.newPassword} onChange={(e) => setPasswordForm({ ...passwordForm, newPassword: e.target.value })} />
          <button onClick={resetPassword} className="rounded-xl bg-amber-500 px-4 py-2 font-semibold text-white">Alterar senha</button>
        </div>
      </section>

      <section className="panel p-5">
        <h3 className="text-lg font-semibold">Usuarios</h3>
        <div className="mt-3 space-y-2">
          {users.map((u) => (
            <div key={u.id} className="rounded-xl border border-slate-800 bg-slate-900/70 p-3">
              <div className="grid gap-3 lg:grid-cols-[1.2fr_0.8fr]">
                <div>
                  <label className="text-xs uppercase tracking-[0.2em] text-slate-500">Email</label>
                  <input
                    className="mt-1 w-full rounded-xl border border-slate-700 bg-slate-950 px-3 py-2"
                    value={drafts[u.id]?.email || ""}
                    onChange={(e) => updateDraft(u.id, "email", e.target.value)}
                  />
                  <div className="mt-3 grid gap-2 md:grid-cols-2">
                    <label className="flex items-center gap-2 rounded-xl border border-slate-300 bg-slate-100 px-3 py-2 text-sm text-slate-700">
                      <input
                        type="checkbox"
                        checked={Boolean(drafts[u.id]?.is_admin)}
                        onChange={(e) => updateDraft(u.id, "is_admin", e.target.checked)}
                      />
                      Administrador
                    </label>
                    <label className="flex items-center gap-2 rounded-xl border border-slate-300 bg-slate-100 px-3 py-2 text-sm text-slate-700">
                      <input
                        type="checkbox"
                        checked={Boolean(drafts[u.id]?.is_active)}
                        onChange={(e) => updateDraft(u.id, "is_active", e.target.checked)}
                      />
                      Usuario ativo
                    </label>
                  </div>
                </div>

                <div className="rounded-xl border border-slate-300 bg-slate-100 p-3 text-sm text-slate-700">
                  <p className="font-medium text-slate-800">#{u.id}</p>
                  <p className="mt-1">Estado atual: admin {String(u.is_admin)} | ativo {String(u.is_active)}</p>
                  <p className="mt-1">Grupos atuais: {(u.group_ids || []).join(", ") || "nenhum"}</p>
                </div>
              </div>

              <div className="mt-3 flex flex-wrap gap-2 text-xs">
                {groups.map((g) => (
                  <label key={g.id} className="flex items-center gap-1 rounded-lg border border-slate-300 bg-white px-2 py-1 text-slate-700">
                    <input type="checkbox" checked={(drafts[u.id]?.group_ids || []).includes(g.id)} onChange={() => toggleDraftGroup(u.id, g.id)} />
                    {g.name}
                  </label>
                ))}
              </div>

              <div className="mt-3 flex flex-wrap gap-2">
                <button
                  onClick={() => saveUser(u.id)}
                  disabled={busyUserId === u.id}
                  className="rounded-lg bg-blue-500/15 px-3 py-1.5 text-xs font-semibold text-blue-200 disabled:opacity-50"
                >
                  {busyUserId === u.id ? "Salvando..." : "Salvar alteracoes"}
                </button>
                <button
                  onClick={() => deleteUser(u.id)}
                  disabled={busyUserId === u.id}
                  className="rounded-lg bg-rose-500/20 px-3 py-1.5 text-xs font-semibold text-rose-300 disabled:opacity-50"
                >
                  Excluir usuario
                </button>
              </div>
            </div>
          ))}
        </div>
      </section>
    </main>
  );
}
