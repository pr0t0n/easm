import { useEffect, useState } from "react";
import client from "../api/client";

export default function UserManagementPage() {
  const [users, setUsers] = useState([]);
  const [groups, setGroups] = useState([]);
  const [newUser, setNewUser] = useState({ email: "", password: "", is_admin: false, group_ids: [] });
  const [passwordForm, setPasswordForm] = useState({ userId: "", newPassword: "" });
  const [groupForm, setGroupForm] = useState({ name: "", description: "" });

  const loadData = async () => {
    const [usersRes, groupsRes] = await Promise.all([client.get("/api/users"), client.get("/api/access-groups")]);
    setUsers(usersRes.data);
    setGroups(groupsRes.data);
  };

  useEffect(() => {
    loadData();
  }, []);

  const createUser = async () => {
    await client.post("/api/users", newUser);
    setNewUser({ email: "", password: "", is_admin: false, group_ids: [] });
    await loadData();
  };

  const toggleGroupOnNewUser = (groupId) => {
    const exists = newUser.group_ids.includes(groupId);
    setNewUser({
      ...newUser,
      group_ids: exists ? newUser.group_ids.filter((id) => id !== groupId) : [...newUser.group_ids, groupId],
    });
  };

  const createGroup = async () => {
    await client.post("/api/access-groups", groupForm);
    setGroupForm({ name: "", description: "" });
    await loadData();
  };

  const resetPassword = async () => {
    if (!passwordForm.userId) return;
    await client.put(`/api/users/${passwordForm.userId}/password`, { new_password: passwordForm.newPassword });
    setPasswordForm({ userId: "", newPassword: "" });
  };

  const toggleAdmin = async (user) => {
    await client.put(`/api/users/${user.id}`, { is_admin: !user.is_admin, group_ids: user.group_ids, is_active: user.is_active });
    await loadData();
  };

  const updateUserGroups = async (user, groupId) => {
    const hasGroup = (user.group_ids || []).includes(groupId);
    const group_ids = hasGroup ? user.group_ids.filter((id) => id !== groupId) : [...(user.group_ids || []), groupId];
    await client.put(`/api/users/${user.id}`, { is_admin: user.is_admin, is_active: user.is_active, group_ids });
    await loadData();
  };

  return (
    <main className="mx-auto mt-6 w-[95%] max-w-6xl space-y-4 pb-10">
      <section className="panel p-5">
        <h2 className="text-xl font-semibold">Gestao de Usuarios</h2>
        <div className="mt-3 grid gap-2 md:grid-cols-4">
          <input className="rounded-xl border border-slate-700 bg-slate-950 px-3 py-2" placeholder="email" value={newUser.email} onChange={(e) => setNewUser({ ...newUser, email: e.target.value })} />
          <input type="password" className="rounded-xl border border-slate-700 bg-slate-950 px-3 py-2" placeholder="senha" value={newUser.password} onChange={(e) => setNewUser({ ...newUser, password: e.target.value })} />
          <label className="flex items-center gap-2 text-sm">
            <input type="checkbox" checked={newUser.is_admin} onChange={(e) => setNewUser({ ...newUser, is_admin: e.target.checked })} />
            Administrador
          </label>
          <button onClick={createUser} className="rounded-xl bg-brand-500 px-4 py-2 font-semibold text-slate-950">Criar usuario</button>
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
          <button onClick={createGroup} className="rounded-xl bg-cyan-500 px-4 py-2 font-semibold text-slate-950">Criar grupo</button>
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
          <button onClick={resetPassword} className="rounded-xl bg-amber-500 px-4 py-2 font-semibold text-slate-950">Alterar senha</button>
        </div>
      </section>

      <section className="panel p-5">
        <h3 className="text-lg font-semibold">Usuarios</h3>
        <div className="mt-3 space-y-2">
          {users.map((u) => (
            <div key={u.id} className="rounded-xl border border-slate-800 bg-slate-900/70 p-3">
              <p className="font-medium">{u.email}</p>
              <p className="text-xs text-slate-300">admin: {String(u.is_admin)} | ativo: {String(u.is_active)} | grupos: {(u.group_ids || []).join(",") || "nenhum"}</p>
              <button onClick={() => toggleAdmin(u)} className="mt-2 rounded-lg bg-cyan-500/20 px-2 py-1 text-xs text-cyan-300">Alternar admin</button>
              <div className="mt-2 flex flex-wrap gap-2 text-xs">
                {groups.map((g) => (
                  <label key={g.id} className="flex items-center gap-1 rounded-lg border border-slate-700 px-2 py-1">
                    <input type="checkbox" checked={(u.group_ids || []).includes(g.id)} onChange={() => updateUserGroups(u, g.id)} />
                    {g.name}
                  </label>
                ))}
              </div>
            </div>
          ))}
        </div>
      </section>
    </main>
  );
}
