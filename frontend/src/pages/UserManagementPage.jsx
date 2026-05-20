import { useEffect, useState } from "react";
import client from "../api/client";

const inputStyle = {
  width: "100%", padding: "9px 12px", borderRadius: 8,
  border: "1px solid var(--line)", background: "var(--canvas)",
  fontSize: 13, color: "var(--ink)",
};
const chip = (on) => ({
  display: "inline-flex", alignItems: "center", gap: 6,
  padding: "5px 10px", borderRadius: 6, fontSize: 12, cursor: "pointer",
  border: `1px solid ${on ? "var(--brand-500)" : "var(--line)"}`,
  background: on ? "rgba(233,99,99,0.08)" : "var(--surface)",
  color: on ? "var(--brand-700)" : "var(--ink-soft)",
});

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
      setFeedback("Usuário criado com sucesso.");
      await loadData();
    } catch (err) {
      setError(err?.response?.data?.detail || "Falha ao criar usuário.");
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
    setDrafts((prev) => ({ ...prev, [userId]: { ...prev[userId], [field]: value } }));
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
      setFeedback("Usuário atualizado com sucesso.");
      await loadData();
    } catch (err) {
      setError(err?.response?.data?.detail || "Falha ao atualizar usuário.");
    } finally {
      setBusyUserId(null);
    }
  };

  const deleteUser = async (userId) => {
    if (!window.confirm("Deseja realmente excluir este usuário?")) return;
    setBusyUserId(userId);
    setError("");
    setFeedback("");
    try {
      await client.delete(`/api/users/${userId}`);
      setFeedback("Usuário excluído com sucesso.");
      await loadData();
    } catch (err) {
      setError(err?.response?.data?.detail || "Falha ao excluir usuário.");
    } finally {
      setBusyUserId(null);
    }
  };

  return (
    <main className="dpage">
      <div className="page-intro">
        <h2>Usuários e grupos.</h2>
        <div className="sub">identidades, grupos de acesso e permissões</div>
      </div>

      {error && <div className="err-box" style={{ marginBottom: 14 }}>{error}</div>}
      {feedback && (
        <div style={{ marginBottom: 14, padding: "10px 14px", borderRadius: 9, fontSize: 13, border: "1px solid var(--sev-low-border)", background: "var(--sev-low-bg)", color: "var(--sev-low-text)" }}>
          {feedback}
        </div>
      )}

      <div className="grid-2" style={{ marginBottom: 16 }}>
        <section className="card">
          <div className="card-h"><div><h3>Novo usuário</h3><div className="sub">cadastro restrito a administradores</div></div></div>
          <div style={{ display: "grid", gap: 10 }}>
            <input style={inputStyle} placeholder="email" value={newUser.email} onChange={(e) => setNewUser({ ...newUser, email: e.target.value })} />
            <input type="password" style={inputStyle} placeholder="senha" value={newUser.password} onChange={(e) => setNewUser({ ...newUser, password: e.target.value })} />
            <label style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 13, color: "var(--ink-soft)" }}>
              <input type="checkbox" checked={newUser.is_admin} onChange={(e) => setNewUser({ ...newUser, is_admin: e.target.checked })} />
              Administrador
            </label>
            <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
              {groups.map((g) => (
                <span key={g.id} style={chip(newUser.group_ids.includes(g.id))} onClick={() => toggleGroupOnNewUser(g.id)}>{g.name}</span>
              ))}
            </div>
            <button className="btn btn-primary" onClick={createUser}>Criar usuário</button>
          </div>
        </section>

        <section className="card">
          <div className="card-h"><div><h3>Grupos de acesso</h3><div className="sub">segmentação por cliente</div></div></div>
          <div style={{ display: "grid", gap: 10 }}>
            <input style={inputStyle} placeholder="Nome do grupo" value={groupForm.name} onChange={(e) => setGroupForm({ ...groupForm, name: e.target.value })} />
            <input style={inputStyle} placeholder="Descrição" value={groupForm.description} onChange={(e) => setGroupForm({ ...groupForm, description: e.target.value })} />
            <button className="btn btn-primary" onClick={createGroup}>Criar grupo</button>
          </div>
          <div className="divider-h" />
          <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
            {groups.map((g) => (
              <div key={g.id} className="mono-sm" style={{ color: "var(--ink-soft)" }}>
                #{g.id} · <b style={{ color: "var(--ink)" }}>{g.name}</b> — {g.description || "sem descrição"}
              </div>
            ))}
          </div>
        </section>
      </div>

      <section className="card" style={{ marginBottom: 16 }}>
        <div className="card-h"><div><h3>Reset de senha</h3><div className="sub">ação administrativa</div></div></div>
        <div style={{ display: "grid", gap: 10, gridTemplateColumns: "1fr 1fr auto" }}>
          <select style={inputStyle} value={passwordForm.userId} onChange={(e) => setPasswordForm({ ...passwordForm, userId: e.target.value })}>
            <option value="">Selecione o usuário</option>
            {users.map((u) => <option key={u.id} value={u.id}>{u.email}</option>)}
          </select>
          <input type="password" style={inputStyle} placeholder="nova senha" value={passwordForm.newPassword} onChange={(e) => setPasswordForm({ ...passwordForm, newPassword: e.target.value })} />
          <button className="btn btn-ghost" onClick={resetPassword}>Alterar senha</button>
        </div>
      </section>

      <section className="t-wrap">
        <div className="t-head"><div><h3>Usuários</h3><div className="sub">{users.length} identidades</div></div></div>
        <div>
          {users.map((u) => (
            <div key={u.id} style={{ padding: "16px 22px", borderBottom: "1px solid var(--line-soft)" }}>
              <div style={{ display: "grid", gap: 14, gridTemplateColumns: "1.3fr 0.7fr" }}>
                <div>
                  <label className="mono-sm muted" style={{ display: "block", marginBottom: 4 }}>Email</label>
                  <input style={inputStyle} value={drafts[u.id]?.email || ""} onChange={(e) => updateDraft(u.id, "email", e.target.value)} />
                  <div style={{ display: "flex", gap: 16, marginTop: 10 }}>
                    <label style={{ display: "flex", alignItems: "center", gap: 7, fontSize: 13, color: "var(--ink-soft)" }}>
                      <input type="checkbox" checked={Boolean(drafts[u.id]?.is_admin)} onChange={(e) => updateDraft(u.id, "is_admin", e.target.checked)} />
                      Administrador
                    </label>
                    <label style={{ display: "flex", alignItems: "center", gap: 7, fontSize: 13, color: "var(--ink-soft)" }}>
                      <input type="checkbox" checked={Boolean(drafts[u.id]?.is_active)} onChange={(e) => updateDraft(u.id, "is_active", e.target.checked)} />
                      Usuário ativo
                    </label>
                  </div>
                  <div style={{ display: "flex", flexWrap: "wrap", gap: 6, marginTop: 10 }}>
                    {groups.map((g) => (
                      <span key={g.id} style={chip((drafts[u.id]?.group_ids || []).includes(g.id))} onClick={() => toggleDraftGroup(u.id, g.id)}>{g.name}</span>
                    ))}
                  </div>
                </div>
                <div className="card-soft" style={{ fontSize: 12.5, color: "var(--ink-soft)" }}>
                  <p style={{ fontWeight: 600, color: "var(--ink)" }}>#{u.id}</p>
                  <p style={{ marginTop: 4 }}>admin {String(u.is_admin)} · ativo {String(u.is_active)}</p>
                  <p style={{ marginTop: 4 }}>grupos: {(u.group_ids || []).join(", ") || "nenhum"}</p>
                </div>
              </div>
              <div style={{ display: "flex", gap: 8, marginTop: 12 }}>
                <button className="btn btn-primary" style={{ padding: "6px 12px", fontSize: 12 }} onClick={() => saveUser(u.id)} disabled={busyUserId === u.id}>
                  {busyUserId === u.id ? "Salvando…" : "Salvar alterações"}
                </button>
                <button className="btn btn-danger" style={{ padding: "6px 12px", fontSize: 12 }} onClick={() => deleteUser(u.id)} disabled={busyUserId === u.id}>
                  Excluir
                </button>
              </div>
            </div>
          ))}
        </div>
      </section>
    </main>
  );
}
