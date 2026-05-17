import { useState } from "react";
import client from "../api/client";
import { authStore } from "../store/auth";

export default function AccountPage() {
  const me = authStore.me;
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");

  const submit = async (e) => {
    e.preventDefault();
    setMessage("");
    setError("");
    try {
      await client.put("/api/users/me/password", {
        current_password: currentPassword,
        new_password: newPassword,
      });
      setCurrentPassword("");
      setNewPassword("");
      setMessage("Senha alterada com sucesso.");
    } catch (err) {
      setError(err?.response?.data?.detail || "Falha ao alterar senha.");
    }
  };

  const inputStyle = {
    width: "100%", padding: "10px 13px", borderRadius: 9,
    border: "1px solid var(--line)", background: "var(--canvas)",
    fontSize: 13.5, color: "var(--ink)", marginBottom: 10,
  };

  return (
    <main className="dpage" style={{ maxWidth: 720, margin: "0 auto" }}>
      <div className="page-intro">
        <h2>Minha conta.</h2>
        <div className="sub">dados de perfil e troca de senha</div>
      </div>

      <section className="grid-2" style={{ marginBottom: 16 }}>
        <div className="kpi">
          <div className="k">Identidade</div>
          <div className="v" style={{ fontSize: 18, marginTop: 10 }}>{me?.email || "—"}</div>
          <div className="hint">{me?.is_admin ? "Admin · acesso total" : "Operador"}</div>
        </div>
        <div className="kpi">
          <div className="k">Sessão</div>
          <div className="v" style={{ fontSize: 18, marginTop: 10 }}>Auditada</div>
          <div className="hint">todas as ações desta sessão são registradas</div>
        </div>
      </section>

      <section className="card">
        <div className="card-h"><div><h3>Trocar senha</h3><div className="sub">defina uma nova senha de acesso</div></div></div>
        <form onSubmit={submit}>
          <input type="password" style={inputStyle} placeholder="Senha atual" value={currentPassword} onChange={(e) => setCurrentPassword(e.target.value)} />
          <input type="password" style={inputStyle} placeholder="Nova senha" value={newPassword} onChange={(e) => setNewPassword(e.target.value)} />
          <button className="btn btn-primary" type="submit">Salvar senha</button>
        </form>
        {message && (
          <div style={{ marginTop: 14, padding: "10px 13px", borderRadius: 9, fontSize: 13, border: "1px solid var(--sev-low-border)", background: "var(--sev-low-bg)", color: "var(--sev-low-text)" }}>
            {message}
          </div>
        )}
        {error && <div className="err-box" style={{ marginTop: 14 }}>{error}</div>}
      </section>
    </main>
  );
}
