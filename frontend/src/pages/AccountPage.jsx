import { useState } from "react";
import client from "../api/client";

export default function AccountPage() {
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [message, setMessage] = useState("");

  const submit = async (e) => {
    e.preventDefault();
    await client.put("/api/users/me/password", {
      current_password: currentPassword,
      new_password: newPassword,
    });
    setCurrentPassword("");
    setNewPassword("");
    setMessage("Senha alterada com sucesso.");
  };

  return (
    <main className="mx-auto mt-6 w-[95%] max-w-3xl pb-10">
      <section className="panel p-5">
        <h2 className="text-xl font-semibold">Minha Conta</h2>
        <p className="mt-1 text-sm text-slate-300">Altere sua propria senha.</p>
        <form onSubmit={submit} className="mt-4 space-y-3">
          <input
            type="password"
            className="w-full rounded-xl border border-slate-700 bg-slate-950 px-3 py-2"
            placeholder="Senha atual"
            value={currentPassword}
            onChange={(e) => setCurrentPassword(e.target.value)}
          />
          <input
            type="password"
            className="w-full rounded-xl border border-slate-700 bg-slate-950 px-3 py-2"
            placeholder="Nova senha"
            value={newPassword}
            onChange={(e) => setNewPassword(e.target.value)}
          />
          <button className="rounded-xl bg-blue-600 px-4 py-2 font-semibold text-white">Salvar senha</button>
        </form>
        {message && <p className="mt-3 text-sm text-emerald-300">{message}</p>}
      </section>
    </main>
  );
}
