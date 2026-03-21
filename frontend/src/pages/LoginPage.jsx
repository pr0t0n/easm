import { useState } from "react";
import { useNavigate } from "react-router-dom";
import client from "../api/client";
import { authStore } from "../store/auth";

export default function LoginPage() {
  const navigate = useNavigate();
  const [mode, setMode] = useState("login");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");

  const submit = async (e) => {
    e.preventDefault();
    const path = mode === "login" ? "/api/auth/login" : "/api/auth/register";
    const { data } = await client.post(path, { email, password });
    authStore.setToken(data.access_token);
    if (data.refresh_token) {
      localStorage.setItem("refresh_token", data.refresh_token);
    }
    const me = await client.get("/api/auth/me");
    authStore.setMe(me.data);
    navigate("/");
  };

  return (
    <main className="mx-auto flex min-h-screen max-w-md items-center px-4">
      <form onSubmit={submit} className="panel w-full p-6">
        <h1 className="font-display text-2xl font-bold">Acesso Seguro</h1>
        <p className="mt-2 text-sm text-slate-300">Autentique para iniciar e acompanhar scans na plataforma VALID ASM - vASM.</p>

        <input
          className="mt-6 w-full rounded-xl border border-slate-700 bg-slate-950 px-3 py-2"
          placeholder="email"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
        />
        <input
          type="password"
          className="mt-3 w-full rounded-xl border border-slate-700 bg-slate-950 px-3 py-2"
          placeholder="senha"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
        />

        <button className="mt-6 w-full rounded-xl bg-brand-500 px-4 py-2 font-semibold text-slate-950">
          {mode === "login" ? "Entrar" : "Criar Conta"}
        </button>

        <button
          type="button"
          className="mt-3 text-sm text-sky-300"
          onClick={() => setMode(mode === "login" ? "register" : "login")}
        >
          {mode === "login" ? "Nao tem conta? Registrar" : "Ja tem conta? Entrar"}
        </button>
      </form>
    </main>
  );
}
