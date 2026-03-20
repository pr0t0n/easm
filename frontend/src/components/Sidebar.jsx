import { NavLink, useNavigate } from "react-router-dom";
import { authStore } from "../store/auth";

export default function Sidebar() {
  const navigate = useNavigate();
  const me = authStore.me;
  const isAdmin = Boolean(me?.is_admin);

  const menuItems = [
    { to: "/", label: "Dashboard", adminOnly: false },
    { to: "/relatorios", label: "Relatorios", adminOnly: false },
    { to: "/agendamento", label: "Agendamento", adminOnly: true },
    { to: "/scan", label: "Scan", adminOnly: true },
    { to: "/conta", label: "Minha Conta", adminOnly: true },
    { to: "/configuracao", label: "Configuracao", adminOnly: true },
    { to: "/usuarios", label: "Gestao de Usuarios", adminOnly: true },
  ];

  const logout = () => {
    authStore.clear();
    navigate("/login");
  };

  return (
    <aside className="w-full border-b border-slate-800 bg-slate-900/70 p-4 md:min-h-screen md:w-64 md:border-b-0 md:border-r">
      <h1 className="font-display text-2xl font-bold text-brand-500">VALID ASM</h1>
      <p className="mt-1 text-xs text-slate-400">vASM</p>

      <nav className="mt-6 space-y-2">
        {menuItems.filter((item) => !item.adminOnly || isAdmin).map((item) => (
          <NavLink
            key={item.to}
            to={item.to}
            className={({ isActive }) =>
              `block rounded-xl px-3 py-2 text-sm ${isActive ? "bg-brand-500 text-slate-950" : "bg-slate-800/60 text-slate-200"}`
            }
          >
            {item.label}
          </NavLink>
        ))}
      </nav>

      <button
        onClick={logout}
        className="mt-6 w-full rounded-xl border border-rose-400/30 bg-rose-400/10 px-3 py-2 text-sm text-rose-300"
      >
        Sair
      </button>
    </aside>
  );
}
