import { NavLink, useNavigate } from "react-router-dom";
import { authStore } from "../store/auth";

export default function Sidebar() {
  const navigate = useNavigate();
  const me = authStore.me;
  const isAdmin = Boolean(me?.is_admin);

  const navGroups = [
    {
      title: "Overview",
      items: [
        { to: "/", label: "Dashboard", adminOnly: false },
      ],
    },
    {
      title: "Attack Surface",
      items: [
        { to: "/targets", label: "Targets", adminOnly: false },
        { to: "/assets", label: "Assets", adminOnly: false },
        { to: "/scan", label: "Scans", adminOnly: true },
        { to: "/agendamento", label: "Schedules", adminOnly: true },
      ],
    },
    {
      title: "Security",
      items: [
        { to: "/vulnerabilidades", label: "Vulnerabilities", adminOnly: false },
        { to: "/issues", label: "Issues", adminOnly: false },
        { to: "/relatorios", label: "Reports", adminOnly: false },
      ],
    },
    {
      title: "Management",
      items: [
        { to: "/ferramentas", label: "Tools", adminOnly: true },
        { to: "/workers", label: "Workers", adminOnly: true },
        { to: "/jobs", label: "Jobs Registry", adminOnly: true },
        { to: "/configuracao", label: "Settings", adminOnly: true },
      ],
    },
    {
      title: "Admin",
      items: [
        { to: "/usuarios", label: "Users", adminOnly: true },
        { to: "/conta", label: "My Account", adminOnly: true },
      ],
    },
  ];

  const logout = () => {
    authStore.clear();
    navigate("/login");
  };

  return (
    <aside className="w-full border-b border-slate-800 bg-slate-900/70 p-4 md:min-h-screen md:w-72 md:border-b-0 md:border-r">
      <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-3">
        <h1 className="font-display text-2xl font-bold text-brand-500">VALID ASM</h1>
        <p className="mt-1 text-xs text-slate-400">Open Attack Surface Console</p>
      </div>

      <nav className="mt-4 space-y-4">
        {navGroups.map((group) => {
          const visibleItems = group.items.filter((item) => !item.adminOnly || isAdmin);
          if (visibleItems.length === 0) return null;
          return (
            <div key={group.title} className="rounded-xl border border-slate-800 bg-slate-950/50 p-2">
              <p className="px-2 py-1 text-[11px] font-semibold uppercase tracking-wider text-slate-400">{group.title}</p>
              <div className="mt-1 space-y-1">
                {visibleItems.map((item) => (
                  <NavLink
                    key={item.to}
                    to={item.to}
                    className={({ isActive }) =>
                      `block rounded-lg px-3 py-2 text-sm ${isActive ? "bg-brand-500 text-slate-950" : "text-slate-200 hover:bg-slate-800/70"}`
                    }
                  >
                    {item.label}
                  </NavLink>
                ))}
              </div>
            </div>
          );
        })}
      </nav>

      <button
        onClick={logout}
        className="mt-4 w-full rounded-xl border border-rose-400/30 bg-rose-400/10 px-3 py-2 text-sm text-rose-300"
      >
        Sair
      </button>
    </aside>
  );
}
