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
        { to: "/scan", label: "Scans", adminOnly: true },
        { to: "/agendamento", label: "Schedules", adminOnly: true },
      ],
    },
    {
      title: "Security",
      items: [
        { to: "/vulnerabilidades", label: "Vulnerabilities", adminOnly: false },
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
    <aside className="w-full border-b border-[#cbd5e0] bg-[#1a365d] p-4 md:min-h-screen md:w-72 md:border-b-0 md:border-r">
      <div className="rounded-xl border border-[#2c5282] bg-[#224874] p-4">
        <h1 className="font-display text-xl font-bold tracking-tight text-white">VALID ASM</h1>
        <p className="mt-1 text-xs text-[#dbeafe]">Enterprise Security Platform</p>
      </div>

      <nav className="mt-4 space-y-4">
        {navGroups.map((group) => {
          const visibleItems = group.items.filter((item) => !item.adminOnly || isAdmin);
          if (visibleItems.length === 0) return null;
          return (
            <div key={group.title} className="rounded-xl border border-[#2c5282] bg-[#224874] p-2">
              <p className="px-2 py-1 text-[11px] font-semibold uppercase tracking-[0.12em] text-[#bfdbfe]">{group.title}</p>
              <div className="mt-1 space-y-1">
                {visibleItems.map((item) => (
                  <NavLink
                    key={item.to}
                    to={item.to}
                    className={({ isActive }) =>
                      `block rounded-lg border px-3 py-2 text-sm font-medium transition-all duration-200 ${
                        isActive
                          ? "border-[#63b3ed] bg-[#2c5282] text-white shadow-[0_0_0_1px_rgba(99,179,237,0.5)]"
                          : "border-transparent text-[#e2e8f0] hover:border-[#2c5282] hover:bg-[#2a4f7a]"
                      }`
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
        className="mt-4 w-full rounded-lg border border-[#2c5282] bg-transparent px-3 py-2 text-sm font-medium text-white hover:border-[#63b3ed] hover:text-[#bfdbfe]"
      >
        Sair
      </button>
    </aside>
  );
}
