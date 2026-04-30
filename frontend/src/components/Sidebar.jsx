import { NavLink, useNavigate } from "react-router-dom";
import { authStore } from "../store/auth";

export default function Sidebar() {
  const navigate = useNavigate();
  const me = authStore.me;
  const isAdmin = Boolean(me?.is_admin);

  const navGroups = [
    {
      title: "Overview",
      items: [{ to: "/", label: "Dashboard", adminOnly: false }],
    },
    {
      title: "Pentest",
      items: [
        { to: "/targets", label: "Targets", adminOnly: false },
        { to: "/scan", label: "Scans", adminOnly: true },
        { to: "/phase-monitor", label: "Phase Monitor", adminOnly: true },
        { to: "/agendamento", label: "Schedules", adminOnly: true },
      ],
    },
    {
      title: "Security",
      items: [
        { to: "/vulnerabilidades", label: "Vulnerabilities", adminOnly: false },
        { to: "/evolucao", label: "Attack Evolution", adminOnly: false },
        { to: "/relatorios", label: "Reports", adminOnly: false },
      ],
    },
    {
      title: "Management",
      items: [
        { to: "/ferramentas", label: "Tools", adminOnly: true },
        { to: "/workers", label: "Workers", adminOnly: true },
        { to: "/jobs", label: "Jobs Registry", adminOnly: true },
        { to: "/worker-logs", label: "Worker Logs", adminOnly: true },
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
    <aside
      className="w-full p-4 md:min-h-screen md:w-72 md:border-b-0 md:border-r"
      style={{
        background: "var(--sidebar-bg)",
        borderColor: "var(--sidebar-border)",
        borderBottomWidth: 1,
        borderRightWidth: 1,
      }}
    >
      <div
        className="rounded-xl p-4"
        style={{
          background: "var(--bg-muted)",
          border: "1px solid var(--border)",
        }}
      >
        <div className="flex items-center gap-2">
          <span
            style={{
              width: 8,
              height: 8,
              borderRadius: 999,
              background: "var(--primary)",
              display: "inline-block",
            }}
          />
          <h1
            className="font-display text-xl font-bold tracking-tight"
            style={{ color: "var(--text-primary)" }}
          >
            Pentest.io
          </h1>
        </div>
        <p className="mt-1 text-xs" style={{ color: "var(--text-tertiary)" }}>
          Enterprise Security Platform
        </p>
      </div>

      <nav className="mt-4 space-y-4">
        {navGroups.map((group) => {
          const visibleItems = group.items.filter((item) => !item.adminOnly || isAdmin);
          if (visibleItems.length === 0) return null;
          return (
            <div key={group.title}>
              <p
                className="px-2 py-1 text-[11px] font-semibold uppercase tracking-[0.12em]"
                style={{ color: "var(--text-tertiary)" }}
              >
                {group.title}
              </p>
              <div className="mt-1 space-y-1">
                {visibleItems.map((item) => (
                  <NavLink
                    key={item.to}
                    to={item.to}
                    style={({ isActive }) =>
                      isActive
                        ? {
                            display: "block",
                            borderRadius: 8,
                            border: "1px solid transparent",
                            padding: "8px 12px",
                            fontSize: 14,
                            fontWeight: 500,
                            background: "rgba(254,123,2,0.10)",
                            color: "var(--primary)",
                            borderColor: "rgba(254,123,2,0.25)",
                          }
                        : {
                            display: "block",
                            borderRadius: 8,
                            border: "1px solid transparent",
                            padding: "8px 12px",
                            fontSize: 14,
                            fontWeight: 500,
                            color: "var(--text-secondary)",
                            background: "transparent",
                          }
                    }
                    onMouseEnter={(e) => {
                      if (!e.currentTarget.style.color.includes("254")) {
                        e.currentTarget.style.background = "var(--bg-muted)";
                        e.currentTarget.style.color = "var(--text-primary)";
                      }
                    }}
                    onMouseLeave={(e) => {
                      if (!e.currentTarget.style.color.includes("254")) {
                        e.currentTarget.style.background = "transparent";
                        e.currentTarget.style.color = "var(--text-secondary)";
                      }
                    }}
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
        className="mt-6 w-full rounded-lg px-3 py-2 text-sm font-medium"
        style={{
          background: "transparent",
          border: "1px solid var(--border)",
          color: "var(--text-secondary)",
        }}
        onMouseEnter={(e) => {
          e.currentTarget.style.borderColor = "var(--primary)";
          e.currentTarget.style.color = "var(--text-primary)";
          e.currentTarget.style.background = "var(--bg-muted)";
        }}
        onMouseLeave={(e) => {
          e.currentTarget.style.borderColor = "var(--border)";
          e.currentTarget.style.color = "var(--text-secondary)";
          e.currentTarget.style.background = "transparent";
        }}
      >
        Sair
      </button>
    </aside>
  );
}
