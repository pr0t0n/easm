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
        { to: "/relatorios", label: "Relatórios", adminOnly: false },
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
    <aside className="sb">
      <div className="sb-logo">
        <span className="sb-logo-mark" aria-hidden />
        <div>
          <span className="sb-logo-name">Pentest.io</span>
          <span className="sb-logo-tag">Enterprise Security</span>
        </div>
      </div>

      {navGroups.map((group) => {
        const visibleItems = group.items.filter((item) => !item.adminOnly || isAdmin);
        if (visibleItems.length === 0) return null;
        return (
          <div key={group.title}>
            <div className="sb-group">{group.title}</div>
            {visibleItems.map((item) => (
              <NavLink
                key={item.to}
                to={item.to}
                end={item.to === "/"}
                className={({ isActive }) => `sb-item${isActive ? " active" : ""}`}
              >
                <span className="sb-item-dot" aria-hidden />
                {item.label}
              </NavLink>
            ))}
          </div>
        );
      })}

      <div className="sb-foot">
        <strong>{me?.email || "—"}</strong>
        {isAdmin ? "Admin · acesso total" : "Operador"}
        <button
          onClick={logout}
          style={{
            marginTop: 10,
            display: "block",
            width: "100%",
            padding: "8px 12px",
            borderRadius: 8,
            border: "1px solid var(--sidebar-border)",
            background: "transparent",
            color: "var(--sidebar-muted)",
            fontSize: 12,
            fontWeight: 500,
            cursor: "pointer",
          }}
          onMouseEnter={(e) => {
            e.currentTarget.style.background = "var(--sidebar-hover-bg)";
            e.currentTarget.style.color = "#ffffff";
          }}
          onMouseLeave={(e) => {
            e.currentTarget.style.background = "transparent";
            e.currentTarget.style.color = "var(--sidebar-muted)";
          }}
        >
          Sair
        </button>
      </div>
    </aside>
  );
}
