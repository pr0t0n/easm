import { NavLink, useNavigate } from "react-router-dom";
import { authStore } from "../store/auth";

/* ── Ícones Lucide-style (inline SVG, sem dependência) ───────────────────── */
const svg = (children) => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round">
    {children}
  </svg>
);

const ICONS = {
  dashboard: svg(<><path d="m12 14 4-4" /><path d="M3.34 19a10 10 0 1 1 17.32 0" /></>),
  target: svg(<><circle cx="12" cy="12" r="10" /><circle cx="12" cy="12" r="6" /><circle cx="12" cy="12" r="2" /></>),
  scans: svg(<><path d="M19.07 4.93A10 10 0 0 0 6.99 3.34" /><path d="M4 6h.01" /><path d="M2.29 9.62A10 10 0 1 0 21.31 8.35" /><path d="M16.24 7.76A6 6 0 1 0 8.23 16.67" /><path d="M12 18h.01" /><path d="M17.99 11.66A6 6 0 0 1 15.77 16.67" /><circle cx="12" cy="12" r="2" /><path d="m13.41 10.59 5.66-5.66" /></>),
  operations: svg(<path d="M22 12h-2.48a2 2 0 0 0-1.93 1.46l-2.35 8.36a.25.25 0 0 1-.48 0L9.24 2.18a.25.25 0 0 0-.48 0l-2.35 8.36A2 2 0 0 1 4.49 12H2" />),
  bug: svg(<><path d="m8 2 1.88 1.88" /><path d="M14.12 3.88 16 2" /><path d="M9 7.13v-1a3 3 0 1 1 6 0v1" /><path d="M12 20c-3.3 0-6-2.7-6-6v-3a4 4 0 0 1 4-4h4a4 4 0 0 1 4 4v3c0 3.3-2.7 6-6 6Z" /><path d="M12 20v-9" /><path d="M6.5 9C4.6 8.8 3 7.1 3 5" /><path d="M6 13H2" /><path d="M3 21c0-2.1 1.7-3.9 3.8-4" /><path d="M20.97 5c0 2.1-1.6 3.8-3.5 4" /><path d="M22 13h-4" /><path d="M17.2 17c2.1.1 3.8 1.9 3.8 4" /></>),
  domains: svg(<><circle cx="12" cy="12" r="10" /><path d="M2 12h20" /><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10Z" /></>),
  learning: svg(<><path d="M12 5a3 3 0 1 0-5.997.125 4 4 0 0 0-2.526 5.77 4 4 0 0 0 .556 6.588A4 4 0 1 0 12 18Z" /><path d="M12 5a3 3 0 1 1 5.997.125 4 4 0 0 1 2.526 5.77 4 4 0 0 1-.556 6.588A4 4 0 1 1 12 18Z" /></>),
  report: svg(<><path d="M15 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7Z" /><path d="M14 2v4a2 2 0 0 0 2 2h4" /><path d="M16 13H8" /><path d="M16 17H8" /><path d="M10 9H8" /></>),
  users: svg(<><path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2" /><circle cx="9" cy="7" r="4" /><path d="M22 21v-2a4 4 0 0 0-3-3.87" /><path d="M16 3.13a4 4 0 0 1 0 7.75" /></>),
  account: svg(<><circle cx="10" cy="8" r="4" /><path d="M10.3 15H7a4 4 0 0 0-4 4v2" /><circle cx="18" cy="17.5" r="2.5" /><path d="M18 14v1M18 20v1M21 17.5h-1M16 17.5h-1M20.1 15.4l-.7.7M16.6 18.9l-.7.7M20.1 19.6l-.7-.7M16.6 16.1l-.7-.7" /></>),
  shield: svg(<><path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z" /><path d="m9 12 2 2 4-4" /></>),
};

export default function Sidebar() {
  const navigate = useNavigate();
  const me = authStore.me;
  const isAdmin = Boolean(me?.is_admin);

  const navGroups = [
    {
      title: "Overview",
      items: [{ to: "/", label: "Início", icon: "dashboard", adminOnly: false }],
    },
    {
      title: "Vulnerability Ops",
      items: [
        { to: "/scan", label: "Scan", icon: "scans", adminOnly: true },
        { to: "/operacional", label: "Centro Operacional", icon: "operations", adminOnly: true },
      ],
    },
    {
      title: "Security",
      items: [
        { to: "/vulnerabilidades", label: "Vulnerabilidades", icon: "bug", adminOnly: false },
        { to: "/dominios", label: "Domínios", icon: "domains", adminOnly: false },
        { to: "/aprendizado", label: "Aprendizado", icon: "learning", adminOnly: true },
        { to: "/relatorios", label: "Relatórios", icon: "report", adminOnly: false },
      ],
    },
    {
      title: "Admin",
      items: [
        { to: "/usuarios", label: "Usuários", icon: "users", adminOnly: true },
        { to: "/guardrails", label: "Guardrails", icon: "shield", adminOnly: true },
        { to: "/conta", label: "Minha Conta", icon: "account", adminOnly: true },
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
          <span className="sb-logo-name">ScriptKidd.o</span>
          <span className="sb-logo-tag">Vulnerability Analysis</span>
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
                <span className="sb-ico" aria-hidden>{ICONS[item.icon]}</span>
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
