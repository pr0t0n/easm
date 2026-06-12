import { NavLink, useNavigate, useLocation } from "react-router-dom";
import { authStore } from "../store/auth";

const svg = (children) => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" style={{ width: 17, height: 17, flex: "none" }}>
    {children}
  </svg>
);

const ICONS = {
  cockpit:     svg(<><path d="m12 14 4-4" /><path d="M3.34 19a10 10 0 1 1 17.32 0" /></>),
  superficie:  svg(<><circle cx="12" cy="12" r="10" /><path d="M2 12h20" /><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10Z" /></>),
  joias:       svg(<><path d="m2 6 4 12h12l4-12-5.5 5L12 5l-4.5 6L2 6Z" /><path d="M6 18h12" /></>),
  vulns:       svg(<><path d="m8 2 1.88 1.88" /><path d="M14.12 3.88 16 2" /><path d="M9 7.13v-1a3 3 0 1 1 6 0v1" /><path d="M12 20c-3.3 0-6-2.7-6-6v-3a4 4 0 0 1 4-4h4a4 4 0 0 1 4 4v3c0 3.3-2.7 6-6 6Z" /><path d="M12 20v-9" /><path d="M6 13H2" /><path d="M22 13h-4" /></>),
  scans:       svg(<><path d="M19.07 4.93A10 10 0 0 0 6.99 3.34" /><path d="M4 6h.01" /><path d="M2.29 9.62A10 10 0 1 0 21.31 8.35" /><path d="M16.24 7.76A6 6 0 1 0 8.23 16.67" /><circle cx="12" cy="12" r="2" /><path d="m13.41 10.59 5.66-5.66" /></>),
  operacional: svg(<path d="M22 12h-2.48a2 2 0 0 0-1.93 1.46l-2.35 8.36a.25.25 0 0 1-.48 0L9.24 2.18a.25.25 0 0 0-.48 0l-2.35 8.36A2 2 0 0 1 4.49 12H2" />),
  relatorios:  svg(<><path d="M15 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7Z" /><path d="M14 2v4a2 2 0 0 0 2 2h4" /><path d="M16 13H8" /><path d="M16 17H8" /></>),
  usuarios:    svg(<><path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2" /><circle cx="9" cy="7" r="4" /><path d="M22 21v-2a4 4 0 0 0-3-3.87" /><path d="M16 3.13a4 4 0 0 1 0 7.75" /></>),
  guardrails:  svg(<><path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z" /><path d="m9 12 2 2 4-4" /></>),
  settings:    svg(<><path d="M12.22 2h-.44a2 2 0 0 0-2 2v.18a2 2 0 0 1-1 1.73l-.43.25a2 2 0 0 1-2 0l-.15-.08a2 2 0 0 0-2.73.73l-.22.38a2 2 0 0 0 .73 2.73l.15.1a2 2 0 0 1 1 1.72v.51a2 2 0 0 1-1 1.74l-.15.09a2 2 0 0 0-.73 2.73l.22.38a2 2 0 0 0 2.73.73l.15-.08a2 2 0 0 1 2 0l.43.25a2 2 0 0 1 1 1.73V20a2 2 0 0 0 2 2h.44a2 2 0 0 0 2-2v-.18a2 2 0 0 1 1-1.73l.43-.25a2 2 0 0 1 2 0l.15.08a2 2 0 0 0 2.73-.73l.22-.39a2 2 0 0 0-.73-2.73l-.15-.08a2 2 0 0 1-1-1.74v-.5a2 2 0 0 1 1-1.74l.15-.09a2 2 0 0 0 .73-2.73l-.22-.38a2 2 0 0 0-2.73-.73l-.15.08a2 2 0 0 1-2 0l-.43-.25a2 2 0 0 1-1-1.73V4a2 2 0 0 0-2-2z" /><circle cx="12" cy="12" r="3" /></>),
  learning:    svg(<><path d="M12 5a3 3 0 1 0-5.997.125 4 4 0 0 0-2.526 5.77 4 4 0 0 0 .556 6.588A4 4 0 1 0 12 18Z" /><path d="M12 5a3 3 0 1 1 5.997.125 4 4 0 0 1 2.526 5.77 4 4 0 0 1-.556 6.588A4 4 0 1 1 12 18Z" /></>),
  logs:        svg(<><polyline points="4 17 10 11 4 5" /><line x1="12" y1="19" x2="20" y2="19" /></>),
};

const NAV_GROUPS = [
  {
    grupo: "Comando",
    itens: [
      { to: "/", label: "Cockpit", icon: "cockpit", end: true },
    ],
  },
  {
    grupo: "Superfície",
    itens: [
      { to: "/superficie", label: "Superfície de ataque", icon: "superficie" },
      { to: "/joias",      label: "Joias da Coroa",       icon: "joias" },
      { to: "/vulnerabilidades", label: "Vulnerabilidades", icon: "vulns" },
    ],
  },
  {
    grupo: "Operação",
    itens: [
      {
        to: "/scan",
        label: "Scans",
        icon: "scans",
        sub: [
          { to: "/agendamento", label: "Agendamento", adminOnly: true },
        ],
      },
      {
        to: "/operacional",
        label: "Centro Operacional",
        icon: "operacional",
        adminOnly: true,
      },
    ],
  },
  {
    grupo: "Entrega",
    itens: [
      { to: "/relatorios", label: "Relatórios", icon: "relatorios" },
    ],
  },
  {
    grupo: "Admin",
    itens: [
      { to: "/usuarios",     label: "Usuários",      icon: "usuarios",   adminOnly: true },
      { to: "/logs",         label: "Logs",          icon: "logs",       adminOnly: true },
      { to: "/guardrails",   label: "Guardrails",    icon: "guardrails", adminOnly: true },
      {
        to: "/configuracoes",
        label: "Configurações",
        icon: "settings",
        adminOnly: true,
        sub: [
          { to: "/aprendizado", label: "Aprendizado", icon: "learning", adminOnly: true },
        ],
      },
    ],
  },
];

export default function Sidebar() {
  const navigate  = useNavigate();
  const location  = useLocation();
  const me        = authStore.me;
  const isAdmin   = Boolean(me?.is_admin);

  const logout = () => {
    authStore.clear();
    navigate("/login");
  };

  const isActive = (to, end = false) => {
    if (end) return location.pathname === to;
    return location.pathname === to || location.pathname.startsWith(to + "/");
  };

  const anySubActive = (sub = []) =>
    sub.some((s) => {
      const path = s.to.split("?")[0];
      const qs   = s.to.includes("?") ? "?" + s.to.split("?")[1] : "";
      return location.pathname === path && (!qs || location.search === qs);
    });

  return (
    <aside className="sb">
      {/* Logo */}
      <div style={{ display: "flex", alignItems: "center", gap: 10, padding: "0 8px 18px" }}>
        <div style={{
          width: 30, height: 30, borderRadius: 8,
          background: "var(--brand-500)",
          display: "grid", placeItems: "center",
          color: "#fff", fontWeight: 800, fontSize: 14,
          fontFamily: "var(--font-mono)",
          boxShadow: "0 2px 8px rgba(233,99,99,.35)",
        }}>S</div>
        <div>
          <div style={{ color: "#fff", fontWeight: 700, fontSize: 14, letterSpacing: "-0.01em" }}>ScriptKidd.o</div>
          <div style={{ color: "var(--sidebar-group-label)", fontSize: 9.5, letterSpacing: "0.1em", textTransform: "uppercase" }}>Pentest Automatizado</div>
        </div>
      </div>

      {/* Nav groups */}
      {NAV_GROUPS.map((group) => {
        const visible = group.itens.filter((it) => !it.adminOnly || isAdmin);
        if (visible.length === 0) return null;
        return (
          <div key={group.grupo} style={{ marginBottom: 6 }}>
            <div style={{
              fontSize: 10, fontWeight: 600, letterSpacing: "0.12em",
              textTransform: "uppercase", color: "var(--sidebar-group-label)",
              padding: "8px 10px 4px",
            }}>{group.grupo}</div>

            {visible.map((item) => {
              const visibleSub = (item.sub || []).filter((s) => !s.adminOnly || isAdmin);
              const active    = isActive(item.to, item.end) || anySubActive(visibleSub);
              const showSub   = (isActive(item.to, item.end) || anySubActive(visibleSub)) && visibleSub.length > 0;

              return (
                <div key={item.to}>
                  <NavLink
                    to={item.to}
                    end={item.end}
                    style={({ isActive: _a }) => ({
                      display: "flex",
                      alignItems: "center",
                      gap: 10,
                      padding: "8px 10px",
                      borderRadius: 8,
                      fontSize: 12.5,
                      fontWeight: active ? 600 : 400,
                      cursor: "pointer",
                      color: active ? "#fff" : "var(--sidebar-muted)",
                      background: active ? "var(--brand-500)" : "transparent",
                      textDecoration: "none",
                      transition: "background 120ms, color 120ms",
                    })}
                    onMouseEnter={(e) => {
                      if (!active) {
                        e.currentTarget.style.background = "rgba(255,255,255,0.05)";
                        e.currentTarget.style.color = "#fff";
                      }
                    }}
                    onMouseLeave={(e) => {
                      if (!active) {
                        e.currentTarget.style.background = "transparent";
                        e.currentTarget.style.color = "var(--sidebar-muted)";
                      }
                    }}
                  >
                    {ICONS[item.icon]}
                    <span style={{ flex: 1 }}>{item.label}</span>
                    {item.adminOnly && (
                      <span style={{
                        fontSize: 8.5, fontWeight: 700, letterSpacing: "0.08em",
                        color: "var(--sidebar-group-label)",
                        border: "1px solid var(--sidebar-border)",
                        borderRadius: 4, padding: "1px 4px",
                      }}>ADM</span>
                    )}
                  </NavLink>

                  {showSub && (
                    <div style={{ paddingLeft: 12 }}>
                      {visibleSub.map((sub) => {
                        const subPath   = sub.to.split("?")[0];
                        const subSearch = sub.to.includes("?") ? "?" + sub.to.split("?")[1] : "";
                        const subActive = location.pathname === subPath && (!subSearch || location.search === subSearch);
                        return (
                          <NavLink
                            key={sub.to}
                            to={sub.to}
                            style={() => ({
                              display: "flex",
                              alignItems: "center",
                              gap: 8,
                              padding: "6px 10px",
                              borderRadius: 6,
                              fontSize: 11.5,
                              fontWeight: subActive ? 600 : 400,
                              color: subActive ? "#fff" : "var(--sidebar-muted)",
                              background: subActive ? "rgba(233,99,99,0.25)" : "transparent",
                              textDecoration: "none",
                              transition: "background 120ms, color 120ms",
                            })}
                            onMouseEnter={(e) => {
                              if (!subActive) {
                                e.currentTarget.style.background = "rgba(255,255,255,0.04)";
                                e.currentTarget.style.color = "#fff";
                              }
                            }}
                            onMouseLeave={(e) => {
                              if (!subActive) {
                                e.currentTarget.style.background = "transparent";
                                e.currentTarget.style.color = "var(--sidebar-muted)";
                              }
                            }}
                          >
                            {sub.icon && ICONS[sub.icon] && (
                              <span style={{ opacity: 0.7 }}>{ICONS[sub.icon]}</span>
                            )}
                            {sub.label}
                          </NavLink>
                        );
                      })}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        );
      })}

      {/* Footer */}
      <div style={{ marginTop: "auto", padding: "12px 10px 0", borderTop: "1px solid var(--sidebar-border)" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 10 }}>
          <span style={{ width: 7, height: 7, borderRadius: 99, background: "var(--sev-low-solid)", boxShadow: "0 0 0 3px rgba(34,145,96,.22)" }} />
          <span style={{ fontFamily: "var(--font-mono)", fontSize: 10.5, color: "var(--sidebar-muted)" }}>runtime · ativo</span>
        </div>
        <div style={{ fontSize: 11, color: "var(--sidebar-text)", fontWeight: 600 }}>{me?.email || "—"}</div>
        <div style={{ fontSize: 10, color: "var(--sidebar-group-label)", marginBottom: 8 }}>
          {isAdmin ? "Admin · acesso total" : "Operador"}
        </div>
        <button
          onClick={logout}
          style={{
            width: "100%", padding: "7px 12px", borderRadius: 8,
            border: "1px solid var(--sidebar-border)", background: "transparent",
            color: "var(--sidebar-muted)", fontSize: 11.5, fontWeight: 500,
            cursor: "pointer", fontFamily: "var(--font-body)",
          }}
          onMouseEnter={(e) => { e.currentTarget.style.background = "rgba(255,255,255,0.05)"; e.currentTarget.style.color = "#fff"; }}
          onMouseLeave={(e) => { e.currentTarget.style.background = "transparent"; e.currentTarget.style.color = "var(--sidebar-muted)"; }}
        >
          Sair
        </button>
      </div>
    </aside>
  );
}
