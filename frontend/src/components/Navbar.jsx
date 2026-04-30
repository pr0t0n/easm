import { Link, useNavigate } from "react-router-dom";
import { authStore } from "../store/auth";

export default function Navbar() {
  const navigate = useNavigate();
  const me = authStore.me;

  const logout = () => {
    authStore.clear();
    navigate("/login");
  };

  return (
    <header className="app-header sticky top-0 z-30 border-b px-4 py-3 backdrop-blur md:px-6">
      <div className="mx-auto flex w-full max-w-[1600px] items-center justify-between">
        <div>
          <p className="app-header-title font-display text-lg font-semibold tracking-tight">Cyber Exposure Dashboard</p>
          <p className="app-header-subtitle text-xs">Monitoramento, risco e operacoes de superficie externa</p>
        </div>

        <div className="flex items-center gap-3">
          <Link
            to="/scan"
            className="rounded-lg px-3 py-2 text-sm font-semibold"
            style={{
              background: "var(--primary)",
              color: "#ffffff",
              boxShadow: "0 1px 2px rgba(254,123,2,0.2)",
            }}
            onMouseEnter={(e) => (e.currentTarget.style.background = "var(--primary-hover)")}
            onMouseLeave={(e) => (e.currentTarget.style.background = "var(--primary)")}
          >
            Novo Scan
          </Link>
          <div className="app-btn-secondary hidden rounded-lg border px-3 py-2 text-xs sm:block">
            {me?.email || "usuario"}
          </div>
          <button onClick={logout} className="app-btn-secondary rounded-lg border px-3 py-2 text-sm">
            Sair
          </button>
        </div>
      </div>
    </header>
  );
}
