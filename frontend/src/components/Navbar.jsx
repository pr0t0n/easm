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
    <header className="sticky top-0 z-30 border-b border-[#cbd5e0] bg-white/95 px-4 py-3 backdrop-blur md:px-6">
      <div className="mx-auto flex w-full max-w-[1600px] items-center justify-between">
        <div>
          <p className="font-display text-lg font-semibold tracking-tight text-[#1a365d]">Cyber Exposure Dashboard</p>
          <p className="text-xs text-[#4a5568]">Monitoramento, risco e operacoes de superficie externa</p>
        </div>

        <div className="flex items-center gap-3">
          <Link
            to="/scan"
            className="rounded-lg border border-[#2c5282] bg-[#1a365d] px-3 py-2 text-sm font-semibold text-white shadow-[0_0_18px_rgba(26,54,93,0.2)] hover:bg-[#2c5282]"
          >
            Novo Scan
          </Link>
          <div className="hidden rounded-lg border border-[#cbd5e0] bg-[#f7fafc] px-3 py-2 text-xs text-[#4a5568] sm:block">
            {me?.email || "usuario"}
          </div>
          <button onClick={logout} className="rounded-lg border border-[#cbd5e0] px-3 py-2 text-sm text-[#2d3748] hover:border-[#2c5282] hover:text-[#1a365d]">
            Sair
          </button>
        </div>
      </div>
    </header>
  );
}
