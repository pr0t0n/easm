import { Link, useNavigate } from "react-router-dom";
import { authStore } from "../store/auth";

export default function Navbar() {
  const navigate = useNavigate();

  const logout = () => {
    authStore.clear();
    navigate("/login");
  };

  return (
    <header className="mx-auto mt-4 flex w-[95%] max-w-6xl items-center justify-between rounded-2xl border border-slate-800 bg-slate-900/70 px-4 py-3">
      <div className="text-xl font-bold text-brand-500">VALID ASM - vASM</div>
      <nav className="flex gap-4 text-sm text-slate-200">
        <Link to="/">Dashboard</Link>
        <Link to="/scans">Scans</Link>
        <Link to="/reports">Relatorios</Link>
        <button onClick={logout} className="text-rose-300">Sair</button>
      </nav>
    </header>
  );
}
