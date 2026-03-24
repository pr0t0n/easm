import { Navigate, Route, Routes } from "react-router-dom";
import { useEffect, useState } from "react";
import client from "./api/client";
import Sidebar from "./components/Sidebar";
import Navbar from "./components/Navbar";
import ToastCenter from "./components/ToastCenter";
import AccountPage from "./pages/AccountPage";
import ConfigurationPage from "./pages/ConfigurationPage";
import DashboardPage from "./pages/DashboardPage";
import LoginPage from "./pages/LoginPage";
import ReportsPage from "./pages/ReportsPage";
import SchedulingPage from "./pages/SchedulingPage";
import ScansPage from "./pages/ScansPage";
import TargetsPage from "./pages/TargetsPage";
import ToolsPage from "./pages/ToolsPage";
import UserManagementPage from "./pages/UserManagementPage";
import VulnerabilitiesPage from "./pages/VulnerabilitiesPage";
import WorkersPage from "./pages/WorkersPage";
import JobsRegistryPage from "./pages/JobsRegistryPage";
import { authStore } from "./store/auth";

function Protected({ children }) {
  if (!authStore.token) return <Navigate to="/login" replace />;
  return children;
}

function AdminOnly({ children }) {
  const me = authStore.me;
  if (!me?.is_admin) return <Navigate to="/" replace />;
  return children;
}

export default function App() {
  const [ready, setReady] = useState(false);
  const [theme, setTheme] = useState("light");

  useEffect(() => {
    const stored = localStorage.getItem("theme");
    const initial = stored === "dark" || stored === "light"
      ? stored
      : (window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
    setTheme(initial);
    document.documentElement.setAttribute("data-theme", initial);
  }, []);

  const toggleTheme = () => {
    setTheme((prev) => {
      const next = prev === "dark" ? "light" : "dark";
      localStorage.setItem("theme", next);
      document.documentElement.setAttribute("data-theme", next);
      return next;
    });
  };

  useEffect(() => {
    const syncMe = async () => {
      if (!authStore.token) {
        setReady(true);
        return;
      }
      try {
        const me = await client.get("/api/auth/me");
        authStore.setMe(me.data);
      } catch {
        authStore.clear();
      } finally {
        setReady(true);
      }
    };
    syncMe();
  }, []);

  if (!ready) return null;

  return (
    <>
      <ToastCenter />
      <Routes>
        <Route path="/login" element={<LoginPage />} />
        <Route
          path="/*"
          element={
            <Protected>
              <div className="min-h-screen md:flex" style={{ backgroundColor: "var(--bg-main)" }}>
                <Sidebar />
                <div className="flex min-h-screen flex-1 flex-col">
                  <Navbar theme={theme} onToggleTheme={toggleTheme} />
                  <Routes>
                    <Route path="/" element={<DashboardPage />} />
                    <Route path="/relatorios" element={<ReportsPage />} />
                    <Route path="/targets" element={<TargetsPage />} />
                    <Route path="/vulnerabilidades" element={<VulnerabilitiesPage />} />
                    <Route path="/agendamento" element={<AdminOnly><SchedulingPage /></AdminOnly>} />
                    <Route path="/configuracao" element={<AdminOnly><ConfigurationPage /></AdminOnly>} />
                    <Route path="/usuarios" element={<AdminOnly><UserManagementPage /></AdminOnly>} />
                    <Route path="/scan" element={<AdminOnly><ScansPage /></AdminOnly>} />
                    <Route path="/ferramentas" element={<AdminOnly><ToolsPage /></AdminOnly>} />
                    <Route path="/workers" element={<AdminOnly><WorkersPage /></AdminOnly>} />
                    <Route path="/jobs" element={<AdminOnly><JobsRegistryPage /></AdminOnly>} />
                    <Route path="/conta" element={<AdminOnly><AccountPage /></AdminOnly>} />
                  </Routes>
                </div>
              </div>
            </Protected>
          }
        />
      </Routes>
    </>
  );
}
