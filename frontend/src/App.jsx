import { Navigate, Route, Routes } from "react-router-dom";
import { useEffect, useState } from "react";
import client from "./api/client";
import Sidebar from "./components/Sidebar";
import Navbar from "./components/Navbar";
import ToastCenter from "./components/ToastCenter";
import AccountPage from "./pages/AccountPage";
import DashboardPage from "./pages/DashboardPage";
import LandingPage from "./pages/LandingPage";
import LoginPage from "./pages/LoginPage";
import AttackEvolutionPage from "./pages/AttackEvolutionPage";
import ReportsPage from "./pages/ReportsPage";
import SchedulingPage from "./pages/SchedulingPage";
import ScanOperationsPage from "./pages/ScanOperationsPage";
import OperationsCenterPage from "./pages/OperationsCenterPage";
import TargetsPage from "./pages/TargetsPage";
import UserManagementPage from "./pages/UserManagementPage";
import VulnerabilitiesPage from "./pages/VulnerabilitiesPage";
import WorkersPage from "./pages/WorkersPage";
import JobsRegistryPage from "./pages/JobsRegistryPage";
import LearningPage from "./pages/LearningPage";
import WorkerLogsPage from "./pages/WorkerLogsPage";
import PhaseMonitorPage from "./pages/PhaseMonitorPage";
import AgentFlowPage from "./pages/AgentFlowPage";
import { authStore } from "./store/auth";

function Protected({ children }) {
  // Sem sessão → cai na página índice (landing), não direto no login.
  if (!authStore.token) return <Navigate to="/welcome" replace />;
  return children;
}

function AdminOnly({ children }) {
  const me = authStore.me;
  if (!me?.is_admin) return <Navigate to="/" replace />;
  return children;
}

export default function App() {
  const [ready, setReady] = useState(false);

  useEffect(() => {
    document.documentElement.setAttribute("data-theme", "light");
  }, []);

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
        <Route path="/welcome" element={<LandingPage />} />
        <Route path="/login" element={<LoginPage />} />
        <Route
          path="/*"
          element={
            <Protected>
              <div className="app-shell" style={{ backgroundColor: "var(--bg-main)" }}>
                <Sidebar />
                <div className="main-column">
                  <Navbar />
                  <Routes>
                    <Route path="/" element={<DashboardPage />} />
                    <Route path="/relatorios" element={<ReportsPage />} />
                    <Route path="/evolucao" element={<AttackEvolutionPage />} />
                    <Route path="/targets" element={<TargetsPage />} />
                    <Route path="/vulnerabilidades" element={<VulnerabilitiesPage />} />
                    <Route path="/agendamento" element={<AdminOnly><SchedulingPage /></AdminOnly>} />
                    <Route path="/usuarios" element={<AdminOnly><UserManagementPage /></AdminOnly>} />
                    <Route path="/scan" element={<AdminOnly><ScanOperationsPage /></AdminOnly>} />
                    <Route path="/phase-monitor" element={<AdminOnly><PhaseMonitorPage /></AdminOnly>} />
                    <Route path="/operacional" element={<AdminOnly><OperationsCenterPage /></AdminOnly>} />
                    <Route path="/workers" element={<AdminOnly><WorkersPage /></AdminOnly>} />
                    <Route path="/jobs" element={<AdminOnly><JobsRegistryPage /></AdminOnly>} />
                    <Route path="/aprendizado" element={<AdminOnly><LearningPage /></AdminOnly>} />
                    <Route path="/worker-logs" element={<AdminOnly><WorkerLogsPage /></AdminOnly>} />
                    <Route path="/agent-flow" element={<AdminOnly><AgentFlowPage /></AdminOnly>} />
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
