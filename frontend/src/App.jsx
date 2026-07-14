import { Navigate, Route, Routes, useLocation } from "react-router-dom";
import { useEffect, useState } from "react";
import client from "./api/client";
import Sidebar from "./components/Sidebar";
import ToastCenter from "./components/ToastCenter";
import ErrorBoundary from "./components/ErrorBoundary";
import AccountPage from "./pages/AccountPage";
import DashboardPage from "./pages/DashboardPage";
import LandingPage from "./pages/LandingPage";
import LoginPage from "./pages/LoginPage";
import AttackEvolutionPage from "./pages/AttackEvolutionPage";
import ReportsPage from "./pages/ReportsPage";
import RedTeamReportPage from "./pages/RedTeamReportPage";
import ScanOperationsPage from "./pages/ScanOperationsPage";
import OperationsCenterPage from "./pages/OperationsCenterPage";
import UserManagementPage from "./pages/UserManagementPage";
import AdminLogsPage from "./pages/AdminLogsPage";
import VulnerabilitiesPage from "./pages/VulnerabilitiesPage";
import DomainsPage from "./pages/DomainsPage";
import AttackSurfacePage from "./pages/AttackSurfacePage";
import AttackGraphPage from "./pages/AttackGraphPage";
import CrownJewelsPage from "./pages/CrownJewelsPage";
import LearningPage from "./pages/LearningPage";
import GuardrailsPage from "./pages/GuardrailsPage";
import CapabilityBlueprintPage from "./pages/CapabilityBlueprintPage";
import SchedulingPage from "./pages/SchedulingPage";
import SettingsPage from "./pages/SettingsPage";
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

// Error boundary que reinicia a cada mudança de rota — uma página com
// erro de render mostra um fallback isolado em vez de derrubar o app.
function RoutedBoundary({ children }) {
  const { pathname } = useLocation();
  return <ErrorBoundary key={pathname}>{children}</ErrorBoundary>;
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
              <div className="app-shell sk" style={{ backgroundColor: "var(--bg-main)" }}>
                <Sidebar />
                <div className="main-column">
                  <RoutedBoundary>
                  <Routes>
                    <Route path="/" element={<DashboardPage />} />
                    <Route path="/relatorios" element={<RedTeamReportPage />} />
                    <Route path="/relatorios-legacy" element={<ReportsPage />} />
                    <Route path="/evolucao" element={<AttackEvolutionPage />} />
                    <Route path="/targets" element={<Navigate to="/scan" replace />} />
                    <Route path="/vulnerabilidades" element={<VulnerabilitiesPage />} />
                    <Route path="/superficie" element={<AttackSurfacePage />} />
                    <Route path="/attack-graph" element={<AttackGraphPage />} />
                    <Route path="/dominios" element={<Navigate to="/vulnerabilidades" replace />} />
                    <Route path="/joias" element={<CrownJewelsPage />} />
                    <Route path="/agendamento" element={<AdminOnly><SchedulingPage /></AdminOnly>} />
                    <Route path="/usuarios" element={<AdminOnly><UserManagementPage /></AdminOnly>} />
                    <Route path="/logs" element={<AdminOnly><AdminLogsPage /></AdminOnly>} />
                    <Route path="/scan" element={<AdminOnly><ScanOperationsPage /></AdminOnly>} />
                    <Route path="/operacional" element={<AdminOnly><OperationsCenterPage /></AdminOnly>} />
                    <Route path="/phase-monitor" element={<Navigate to="/operacional?module=phases_agents" replace />} />
                    <Route path="/workers" element={<Navigate to="/operacional?module=infra" replace />} />
                    <Route path="/jobs" element={<Navigate to="/operacional?module=infra" replace />} />
                    <Route path="/worker-logs" element={<Navigate to="/operacional?module=runtime" replace />} />
                    <Route path="/agent-flow" element={<Navigate to="/operacional?module=phases_agents" replace />} />
                    <Route path="/aprendizado" element={<AdminOnly><LearningPage /></AdminOnly>} />
                    <Route path="/guardrails" element={<AdminOnly><GuardrailsPage /></AdminOnly>} />
                    <Route path="/estrategia" element={<AdminOnly><CapabilityBlueprintPage /></AdminOnly>} />
                    <Route path="/configuracoes" element={<AdminOnly><SettingsPage /></AdminOnly>} />
                    <Route path="/conta" element={<AdminOnly><AccountPage /></AdminOnly>} />
                  </Routes>
                  </RoutedBoundary>
                </div>
              </div>
            </Protected>
          }
        />
      </Routes>
    </>
  );
}
