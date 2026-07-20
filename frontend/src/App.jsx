import { Navigate, Route, Routes, useLocation } from "react-router-dom";
import { lazy, Suspense, useEffect, useState } from "react";
import client from "./api/client";
import Sidebar from "./components/Sidebar";
import ToastCenter from "./components/ToastCenter";
import ErrorBoundary from "./components/ErrorBoundary";
import LandingPage from "./pages/LandingPage";
import LoginPage from "./pages/LoginPage";
import { authStore } from "./store/auth";

const AccountPage = lazy(() => import("./pages/AccountPage"));
const DashboardPage = lazy(() => import("./pages/DashboardPage"));
const AttackEvolutionPage = lazy(() => import("./pages/AttackEvolutionPage"));
const RedTeamReportPage = lazy(() => import("./pages/RedTeamReportPage"));
const ScanOperationsPage = lazy(() => import("./pages/ScanOperationsPage"));
const OperationsCenterPage = lazy(() => import("./pages/OperationsCenterPage"));
const UserManagementPage = lazy(() => import("./pages/UserManagementPage"));
const AdminLogsPage = lazy(() => import("./pages/AdminLogsPage"));
const VulnerabilitiesPage = lazy(() => import("./pages/VulnerabilitiesPage"));
const AttackSurfacePage = lazy(() => import("./pages/AttackSurfacePage"));
const AttackGraphPage = lazy(() => import("./pages/AttackGraphPage"));
const CrownJewelsPage = lazy(() => import("./pages/CrownJewelsPage"));
const LearningPage = lazy(() => import("./pages/LearningPage"));
const GuardrailsPage = lazy(() => import("./pages/GuardrailsPage"));
const CapabilityBlueprintPage = lazy(() => import("./pages/CapabilityBlueprintPage"));
const SchedulingPage = lazy(() => import("./pages/SchedulingPage"));
const SettingsPage = lazy(() => import("./pages/SettingsPage"));

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
                  <Suspense fallback={<div style={{ padding: 24, color: "var(--ink-muted)" }}>Carregando módulo…</div>}>
                  <Routes>
                    <Route path="/" element={<DashboardPage />} />
                    <Route path="/relatorios" element={<RedTeamReportPage />} />
                    <Route path="/relatorios-legacy" element={<Navigate to="/relatorios" replace />} />
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
                  </Suspense>
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
