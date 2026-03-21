import { Navigate, Route, Routes } from "react-router-dom";
import { useEffect, useState } from "react";
import client from "./api/client";
import Sidebar from "./components/Sidebar";
import ToastCenter from "./components/ToastCenter";
import AccountPage from "./pages/AccountPage";
import ConfigurationPage from "./pages/ConfigurationPage";
import DashboardPage from "./pages/DashboardPage";
import AssetsPage from "./pages/AssetsPage";
import IssuesPage from "./pages/IssuesPage";
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
              <div className="min-h-screen md:flex">
                <Sidebar />
                <div className="flex-1">
                  <Routes>
                    <Route path="/" element={<DashboardPage />} />
                    <Route path="/relatorios" element={<ReportsPage />} />
                    <Route path="/targets" element={<TargetsPage />} />
                    <Route path="/assets" element={<AssetsPage />} />
                    <Route path="/vulnerabilidades" element={<VulnerabilitiesPage />} />
                    <Route path="/issues" element={<IssuesPage />} />
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
