import { Navigate, Route, Routes } from "react-router-dom";
import { useAuth } from "./auth";
import { Layout } from "./components/Layout";
import { Account } from "./pages/Account";
import { Admin } from "./pages/Admin";
import { Approvals } from "./pages/Approvals";
import { Audit } from "./pages/Audit";
import { Dashboard } from "./pages/Dashboard";
import { Login } from "./pages/Login";
import { Scans } from "./pages/Scans";
import { Setup } from "./pages/Setup";
import { TargetDetail } from "./pages/TargetDetail";
import { Targets } from "./pages/Targets";

export function App() {
  const { me, loading, needsSetup } = useAuth();

  if (loading) return <div className="center-page">Loading Trash Scan…</div>;
  if (needsSetup) return <Setup />;
  if (!me) return <Login />;

  return (
    <Layout>
      <Routes>
        <Route path="/" element={<Dashboard />} />
        <Route path="/targets" element={<Targets />} />
        <Route path="/targets/:id" element={<TargetDetail />} />
        <Route path="/scans" element={<Scans />} />
        <Route path="/audit" element={<Audit />} />
        <Route path="/account" element={<Account />} />
        <Route path="/reports" element={<Navigate to="/" replace />} />
        {me.role === "ADMINISTRATOR" && <Route path="/approvals" element={<Approvals />} />}
        {me.role === "ADMINISTRATOR" && <Route path="/admin" element={<Admin />} />}
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </Layout>
  );
}
