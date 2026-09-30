import { Navigate, Route, Routes } from 'react-router-dom'

import { AppShell } from './components/AppShell'
import { RequireAuth } from './components/RequireAuth'
import { AuthProvider } from './auth/AuthContext'
import { AgentCreatePage } from './pages/AgentCreatePage'
import { AgentDetailPage } from './pages/AgentDetailPage'
import { AgentsPage } from './pages/AgentsPage'
import { ApprovalsPage } from './pages/ApprovalsPage'
import { AuditSearchPage } from './pages/AuditSearchPage'
import { LiveDecisionsPage } from './pages/LiveDecisionsPage'
import { LoginPage } from './pages/LoginPage'
import { OverviewPage } from './pages/OverviewPage'
import { PoliciesPage } from './pages/PoliciesPage'

export function App() {
  return (
    <AuthProvider>
      <Routes>
        <Route path="/login" element={<LoginPage />} />
        <Route
          element={
            <RequireAuth>
              <AppShell />
            </RequireAuth>
          }
        >
          <Route path="/overview" element={<OverviewPage />} />
          <Route path="/agents" element={<AgentsPage />} />
          <Route path="/agents/new" element={<AgentCreatePage />} />
          <Route path="/agents/:id" element={<AgentDetailPage />} />
          <Route path="/live" element={<LiveDecisionsPage />} />
          <Route path="/audit" element={<AuditSearchPage />} />
          <Route path="/policies" element={<PoliciesPage />} />
          <Route path="/approvals" element={<ApprovalsPage />} />
        </Route>
        <Route path="*" element={<Navigate to="/overview" replace />} />
      </Routes>
    </AuthProvider>
  )
}
