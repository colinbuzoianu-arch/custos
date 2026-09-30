import { Navigate, Route, Routes } from 'react-router-dom'

import { AppShell } from './components/AppShell'
import { RequireAuth } from './components/RequireAuth'
import { AuthProvider } from './auth/AuthContext'
import { AgentsPage } from './pages/AgentsPage'
import { LoginPage } from './pages/LoginPage'
import { OverviewPage } from './pages/OverviewPage'

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
        </Route>
        <Route path="*" element={<Navigate to="/overview" replace />} />
      </Routes>
    </AuthProvider>
  )
}
