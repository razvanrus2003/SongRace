import { Routes, Route } from 'react-router-dom'
import { AuthProvider } from './AuthContext'
import { AppLayout } from './components/AppShell'
import { RequireAuth } from './components/RequireAuth'
import { HomePage } from './pages/HomePage'
import { LobbiesPage } from './pages/LobbiesPage'
import { GamePage } from './pages/GamePage'
import { LibraryPage } from './pages/LibraryPage'
import {
  UserDashboardPage,
  AdminDashboardPage,
  AccessDeniedPage,
} from './pages/DashboardPages'

function App() {
  return (
    <AuthProvider>
      <AppLayout>
        <Routes>
          <Route path="/" element={<HomePage />} />
          <Route
            path="/lobbies"
            element={
              <RequireAuth>
                <LobbiesPage />
              </RequireAuth>
            }
          />
          <Route
            path="/game"
            element={
              <RequireAuth>
                <GamePage />
              </RequireAuth>
            }
          />
          <Route
            path="/library"
            element={
              <RequireAuth role="admin">
                <LibraryPage />
              </RequireAuth>
            }
          />
          <Route
            path="/user"
            element={
              <RequireAuth role="user">
                <UserDashboardPage />
              </RequireAuth>
            }
          />
          <Route
            path="/admin"
            element={
              <RequireAuth role="admin">
                <AdminDashboardPage />
              </RequireAuth>
            }
          />
          <Route path="/denied" element={<AccessDeniedPage />} />
          <Route path="*" element={<HomePage />} />
        </Routes>
      </AppLayout>
    </AuthProvider>
  )
}

export default App
