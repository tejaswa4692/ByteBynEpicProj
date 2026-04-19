import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import LoginPage from './pages/LoginPage'
import ReposPage from './pages/ReposPage'
import RepoDetailPage from './pages/RepoDetailPage'
import CertifyPage from './pages/CertifyPage'
import VerifyPage from './pages/VerifyPage'
import ProtectedRoute from './components/ProtectedRoute'
import DownloadsPage from './pages/DownloadsPage'
import BlastRadiusPage from './pages/BlastRadiusPage'

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<LoginPage />} />
        <Route path="/verify" element={<VerifyPage />} />
        <Route element={<ProtectedRoute />}>
          <Route path="/repos" element={<ReposPage />} />
          <Route path="/repos/:owner/:name" element={<RepoDetailPage />} />
          <Route path="/certify" element={<CertifyPage />} />
          <Route path="/blast-radius" element={<BlastRadiusPage />} />
          <Route path="/downloads" element={<DownloadsPage />} />
        </Route>
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </BrowserRouter>
  )
}
