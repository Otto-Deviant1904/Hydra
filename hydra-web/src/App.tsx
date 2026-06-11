import { Link, Route, Routes } from 'react-router-dom'
import Dashboard from './pages/Dashboard'
import CrackPage from './pages/CrackPage'
import SessionsPage from './pages/SessionsPage'

export default function App() {
  return (
    <div className="min-h-screen flex flex-col">
      <nav className="bg-gray-900 border-b border-gray-800 px-6 py-3 flex items-center gap-6">
        <Link to="/" className="text-xl font-bold text-hydra-500 tracking-tight">
          HYDRA
        </Link>
        <Link to="/" className="text-sm text-gray-400 hover:text-white transition-colors">
          Dashboard
        </Link>
        <Link to="/crack" className="text-sm text-gray-400 hover:text-white transition-colors">
          Crack
        </Link>
        <Link to="/sessions" className="text-sm text-gray-400 hover:text-white transition-colors">
          Sessions
        </Link>
      </nav>
      <main className="flex-1 p-6">
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/crack" element={<CrackPage />} />
          <Route path="/sessions" element={<SessionsPage />} />
        </Routes>
      </main>
    </div>
  )
}
