import { useState } from 'react'
import Login from './Login'
import Dashboard from './Dashboard'

export default function App() {
  const [token, setToken] = useState(localStorage.getItem('token'))

  const onLogin = (tok, user) => {
    localStorage.setItem('token', tok)
    localStorage.setItem('username', user)
    setToken(tok)
  }

  const onLogout = () => {
    localStorage.clear()
    setToken(null)
  }

  return token ? <Dashboard onLogout={onLogout} /> : <Login onLogin={onLogin} />
}
