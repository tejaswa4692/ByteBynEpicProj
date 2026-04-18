import { useState } from 'react'
import Login from './Login'
import Dashboard from './Dashboard'

export default function App() {
  const [token, setToken] = useState(localStorage.getItem('token'))

  const onLogin = (tok, user, avatar) => {
    localStorage.setItem('token', tok)
    localStorage.setItem('username', user)
    if (avatar) localStorage.setItem('avatar_url', avatar)
    setToken(tok)
  }

  const onLogout = () => {
    localStorage.clear()
    setToken(null)
  }

  return token ? <Dashboard onLogout={onLogout} /> : <Login onLogin={onLogin} />
}
