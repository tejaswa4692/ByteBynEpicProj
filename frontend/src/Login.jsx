import { useState } from 'react'
import { login, register } from './api'

export default function Login({ onLogin }) {
  const [tab, setTab]   = useState('login')
  const [user, setUser] = useState('')
  const [pass, setPass] = useState('')
  const [err,  setErr]  = useState('')

  const submit = async e => {
    e.preventDefault()
    setErr('')
    const fn = tab === 'login' ? login : register
    const data = await fn(user, pass)
    if (data.token) onLogin(data.token, data.username)
    else setErr(data.detail || 'Something went wrong')
  }

  return (
    <div className="min-h-screen flex items-center justify-center">
      <div className="w-full max-w-md p-8 bg-gray-900 rounded-2xl shadow-xl">
        <h1 className="text-3xl font-bold text-center mb-1">🔐 HackHelix</h1>
        <p className="text-gray-400 text-center mb-7 text-sm">CVE Dependency Exploit Mapper</p>

        <div className="flex mb-6 bg-gray-800 rounded-lg p-1 gap-1">
          {['login', 'register'].map(t => (
            <button key={t} onClick={() => { setTab(t); setErr('') }}
              className={`flex-1 py-2 rounded-md text-sm font-medium transition ${tab === t ? 'bg-indigo-600 text-white' : 'text-gray-400 hover:text-white'}`}>
              {t === 'login' ? 'Login' : 'Register'}
            </button>
          ))}
        </div>

        {err && <div className="mb-4 p-3 bg-red-900 text-red-300 rounded-lg text-sm">{err}</div>}

        <form onSubmit={submit}>
          <input value={user} onChange={e => setUser(e.target.value)} placeholder="Username" required
            className="w-full mb-3 px-4 py-3 bg-gray-800 rounded-lg outline-none focus:ring-2 focus:ring-indigo-500" />
          <input value={pass} onChange={e => setPass(e.target.value)} placeholder="Password" type="password" required
            className="w-full mb-5 px-4 py-3 bg-gray-800 rounded-lg outline-none focus:ring-2 focus:ring-indigo-500" />
          <button type="submit" className="w-full py-3 bg-indigo-600 hover:bg-indigo-500 rounded-lg font-semibold transition">
            {tab === 'login' ? 'Login' : 'Create Account'}
          </button>
        </form>
      </div>
    </div>
  )
}
