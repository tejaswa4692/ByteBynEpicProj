import { useState, useEffect } from 'react'
import { githubLogin } from './api'

export default function Login({ onLogin }) {
  const [err, setErr] = useState('')
  const [loading, setLoading] = useState(false)

  useEffect(() => {
    const urlParams = new URLSearchParams(window.location.search);
    const code = urlParams.get('code');
    
    if (code) {
      setLoading(true);
      githubLogin(code)
        .then(data => {
          if (data.token) {
            window.history.replaceState({}, document.title, "/");
            onLogin(data.token, data.username, data.avatar_url);
          } else {
            setErr(data.detail || 'GitHub Login Failed');
            setLoading(false);
          }
        })
        .catch(e => {
          setErr('Network Error during GitHub Login');
          setLoading(false);
        });
    }
  }, []);

  const handleLogin = () => {
    const clientId = 'Ov23liHCqj8m7S6VTMOm';
    const redirectUri = window.location.origin;
    window.location.href = `https://github.com/login/oauth/authorize?client_id=${clientId}&redirect_uri=${redirectUri}&scope=repo,user`;
  }

  return (
    <div className="min-h-screen flex items-center justify-center">
      <div className="w-full max-w-md p-8 bg-gray-900 rounded-2xl shadow-xl">
        <h1 className="text-3xl font-bold text-center mb-1">🔐 HackHelix</h1>
        <p className="text-gray-400 text-center mb-7 text-sm">CVE Dependency Exploit Mapper</p>

        {err && <div className="mb-4 p-3 bg-red-900 text-red-300 rounded-lg text-sm">{err}</div>}

        <button onClick={handleLogin} disabled={loading} className="w-full py-3 bg-indigo-600 hover:bg-indigo-500 rounded-lg font-semibold transition flex items-center justify-center gap-2">
          {loading ? '⏳ Authenticating...' : 'Login with GitHub'}
        </button>
      </div>
    </div>
  )
}
