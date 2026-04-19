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
    <div className="min-h-screen flex flex-col items-center justify-center bg-black text-gray-200 font-sans selection:bg-white/20">
      
      {/* Absolute Ambient Grid / Texture (Optional Minimal Vibe) */}
      <div className="absolute inset-0 bg-[url('data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSIyMCIgaGVpZ2h0PSIyMCI+PGNpcmNsZSBjeD0iMSIgY3k9IjEiIHI9IjEiIGZpbGw9InJnYmEoMjU1LDI1NSwyNTUsMC4wMykiLz48L3N2Zz4=')] [mask-image:radial-gradient(ellipse_at_center,black_40%,transparent_100%)] pointer-events-none"></div>

      <div className="relative z-10 w-full max-w-[360px] p-8">
        
        <div className="flex flex-col items-center justify-center mb-8">
          <div className="w-12 h-12 bg-[#111] border border-[#333] rounded-xl flex items-center justify-center mb-6 shadow-xl">
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className="text-white"><path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5"/></svg>
          </div>
          <h1 className="text-2xl font-semibold text-white tracking-tight mb-2">HackHelix</h1>
          <p className="text-[#888] text-sm text-center">Sign in to secure your repository dependencies</p>
        </div>

        {err && <div className="mb-6 p-3 bg-red-500/10 border border-red-500/20 text-red-500 rounded-md text-[13px] text-center font-medium">{err}</div>}

        <button onClick={handleLogin} disabled={loading} className="w-full py-2.5 bg-white hover:bg-gray-200 text-black rounded-md font-medium text-[14px] transition-colors flex items-center justify-center gap-2">
          {loading ? (
            <span className="flex items-center gap-2">
              <svg className="animate-spin -ml-1 mr-2 h-4 w-4 text-black" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24"><circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle><path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path></svg>
              Authenticating...
            </span>
          ) : (
            <>
              <svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor"><path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0024 12c0-6.63-5.37-12-12-12z"/></svg>
              Continue with GitHub
            </>
          )}
        </button>

        <p className="text-center text-[#555] text-[12px] mt-8">
          By continuing, you agree to our Terms of Service and Privacy Policy.
        </p>
      </div>
    </div>
  )
}
