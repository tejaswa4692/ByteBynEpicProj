import React, { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { githubLogin } from '@/api'
import { Button } from '@/components/ui/button'
import { Shield, Loader2 } from 'lucide-react'

function GithubIcon({ className }) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="currentColor">
      <path d="M12 0C5.374 0 0 5.373 0 12c0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23A11.509 11.509 0 0 1 12 5.803c1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576C20.566 21.797 24 17.3 24 12c0-6.627-5.373-12-12-12z" />
    </svg>
  )
}

const CLIENT_ID = 'Ov23liHCqj8m7S6VTMOm'

export default function LoginPage() {
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const navigate = useNavigate()

  const fetchRef = React.useRef(false)

  useEffect(() => {
    if (localStorage.getItem('token')) {
      navigate('/repos', { replace: true })
      return
    }
    const code = new URLSearchParams(window.location.search).get('code')
    if (!code) return
    if (fetchRef.current) return
    fetchRef.current = true

    setLoading(true)
    githubLogin(code)
      .then(data => {
        if (data.token) {
          localStorage.setItem('token', data.token)
          localStorage.setItem('username', data.username)
          if (data.avatar_url) localStorage.setItem('avatar_url', data.avatar_url)
          window.history.replaceState({}, '', '/')
          navigate('/repos', { replace: true })
        } else {
          setError(data.detail || 'GitHub login failed')
          setLoading(false)
        }
      })
      .catch(() => {
        setError('Network error — make sure the backend is running')
        setLoading(false)
      })
  }, [])

  const handleLogin = () => {
    const redirect = window.location.origin
    window.location.href = `https://github.com/login/oauth/authorize?client_id=${CLIENT_ID}&redirect_uri=${redirect}&scope=repo,user`
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-background">
      <div className="w-full max-w-sm px-6 space-y-8">
        {/* Logo */}
        <div className="text-center space-y-4">
          <div className="flex justify-center">
            <div className="p-4 rounded-2xl bg-primary/10 border border-primary/20">
              <Shield className="w-10 h-10 text-primary" />
            </div>
          </div>
          <div>
            <h1 className="text-3xl font-bold tracking-tight">HackHelix</h1>
            <p className="text-muted-foreground text-sm mt-1.5">
              Secure your dependencies. Automatically.
            </p>
          </div>
        </div>

        {/* Error */}
        {error && (
          <div className="p-3 rounded-lg bg-destructive/10 border border-destructive/20 text-destructive text-sm text-center">
            {error}
          </div>
        )}

        {/* Login */}
        <div className="space-y-3">
          <Button
            onClick={handleLogin}
            disabled={loading}
            className="w-full h-11 gap-2.5 text-sm font-semibold"
          >
            {loading ? (
              <>
                <Loader2 className="w-4 h-4 animate-spin" />
                Authenticating…
              </>
            ) : (
              <>
                <GithubIcon className="w-5 h-5" />
                Continue with GitHub
              </>
            )}
          </Button>
        </div>

        <p className="text-center text-xs text-muted-foreground">
          Scans your npm dependencies for known CVEs and security advisories.
        </p>
      </div>
    </div>
  )
}
