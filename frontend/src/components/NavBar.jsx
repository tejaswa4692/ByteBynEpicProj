import { Link, useNavigate, useLocation } from 'react-router-dom'
import { Button } from '@/components/ui/button'
import { Avatar, AvatarImage, AvatarFallback } from '@/components/ui/avatar'
import { Shield, LogOut } from 'lucide-react'

const NAV_LINKS = [
  { to: '/repos', label: 'Repositories' },
  { to: '/certify', label: 'Certification' },
  { to: '/downloads', label: 'Downloads' },
]

export default function NavBar() {
  const navigate = useNavigate()
  const location = useLocation()
  const username = localStorage.getItem('username')
  const avatar = localStorage.getItem('avatar_url')

  const logout = () => {
    localStorage.clear()
    navigate('/')
  }

  return (
    <nav className="border-b border-border bg-card/60 backdrop-blur-md sticky top-0 z-50">
      <div className="max-w-6xl mx-auto px-6 h-16 flex items-center justify-between">
        <div className="flex items-center gap-8">
          <Link to="/repos" className="flex items-center gap-2.5 font-bold text-lg tracking-tight">
            <div className="p-1.5 rounded-lg bg-primary/15 border border-primary/25">
              <Shield className="w-4 h-4 text-primary" />
            </div>
            <span className="font-black tracking-tight">repodogg</span>
          </Link>
          <div className="flex items-center gap-1">
            {NAV_LINKS.map(({ to, label }) => {
              const active = location.pathname === to || (to !== '/repos' && location.pathname.startsWith(to))
              return (
                <Link
                  key={to}
                  to={to}
                  className={`px-3 py-1.5 rounded-md text-sm font-medium transition-colors ${
                    active
                      ? 'bg-secondary text-foreground'
                      : 'text-muted-foreground hover:text-foreground hover:bg-secondary/60'
                  }`}
                >
                  {label}
                </Link>
              )
            })}
          </div>
        </div>
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2.5">
            <Avatar className="w-7 h-7">
              <AvatarImage src={avatar} />
              <AvatarFallback className="text-xs">{username?.[0]?.toUpperCase()}</AvatarFallback>
            </Avatar>
            <span className="text-sm text-muted-foreground font-medium">{username}</span>
          </div>
          <Button
            variant="ghost"
            size="icon"
            onClick={logout}
            className="w-8 h-8 text-muted-foreground hover:text-destructive hover:bg-destructive/10"
            title="Logout"
          >
            <LogOut className="w-4 h-4" />
          </Button>
        </div>
      </div>
    </nav>
  )
}
