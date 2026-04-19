import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { getGithubRepos, moderateRepo, scanRepo } from '@/api'
import NavBar from '@/components/NavBar'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Switch } from '@/components/ui/switch'
import { Badge } from '@/components/ui/badge'
import { Input } from '@/components/ui/input'
import { Skeleton } from '@/components/ui/skeleton'
import { RefreshCw, ExternalLink, ChevronRight, Search, GitFork, AlertCircle, Loader2, Link2, ScanSearch } from 'lucide-react'

function RepoCardSkeleton() {
  return (
    <Card>
      <CardContent className="p-5 space-y-4">
        <div className="flex justify-between items-start">
          <div className="space-y-2">
            <Skeleton className="h-4 w-36" />
            <Skeleton className="h-3 w-20" />
          </div>
          <Skeleton className="h-6 w-11 rounded-full" />
        </div>
        <div className="flex justify-between items-center">
          <Skeleton className="h-5 w-16 rounded-full" />
          <Skeleton className="h-7 w-24 rounded-md" />
        </div>
      </CardContent>
    </Card>
  )
}

export default function ReposPage() {
  const [repos, setRepos] = useState([])
  const [loading, setLoading] = useState(true)
  const [refreshing, setRefreshing] = useState(false)
  const [togglingId, setTogglingId] = useState(null)
  const [scanningIds, setScanningIds] = useState(new Set())
  const [search, setSearch] = useState('')
  const [manualRepoUrl, setManualRepoUrl] = useState('')
  const [manualScanning, setManualScanning] = useState(false)
  const [manualError, setManualError] = useState('')
  const navigate = useNavigate()

  const parseGithubRepoUrl = (value) => {
    try {
      const url = new URL(value.trim())
      if (url.hostname !== 'github.com') return null
      const parts = url.pathname.split('/').filter(Boolean)
      if (parts.length < 2) return null
      return {
        owner: parts[0],
        repo: parts[1].replace(/\.git$/, ''),
      }
    } catch {
      return null
    }
  }

  const load = async () => {
    const data = await getGithubRepos()
    setRepos(Array.isArray(data) ? data : [])
  }

  useEffect(() => {
    load().finally(() => setLoading(false))
  }, [])

  const handleRefresh = async () => {
    setRefreshing(true)
    await load()
    setRefreshing(false)
  }

  const handleToggle = async (repo) => {
    const newVal = !repo.is_moderated
    setTogglingId(repo.github_id)
    setRepos(prev => prev.map(r => r.github_id === repo.github_id ? { ...r, is_moderated: newVal } : r))
    // Immediately mark as analysing so the UI never flashes 'Monitored'
    if (newVal) {
      setScanningIds(prev => new Set([...prev, repo.github_id]))
    }
    try {
      const res = await moderateRepo(repo.url, repo.owner, repo.repo_name, newVal)
      if (res.repo_id) {
        await load()
        if (newVal) {
          // Remove analysing state after background scan finishes (~30s)
          setTimeout(async () => {
            await load()
            setScanningIds(prev => { const s = new Set(prev); s.delete(repo.github_id); return s })
          }, 30000)
        } else {
          setScanningIds(prev => { const s = new Set(prev); s.delete(repo.github_id); return s })
        }
      }
    } finally {
      setTogglingId(null)
    }
  }

  const filtered = repos.filter(r =>
    r.repo_name?.toLowerCase().includes(search.toLowerCase()) ||
    r.owner?.toLowerCase().includes(search.toLowerCase())
  )

  const monitoredCount = repos.filter(r => r.is_moderated).length

  const handleManualScan = async () => {
    const parsed = parseGithubRepoUrl(manualRepoUrl)
    if (!parsed) {
      setManualError('Paste a valid GitHub repository link.')
      return
    }

    setManualError('')
    setManualScanning(true)
    try {
      const result = await scanRepo(manualRepoUrl.trim())
      navigate(`/repos/${parsed.owner}/${parsed.repo}`, {
        state: {
          repoId: result.repo_id,
          repoUrl: manualRepoUrl.trim(),
          manifests: result.manifests ?? [],
        },
      })
    } catch (e) {
      setManualError(e.message || 'Scan failed. Check the repository link and backend connection.')
    } finally {
      setManualScanning(false)
    }
  }

  return (
    <div className="min-h-screen bg-background">
      <NavBar />
      <main className="max-w-6xl mx-auto px-6 py-8">

        {/* Header */}
        <div className="flex items-start justify-between mb-8">
          <div>
            <h1 className="text-3xl font-bold tracking-tight">Repositories</h1>
            <p className="text-muted-foreground mt-1 text-sm">
              Toggle scanning to monitor repos for vulnerabilities.
              {monitoredCount > 0 && (
                <span className="ml-2 text-green-400 font-medium">{monitoredCount} monitored</span>
              )}
            </p>
          </div>
          <Button onClick={handleRefresh} disabled={refreshing} variant="outline" size="sm" className="gap-2">
            <RefreshCw className={`w-3.5 h-3.5 ${refreshing ? 'animate-spin' : ''}`} />
            {refreshing ? 'Syncing…' : 'Sync GitHub'}
          </Button>
        </div>

        {/* Search */}
        <div className="relative mb-6">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground pointer-events-none" />
          <Input
            placeholder="Search repositories…"
            value={search}
            onChange={e => setSearch(e.target.value)}
            className="pl-9"
          />
        </div>

        <Card className="mb-6 border-primary/25 bg-primary/[0.04]">
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <Link2 className="w-4 h-4 text-primary" />
              Scan Any GitHub Repo
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <p className="text-sm text-muted-foreground">
              Paste a GitHub repository URL to run a one-time scan, even if it is not in your synced repo list.
            </p>
            <div className="flex flex-col gap-3 md:flex-row">
              <Input
                placeholder="https://github.com/owner/repo"
                value={manualRepoUrl}
                onChange={e => setManualRepoUrl(e.target.value)}
                onKeyDown={e => {
                  if (e.key === 'Enter' && !manualScanning) handleManualScan()
                }}
                className="md:flex-1"
              />
              <Button onClick={handleManualScan} disabled={manualScanning} className="gap-2 md:min-w-36">
                {manualScanning
                  ? <><Loader2 className="w-4 h-4 animate-spin" /> Scanning…</>
                  : <><ScanSearch className="w-4 h-4" /> Scan Link</>
                }
              </Button>
            </div>
            {manualError && (
              <div className="rounded-lg border border-destructive/20 bg-destructive/10 px-3 py-2 text-sm text-destructive">
                {manualError}
              </div>
            )}
          </CardContent>
        </Card>

        {/* Grid */}
        {loading ? (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {Array(6).fill(0).map((_, i) => <RepoCardSkeleton key={i} />)}
          </div>
        ) : !filtered.length ? (
          <div className="flex flex-col items-center justify-center py-20 text-center">
            <AlertCircle className="w-10 h-10 text-muted-foreground mb-3" />
            <p className="text-muted-foreground">
              {search ? 'No repositories match your search.' : 'No repositories found. Click Sync GitHub.'}
            </p>
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {filtered.map(repo => (
              <Card
                key={repo.github_id}
                className={`transition-all duration-200 ${
                  repo.is_moderated
                    ? 'border-primary/40 bg-primary/[0.03]'
                    : 'hover:border-border/80'
                }`}
              >
                <CardContent className="p-5">
                  {/* Title row */}
                  <div className="flex items-start justify-between mb-4">
                    <div className="min-w-0 flex-1 pr-3">
                      <a
                        href={repo.url}
                        target="_blank"
                        rel="noreferrer"
                        className="group flex items-center gap-1.5 min-w-0"
                      >
                        <GitFork className="w-3.5 h-3.5 text-muted-foreground shrink-0" />
                        <span className="font-semibold text-sm truncate group-hover:text-primary transition-colors">
                          {repo.repo_name}
                        </span>
                        <ExternalLink className="w-3 h-3 text-muted-foreground opacity-0 group-hover:opacity-100 transition-opacity shrink-0" />
                      </a>
                      <p className="text-xs text-muted-foreground mt-0.5 ml-5">{repo.owner}</p>
                    </div>
                    <Switch
                      checked={!!repo.is_moderated}
                      onCheckedChange={() => handleToggle(repo)}
                      disabled={togglingId === repo.github_id}
                    />
                  </div>

                  {/* Footer row */}
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      {repo.language && (
                        <Badge variant="secondary" className="text-xs font-normal px-1.5 py-0">
                          {repo.language}
                        </Badge>
                      )}
                      {scanningIds.has(repo.github_id) ? (
                        <span className="flex items-center gap-1 text-xs font-medium text-primary">
                          <Loader2 className="w-3 h-3 animate-spin" /> Analysing…
                        </span>
                      ) : (
                        <span className={`text-xs font-medium ${repo.is_moderated ? 'text-green-400' : 'text-muted-foreground'}`}>
                          {repo.is_moderated ? '● Monitored' : '○ Inactive'}
                        </span>
                      )}
                    </div>
                    {repo.is_moderated && repo.id ? (
                      <Button
                        variant="ghost"
                        size="sm"
                        className="h-7 px-2 text-xs text-primary hover:text-primary gap-0.5"
                        onClick={() => navigate(`/repos/${repo.owner}/${repo.repo_name}`, { state: { repoId: repo.id } })}
                      >
                        Analysis <ChevronRight className="w-3.5 h-3.5" />
                      </Button>
                    ) : null}
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        )}
      </main>
    </div>
  )
}
