import { useState, useEffect, useCallback } from 'react'
import { useParams, useLocation, Link } from 'react-router-dom'
import { getGithubRepos, getReport, getRepos, scanRepo } from '@/api'
import NavBar from '@/components/NavBar'
import SeverityBadge from '@/components/SeverityBadge'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Progress } from '@/components/ui/progress'
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription } from '@/components/ui/dialog'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { Skeleton } from '@/components/ui/skeleton'
import {
  ChevronRight, ExternalLink, GitPullRequest, AlertTriangle,
  Shield, Clock, Package2, Zap, RefreshCw, Loader2, ScanLine,
  FolderOpen, FileText, CheckCircle2, XCircle, AlertCircle
} from 'lucide-react'
import {
  PieChart, Pie, Cell, Tooltip, ResponsiveContainer,
  BarChart, Bar, XAxis, YAxis
} from 'recharts'

const SEV_COLORS = { CRITICAL: '#ef4444', HIGH: '#f97316', MEDIUM: '#eab308', LOW: '#3b82f6' }

const riskColor = score =>
  score >= 8 ? 'text-red-400' : score >= 5 ? 'text-orange-400' : score >= 3 ? 'text-yellow-400' : 'text-green-400'

const chartTooltipStyle = {
  backgroundColor: 'oklch(0.12 0.01 265)',
  borderColor: 'oklch(1 0 0 / 8%)',
  borderRadius: '8px',
  color: '#f5f5f5',
  fontSize: '12px',
}

// Infer the manifest path from a vuln's affected_file if source_manifest is absent
function inferManifest(v) {
  if (v.source_manifest) return v.source_manifest
  if (!v.affected_file) return 'package.json'
  const parts = v.affected_file.split('/')
  return parts.length > 1 ? `${parts[0]}/package.json` : 'package.json'
}

function DependencyTree({ vulns, manifests }) {
  const allManifests = new Set(manifests?.length ? manifests : [])
  vulns.forEach(v => allManifests.add(inferManifest(v)))
  if (allManifests.size === 0) return null

  const counts = {}
  allManifests.forEach(m => {
    counts[m] = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, total: 0 }
  })
  vulns.forEach(v => {
    const key = inferManifest(v)
    if (!counts[key]) counts[key] = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, total: 0 }
    if (v.severity && v.severity in counts[key]) counts[key][v.severity]++
    counts[key].total++
  })

  const entries = Object.entries(counts).sort((a, b) => b[1].total - a[1].total)

  const borderFor = (c) => {
    if (c.total === 0) return 'border-green-500/25'
    if (c.CRITICAL > 0) return 'border-red-500/35'
    if (c.HIGH > 0) return 'border-orange-500/35'
    if (c.MEDIUM > 0) return 'border-yellow-500/35'
    return 'border-blue-500/35'
  }

  const bgFor = (c) => {
    if (c.total === 0) return 'bg-green-500/5'
    if (c.CRITICAL > 0) return 'bg-red-500/5'
    if (c.HIGH > 0) return 'bg-orange-500/5'
    if (c.MEDIUM > 0) return 'bg-yellow-500/5'
    return 'bg-blue-500/5'
  }

  return (
    <Card>
      <CardHeader className="pb-3">
        <CardTitle className="text-sm font-medium text-muted-foreground flex items-center gap-2">
          <FolderOpen className="w-4 h-4" />
          Dependency Tree — {entries.length} manifest{entries.length !== 1 ? 's' : ''} scanned
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-2">
        {entries.map(([path, c]) => {
          const dir = path.includes('/') ? path.split('/').slice(0, -1).join('/') : null
          const isClean = c.total === 0
          return (
            <div
              key={path}
              className={`flex items-center gap-3 px-4 py-3 rounded-lg border ${borderFor(c)} ${bgFor(c)}`}
            >
              {/* folder + file */}
              <div className="flex items-center gap-2 min-w-0 flex-1">
                {dir ? (
                  <div className="flex items-center gap-1.5 min-w-0">
                    <FolderOpen className="w-4 h-4 text-muted-foreground shrink-0" />
                    <span className="text-xs text-muted-foreground font-mono">{dir}/</span>
                    <ChevronRight className="w-3 h-3 text-muted-foreground/40 shrink-0" />
                    <FileText className="w-3.5 h-3.5 text-muted-foreground shrink-0" />
                    <span className="text-xs font-mono font-medium">package.json</span>
                  </div>
                ) : (
                  <div className="flex items-center gap-1.5">
                    <FileText className="w-3.5 h-3.5 text-muted-foreground shrink-0" />
                    <span className="text-xs font-mono font-medium">package.json</span>
                    <span className="text-xs text-muted-foreground">(root)</span>
                  </div>
                )}
              </div>

              {/* severity pills */}
              {isClean ? (
                <div className="flex items-center gap-1.5 text-green-400 text-xs font-medium shrink-0">
                  <CheckCircle2 className="w-4 h-4" /> Clean
                </div>
              ) : (
                <div className="flex items-center gap-1.5 shrink-0">
                  {c.CRITICAL > 0 && (
                    <span className="px-2 py-0.5 rounded-full text-[10px] font-bold bg-red-500/20 text-red-400 border border-red-500/30">
                      {c.CRITICAL} CRITICAL
                    </span>
                  )}
                  {c.HIGH > 0 && (
                    <span className="px-2 py-0.5 rounded-full text-[10px] font-bold bg-orange-500/20 text-orange-400 border border-orange-500/30">
                      {c.HIGH} HIGH
                    </span>
                  )}
                  {c.MEDIUM > 0 && (
                    <span className="px-2 py-0.5 rounded-full text-[10px] font-bold bg-yellow-500/20 text-yellow-400 border border-yellow-500/30">
                      {c.MEDIUM} MED
                    </span>
                  )}
                  {c.LOW > 0 && (
                    <span className="px-2 py-0.5 rounded-full text-[10px] font-bold bg-blue-500/20 text-blue-400 border border-blue-500/30">
                      {c.LOW} LOW
                    </span>
                  )}
                </div>
              )}
            </div>
          )
        })}
      </CardContent>
    </Card>
  )
}

function LoadingSkeleton() {
  return (
    <div className="min-h-screen bg-background">
      <NavBar />
      <main className="max-w-6xl mx-auto px-6 py-8 space-y-6">
        <Skeleton className="h-5 w-56" />
        <Skeleton className="h-9 w-72" />
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          {Array(4).fill(0).map((_, i) => <Skeleton key={i} className="h-24 rounded-xl" />)}
        </div>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <Skeleton className="h-72 rounded-xl" />
          <Skeleton className="h-72 rounded-xl" />
        </div>
        <Skeleton className="h-96 rounded-xl" />
      </main>
    </div>
  )
}

export default function RepoDetailPage() {
  const { owner, name } = useParams()
  const location = useLocation()

  const [repoId, setRepoId] = useState(location.state?.repoId ?? null)
  const [repoUrl, setRepoUrl] = useState(location.state?.repoUrl ?? null)
  const [report, setReport] = useState(null)
  const [manifests, setManifests] = useState(location.state?.manifests ?? [])
  const [loading, setLoading] = useState(true)
  const [scanning, setScanning] = useState(false)
  const [scanError, setScanError] = useState('')
  const [error, setError] = useState('')
  const [prOpen, setPrOpen] = useState(false)

  const loadReport = useCallback(async (id) => {
    const data = await getReport(id)
    setReport(data)
  }, [])

  useEffect(() => {
    const init = async () => {
      try {
        let id = repoId
        let url = repoUrl

        if (!id) {
          const [githubRepos, savedRepos] = await Promise.all([
            getGithubRepos().catch(() => []),
            getRepos().catch(() => []),
          ])
          const match = [...githubRepos, ...savedRepos].find(r => r.owner === owner && r.repo_name === name)
          if (!match?.id) {
            setError('Repository not found. Scan it from Repositories or enable monitoring first.')
            return
          }
          id = match.id
          url = match.url
          setRepoId(id)
          setRepoUrl(url)
        } else if (!url) {
          const [githubRepos, savedRepos] = await Promise.all([
            getGithubRepos().catch(() => []),
            getRepos().catch(() => []),
          ])
          const match = [...githubRepos, ...savedRepos].find(r => String(r.id) === String(id))
          if (match) {
            url = match.url
            setRepoUrl(url)
          }
        }

        await loadReport(id)
      } catch {
        setError('Failed to load vulnerability report.')
      } finally {
        setLoading(false)
      }
    }
    init()
  }, [owner, name])

  const handleScan = async () => {
    if (!repoUrl) {
      setScanError('Repository URL not found. Try navigating back to Repositories and clicking Analysis again.')
      return
    }
    setScanError('')
    setScanning(true)
    try {
      const result = await scanRepo(repoUrl)
      if (result.manifests) setManifests(result.manifests)
      await loadReport(repoId)
    } catch (e) {
      setScanError(e.message || 'Scan failed — check that the backend is running.')
    } finally {
      setScanning(false)
    }
  }

  if (loading) return <LoadingSkeleton />

  if (error) {
    return (
      <div className="min-h-screen bg-background">
        <NavBar />
        <main className="max-w-6xl mx-auto px-6 py-20 text-center">
          <AlertTriangle className="w-12 h-12 mx-auto mb-3 text-destructive" />
          <p className="text-muted-foreground">{error}</p>
          <Link to="/repos">
            <Button variant="outline" className="mt-4">Back to Repositories</Button>
          </Link>
        </main>
      </div>
    )
  }

  const vulns = report?.vulnerabilities ?? []
  const sevCounts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 }
  vulns.forEach(v => { if (v.severity in sevCounts) sevCounts[v.severity]++ })

  const pieData = Object.entries(sevCounts)
    .filter(([, v]) => v > 0)
    .map(([k, v]) => ({ name: k, value: v }))

  const barData = [...vulns]
    .sort((a, b) => b.risk_score - a.risk_score)
    .slice(0, 5)
    .map(v => ({ name: v.package_name, risk: v.risk_score }))

  const lastScanned = report?.repo?.scanned_at
    ? new Date(report.repo.scanned_at).toLocaleString()
    : null

  const criticalAndHigh = vulns.filter(v => v.severity === 'CRITICAL' || v.severity === 'HIGH')
  const neverScanned = !lastScanned && vulns.length === 0
  const hasTreeData = vulns.length > 0 || manifests.length > 0

  return (
    <div className="min-h-screen bg-background">
      <NavBar />
      <main className="max-w-6xl mx-auto px-6 py-8 space-y-8">

        {/* Breadcrumb */}
        <div className="flex items-center gap-2 text-sm text-muted-foreground">
          <Link to="/repos" className="hover:text-foreground transition-colors">Repositories</Link>
          <ChevronRight className="w-4 h-4" />
          <span className="text-foreground font-medium">{owner}/{name}</span>
        </div>

        {/* Header */}
        <div className="flex items-start justify-between">
          <div>
            <h1 className="text-3xl font-bold tracking-tight">{owner}/{name}</h1>
            <div className="flex items-center gap-1.5 mt-2 text-xs text-muted-foreground">
              <Clock className="w-3.5 h-3.5" />
              {lastScanned ? `Last scanned: ${lastScanned}` : 'Never scanned'}
            </div>
          </div>
          <div className="flex gap-2">
            <Button
              onClick={handleScan}
              disabled={scanning}
              variant="outline"
              className="gap-2"
            >
              {scanning
                ? <><Loader2 className="w-4 h-4 animate-spin" /> Scanning…</>
                : <><ScanLine className="w-4 h-4" /> {vulns.length === 0 ? 'Run Scan' : 'Re-scan'}</>
              }
            </Button>
            <Button onClick={() => setPrOpen(true)} className="gap-2" disabled={vulns.length === 0}>
              <GitPullRequest className="w-4 h-4" />
              Fix PR
            </Button>
          </div>
        </div>

        {/* Scan error */}
        {scanError && (
          <div className="p-3 rounded-lg bg-destructive/10 border border-destructive/20 text-destructive text-sm">
            {scanError}
          </div>
        )}

        {/* Not-yet-scanned callout */}
        {neverScanned && !scanning && (
          <div className="p-5 rounded-xl border border-primary/30 bg-primary/5 flex items-start gap-4">
            <ScanLine className="w-5 h-5 text-primary mt-0.5 shrink-0" />
            <div>
              <p className="font-medium text-sm">No scan results yet</p>
              <p className="text-muted-foreground text-xs mt-1">
                A background scan was triggered when you enabled monitoring, but it may still be running.
                Click <strong>Run Scan</strong> to scan immediately and see results.
              </p>
            </div>
          </div>
        )}

        {/* Zero vulns but was scanned */}
        {!neverScanned && vulns.length === 0 && !scanning && (
          <div className="p-5 rounded-xl border border-green-500/30 bg-green-500/5 flex items-center gap-4">
            <Shield className="w-5 h-5 text-green-400 shrink-0" />
            <div>
              <p className="font-medium text-sm text-green-400">No vulnerabilities found</p>
              <p className="text-muted-foreground text-xs mt-1">
                Scanned on {lastScanned}. Use <strong>Re-scan</strong> to check for new issues.
              </p>
            </div>
          </div>
        )}

        {/* Scanning banner */}
        {scanning && (
          <div className="p-5 rounded-xl border border-primary/30 bg-primary/5 flex items-center gap-4">
            <Loader2 className="w-5 h-5 text-primary animate-spin shrink-0" />
            <div>
              <p className="font-medium text-sm">Scanning repository…</p>
              <p className="text-muted-foreground text-xs mt-1">
                Checking all <code className="text-primary">package.json</code> files across every folder for vulnerabilities.
              </p>
            </div>
          </div>
        )}

        {/* Dependency Tree — always show after scan or when vulns exist */}
        {hasTreeData && !scanning && (
          <DependencyTree vulns={vulns} manifests={manifests} />
        )}

        {/* Summary cards */}
        {vulns.length > 0 && (
          <>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <Card>
                <CardContent className="p-5">
                  <div className="flex items-center gap-2 text-muted-foreground text-xs mb-2">
                    <Package2 className="w-3.5 h-3.5" /> Total Vulns
                  </div>
                  <p className="text-3xl font-bold">{report?.total_vulns ?? 0}</p>
                </CardContent>
              </Card>
              <Card className="border-red-500/20">
                <CardContent className="p-5">
                  <div className="flex items-center gap-2 text-red-400 text-xs mb-2">
                    <Zap className="w-3.5 h-3.5" /> Critical
                  </div>
                  <p className="text-3xl font-bold text-red-400">{sevCounts.CRITICAL}</p>
                </CardContent>
              </Card>
              <Card className="border-orange-500/20">
                <CardContent className="p-5">
                  <div className="flex items-center gap-2 text-orange-400 text-xs mb-2">
                    <AlertTriangle className="w-3.5 h-3.5" /> High
                  </div>
                  <p className="text-3xl font-bold text-orange-400">{sevCounts.HIGH}</p>
                </CardContent>
              </Card>
              <Card className="border-green-500/20">
                <CardContent className="p-5">
                  <div className="flex items-center gap-2 text-green-400 text-xs mb-2">
                    <Shield className="w-3.5 h-3.5" /> Low Risk
                  </div>
                  <p className="text-3xl font-bold text-green-400">{sevCounts.LOW}</p>
                </CardContent>
              </Card>
            </div>

            {/* Charts */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <Card>
                <CardHeader className="pb-2">
                  <CardTitle className="text-sm font-medium text-muted-foreground">Severity Distribution</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="h-52">
                    <ResponsiveContainer>
                      <PieChart>
                        <Pie data={pieData} innerRadius={50} outerRadius={75} paddingAngle={3} dataKey="value" stroke="none">
                          {pieData.map((entry, i) => <Cell key={i} fill={SEV_COLORS[entry.name]} />)}
                        </Pie>
                        <Tooltip contentStyle={chartTooltipStyle} />
                      </PieChart>
                    </ResponsiveContainer>
                  </div>
                  <div className="flex flex-wrap justify-center gap-4 mt-1">
                    {pieData.map(d => (
                      <div key={d.name} className="flex items-center gap-1.5 text-xs text-muted-foreground">
                        <div className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: SEV_COLORS[d.name] }} />
                        {d.name} ({d.value})
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardHeader className="pb-2">
                  <CardTitle className="text-sm font-medium text-muted-foreground">Top Risk Dependencies</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="h-52">
                    <ResponsiveContainer>
                      <BarChart data={barData} layout="vertical" margin={{ left: 0, right: 24, top: 4, bottom: 4 }}>
                        <XAxis type="number" domain={[0, 10]} hide />
                        <YAxis
                          dataKey="name"
                          type="category"
                          width={90}
                          axisLine={false}
                          tickLine={false}
                          tick={{ fill: '#71717a', fontSize: 11 }}
                        />
                        <Tooltip cursor={{ fill: 'oklch(1 0 0 / 4%)' }} contentStyle={chartTooltipStyle} />
                        <Bar dataKey="risk" radius={[0, 4, 4, 0]} barSize={14}>
                          {barData.map((entry, i) => (
                            <Cell key={i} fill={entry.risk >= 8 ? '#ef4444' : entry.risk >= 5 ? '#f97316' : '#818cf8'} />
                          ))}
                        </Bar>
                      </BarChart>
                    </ResponsiveContainer>
                  </div>
                </CardContent>
              </Card>
            </div>

            {/* Vulnerability table */}
            <Card>
              <CardHeader className="pb-0">
                <CardTitle className="text-sm font-medium text-muted-foreground">
                  All Vulnerabilities ({vulns.length})
                </CardTitle>
              </CardHeader>
              <CardContent className="pt-4 px-0 pb-0">
                <div className="overflow-x-auto">
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead className="pl-6">Package</TableHead>
                        <TableHead>Version</TableHead>
                        <TableHead>CVE / ID</TableHead>
                        <TableHead>Severity</TableHead>
                        <TableHead>Risk</TableHead>
                        <TableHead className="max-w-xs">Summary / Fix</TableHead>
                        <TableHead>Source</TableHead>
                        <TableHead className="pr-6">Advisory</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {vulns.map((v, i) => (
                        <TableRow key={i}>
                          <TableCell className="pl-6 font-mono text-xs text-blue-300 font-medium">
                            {v.package_name}
                          </TableCell>
                          <TableCell className="font-mono text-xs text-muted-foreground">
                            {v.installed_version}
                          </TableCell>
                          <TableCell className="font-mono text-xs text-foreground/80">
                            {v.vuln_id || '—'}
                          </TableCell>
                          <TableCell>
                            <SeverityBadge severity={v.severity} />
                          </TableCell>
                          <TableCell>
                            <div className="flex items-center gap-2 min-w-[80px]">
                              <Progress value={(v.risk_score / 10) * 100} className="h-1.5 w-14" />
                              <span className={`text-xs font-bold tabular-nums ${riskColor(v.risk_score)}`}>
                                {v.risk_score}
                              </span>
                            </div>
                          </TableCell>
                          <TableCell className="text-xs max-w-xs">
                            <p className="text-muted-foreground line-clamp-1">{v.summary || '—'}</p>
                            {v.fix_suggestion && (
                              <p className="text-green-400 mt-0.5 line-clamp-1">↳ {v.fix_suggestion}</p>
                            )}
                            {v.affected_file && (
                              <p className="font-mono text-yellow-400 text-[10px] mt-0.5">
                                {v.affected_file}{v.line_number ? `:${v.line_number}` : ''}
                              </p>
                            )}
                          </TableCell>
                          <TableCell className="text-xs">
                            {inferManifest(v) ? (
                              <span className="font-mono text-muted-foreground text-[10px]">
                                {inferManifest(v)}
                              </span>
                            ) : <span className="text-muted-foreground">—</span>}
                          </TableCell>
                          <TableCell className="pr-6">
                            {v.vuln_id ? (
                              <a href={`https://github.com/advisories/${v.vuln_id}`} target="_blank" rel="noreferrer">
                                <Button variant="ghost" size="sm" className="h-7 w-7 p-0">
                                  <ExternalLink className="w-3.5 h-3.5" />
                                </Button>
                              </a>
                            ) : <span className="text-muted-foreground text-xs">—</span>}
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </div>
              </CardContent>
            </Card>
          </>
        )}
      </main>

      {/* Fix PR Dialog */}
      <Dialog open={prOpen} onOpenChange={setPrOpen}>
        <DialogContent className="max-w-md">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <GitPullRequest className="w-5 h-5 text-primary" />
              Automated Fix PR
            </DialogTitle>
            <DialogDescription>
              Automated pull request generation is coming soon. Here are the critical and high severity packages to update:
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-2 max-h-64 overflow-y-auto">
            {criticalAndHigh.length ? criticalAndHigh.map((v, i) => (
              <div key={i} className="flex items-center justify-between p-3 rounded-lg bg-secondary text-sm gap-3">
                <span className="font-mono text-xs truncate">{v.package_name}@{v.installed_version}</span>
                <SeverityBadge severity={v.severity} />
              </div>
            )) : (
              <p className="text-center text-muted-foreground text-sm py-4">
                No critical or high severity issues.
              </p>
            )}
          </div>
        </DialogContent>
      </Dialog>
    </div>
  )
}
