import { useState, useEffect, useMemo, useRef } from 'react'
import NavBar from '@/components/NavBar'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Badge } from '@/components/ui/badge'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription } from '@/components/ui/dialog'
import { resolveCve, blastRadiusScan, draftIssue } from '@/api'
import {
  Loader2, Search, Download, ExternalLink, AlertCircle,
  Zap, Copy, Check, RefreshCw, Target, Package2
} from 'lucide-react'

const EXAMPLE_CVES = [
  { id: 'CVE-2022-25883', label: 'semver ReDoS' },
  { id: 'CVE-2021-23337', label: 'lodash command injection' },
  { id: 'CVE-2024-4068', label: 'braces DoS' },
]

const LOADING_MESSAGES = [
  'Resolving CVE...',
  'Querying dependency graph...',
  'Ranking by impact...',
  'Generating report...',
]

function severityBadgeVariant(sev) {
  const s = String(sev || '').toUpperCase()
  if (s.includes('CRITICAL') || s.includes('HIGH') || s.startsWith('CVSS:3'))
    return 'text-red-400'
  if (s.includes('MEDIUM') || s.includes('MODERATE'))
    return 'text-amber-400'
  if (s.includes('LOW'))
    return 'text-yellow-300'
  return 'text-muted-foreground'
}

export default function BlastRadiusPage() {
  const [mode, setMode] = useState('cve')
  const [cveInput, setCveInput] = useState('CVE-2022-25883')
  const [pkgName, setPkgName] = useState('')
  const [pkgVersion, setPkgVersion] = useState('')

  const [loading, setLoading] = useState(false)
  const [loadingIdx, setLoadingIdx] = useState(0)

  const [error, setError] = useState('')
  const [retryAvailable, setRetryAvailable] = useState(false)
  const lastScanArgs = useRef(null)

  const [results, setResults] = useState(null)
  const [filter, setFilter] = useState('')
  const [modalOpen, setModalOpen] = useState(false)
  const [modal, setModal] = useState(null)
  const [copyStatus, setCopyStatus] = useState('')

  useEffect(() => {
    if (!loading) return
    setLoadingIdx(0)
    const id = setInterval(() => {
      setLoadingIdx(i => (i + 1) % LOADING_MESSAGES.length)
    }, 900)
    return () => clearInterval(id)
  }, [loading])

  async function runScan(overrideCve) {
    setError('')
    setRetryAvailable(false)
    setResults(null)
    setFilter('')
    setLoading(true)

    try {
      let resolveBody
      if (overrideCve) {
        resolveBody = { cveId: overrideCve }
      } else if (mode === 'cve') {
        const id = cveInput.trim()
        if (!id) throw new Error('Enter a CVE ID')
        resolveBody = { cveId: id }
      } else {
        const name = pkgName.trim()
        if (!name) throw new Error('Enter a package name')
        resolveBody = { packageName: name, version: pkgVersion.trim() }
      }

      lastScanArgs.current = resolveBody

      const resolved = await resolveCve(resolveBody)
      const blast = await blastRadiusScan({
        packageName: resolved.package,
        version: resolved.affectedVersions,
      })

      setResults({ resolved, blast })
    } catch (err) {
      setError(err.message || 'Something went wrong')
      setRetryAvailable(true)
    } finally {
      setLoading(false)
    }
  }

  async function handleDraftIssue(dep) {
    if (!results) return
    const resolved = results.resolved
    try {
      const data = await draftIssue({
        vulnerablePackage: resolved.package,
        affectedVersions: resolved.affectedVersions,
        cveId: resolved.cveId,
        dependentPackage: dep.name,
        repoUrl: dep.repoUrl,
      })
      if (data.issueUrl) {
        window.open(data.issueUrl, '_blank', 'noopener,noreferrer')
      } else {
        setModal({
          title: data.title,
          body: data.body,
          text: data.copyableText,
          dependent: dep.name,
        })
        setModalOpen(true)
      }
    } catch (err) {
      setError(err.message)
    }
  }

  function copyModalText() {
    if (!modal) return
    navigator.clipboard.writeText(modal.text).then(
      () => {
        setCopyStatus('Copied!')
        setTimeout(() => setCopyStatus(''), 1500)
      },
      () => setCopyStatus('Copy failed')
    )
  }

  function downloadJson() {
    if (!results) return
    const payload = {
      generatedAt: new Date().toISOString(),
      ...results,
    }
    const blob = new Blob([JSON.stringify(payload, null, 2)], {
      type: 'application/json',
    })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    const safeId = (results.resolved.cveId || 'scan').replace(/[^A-Za-z0-9_-]/g, '_')
    a.download = `blast-radius-${safeId}.json`
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    URL.revokeObjectURL(url)
  }

  const filteredDeps = useMemo(() => {
    const list = results?.blast?.dependents || []
    if (!filter.trim()) return list
    const q = filter.toLowerCase()
    return list.filter(d => d.name.toLowerCase().includes(q))
  }, [filter, results])

  return (
    <div className="min-h-screen bg-background">
      <NavBar />
      <main className="max-w-6xl mx-auto px-6 py-8">

        {/* Header */}
        <header className="mb-8">
          <div className="flex items-baseline gap-3 flex-wrap">
            <h1 className="text-3xl font-bold tracking-tight flex items-center gap-2">
              <Target className="w-7 h-7 text-destructive" />
              <span className="text-destructive">Blast</span> Radius
            </h1>
            <Badge variant="secondary" className="text-[10px] font-mono uppercase tracking-widest">
              v1.0 · demo
            </Badge>
          </div>
          <p className="text-muted-foreground mt-1 text-sm">
            Map the downstream impact of open-source CVEs across the npm ecosystem.
          </p>
        </header>

        {/* Input Section */}
        <Card className="mb-6">
          <CardContent className="p-6">
            {/* Mode Tabs */}
            <div className="flex gap-2 mb-4">
              <Button
                onClick={() => setMode('cve')}
                variant={mode === 'cve' ? 'default' : 'outline'}
                size="sm"
                className={mode === 'cve' ? 'bg-destructive hover:bg-destructive/90' : ''}
              >
                Search by CVE ID
              </Button>
              <Button
                onClick={() => setMode('package')}
                variant={mode === 'package' ? 'default' : 'outline'}
                size="sm"
                className={mode === 'package' ? 'bg-destructive hover:bg-destructive/90' : ''}
              >
                Search by Package
              </Button>
            </div>

            {/* Inputs */}
            {mode === 'cve' ? (
              <Input
                value={cveInput}
                onChange={e => setCveInput(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && runScan()}
                placeholder="CVE-2022-25883"
                spellCheck={false}
                className="font-mono"
              />
            ) : (
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                <Input
                  value={pkgName}
                  onChange={e => setPkgName(e.target.value)}
                  onKeyDown={e => e.key === 'Enter' && runScan()}
                  placeholder="lodash"
                  spellCheck={false}
                  className="font-mono"
                />
                <Input
                  value={pkgVersion}
                  onChange={e => setPkgVersion(e.target.value)}
                  onKeyDown={e => e.key === 'Enter' && runScan()}
                  placeholder="<4.17.21"
                  spellCheck={false}
                  className="font-mono"
                />
              </div>
            )}

            {/* Scan Button */}
            <div className="mt-4 flex items-center gap-4 flex-wrap">
              <Button
                onClick={() => runScan()}
                disabled={loading}
                className="bg-destructive hover:bg-destructive/90 text-white gap-2 shadow-lg shadow-red-900/30"
              >
                {loading ? (
                  <><Loader2 className="w-4 h-4 animate-spin" /> Scanning…</>
                ) : (
                  <><Zap className="w-4 h-4" /> Scan Blast Radius</>
                )}
              </Button>
              {loading && (
                <span className="flex items-center gap-2 text-sm text-muted-foreground">
                  <Loader2 className="w-4 h-4 animate-spin text-destructive" />
                  <span className="font-mono">{LOADING_MESSAGES[loadingIdx]}</span>
                </span>
              )}
            </div>

            {/* Example CVEs */}
            <div className="mt-5 flex flex-wrap gap-2 items-center">
              <span className="text-[10px] text-muted-foreground uppercase tracking-widest mr-1">
                Example CVEs:
              </span>
              {EXAMPLE_CVES.map(ex => (
                <Button
                  key={ex.id}
                  disabled={loading}
                  variant="outline"
                  size="sm"
                  className="text-xs font-mono h-7 gap-1"
                  onClick={() => {
                    setMode('cve')
                    setCveInput(ex.id)
                    runScan(ex.id)
                  }}
                >
                  {ex.id} <span className="text-muted-foreground">· {ex.label}</span>
                </Button>
              ))}
            </div>

            {/* Error */}
            {error && (
              <div className="mt-4 rounded-lg border border-destructive/30 bg-destructive/10 p-3 text-sm">
                <div className="flex items-start justify-between gap-3">
                  <div>
                    <div className="font-semibold text-destructive mb-0.5 flex items-center gap-1.5">
                      <AlertCircle className="w-4 h-4" /> Error
                    </div>
                    <div className="text-foreground/80">{error}</div>
                  </div>
                  {retryAvailable && (
                    <Button
                      onClick={() => runScan()}
                      variant="outline"
                      size="sm"
                      className="gap-1.5"
                    >
                      <RefreshCw className="w-3.5 h-3.5" /> Retry
                    </Button>
                  )}
                </div>
              </div>
            )}
          </CardContent>
        </Card>

        {/* Results */}
        {results && (
          <div className="space-y-4 animate-in fade-in-0 slide-in-from-bottom-4 duration-300">

            {/* Summary Cards */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <Card>
                <CardContent className="p-5">
                  <div className="text-[10px] text-muted-foreground uppercase tracking-widest">
                    Affected
                  </div>
                  <div className="text-3xl font-bold text-destructive font-mono mt-1 leading-none">
                    {results.blast.dependents.length}
                  </div>
                  <div className="text-xs text-muted-foreground mt-1">
                    public dependents shown
                    {results.blast.totalCount &&
                    results.blast.totalCount !== results.blast.dependents.length
                      ? ` · ${results.blast.totalCount.toLocaleString()} total`
                      : ''}
                  </div>
                </CardContent>
              </Card>
              <Card>
                <CardContent className="p-5">
                  <div className="text-[10px] text-muted-foreground uppercase tracking-widest">
                    CVE
                  </div>
                  <div className="text-sm font-mono mt-1 break-all text-foreground">
                    {results.resolved.cveId}
                  </div>
                </CardContent>
              </Card>
              <Card>
                <CardContent className="p-5">
                  <div className="text-[10px] text-muted-foreground uppercase tracking-widest">
                    Vulnerable
                  </div>
                  <div className="text-sm font-mono mt-1 break-all">
                    <span className="text-foreground">{results.resolved.package}</span>
                    <span className="text-muted-foreground">@{results.resolved.affectedVersions}</span>
                  </div>
                </CardContent>
              </Card>
              <Card>
                <CardContent className="p-5">
                  <div className="text-[10px] text-muted-foreground uppercase tracking-widest">
                    Severity
                  </div>
                  <div className={`text-sm font-mono mt-1 font-semibold ${severityBadgeVariant(results.resolved.severity)}`}>
                    {results.resolved.severity}
                  </div>
                </CardContent>
              </Card>
            </div>

            {/* Summary description */}
            {results.resolved.summary && (
              <Card>
                <CardContent className="p-5">
                  <p className="text-sm text-muted-foreground leading-relaxed">
                    {results.resolved.summary}
                  </p>
                </CardContent>
              </Card>
            )}

            {/* Filter + download */}
            <div className="flex items-center gap-3">
              <div className="relative flex-1">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground pointer-events-none" />
                <Input
                  value={filter}
                  onChange={e => setFilter(e.target.value)}
                  placeholder="Filter by package name..."
                  spellCheck={false}
                  className="pl-9 font-mono"
                />
              </div>
              <Button onClick={downloadJson} variant="outline" className="gap-2">
                <Download className="w-4 h-4" /> JSON
              </Button>
            </div>

            {/* Dependents Table */}
            {filteredDeps.length === 0 ? (
              <Card>
                <CardContent className="p-8 text-center text-muted-foreground text-sm">
                  {results.blast.dependents.length === 0
                    ? 'No public dependents found — this package may be leaf or unindexed.'
                    : 'No dependents match your filter.'}
                </CardContent>
              </Card>
            ) : (
              <Card>
                <CardContent className="px-0 pb-0 pt-0">
                  <div className="overflow-x-auto">
                    <Table>
                      <TableHeader>
                        <TableRow>
                          <TableHead className="pl-6 w-14">Rank</TableHead>
                          <TableHead>Package Name</TableHead>
                          <TableHead>Version</TableHead>
                          <TableHead>Has Repo</TableHead>
                          <TableHead className="text-right">Downstream</TableHead>
                          <TableHead className="text-right pr-6">Action</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {filteredDeps.map((d, idx) => (
                          <TableRow key={`${d.name}-${idx}`}>
                            <TableCell className="pl-6 font-mono text-muted-foreground">
                              #{idx + 1}
                            </TableCell>
                            <TableCell className="font-mono text-sm text-blue-300 font-medium">
                              {d.name}
                            </TableCell>
                            <TableCell className="font-mono text-sm text-muted-foreground">
                              {d.version}
                            </TableCell>
                            <TableCell>
                              {d.repoUrl ? (
                                <a
                                  href={d.repoUrl}
                                  target="_blank"
                                  rel="noopener noreferrer"
                                  className="text-green-400 hover:underline font-mono text-xs flex items-center gap-1"
                                  title={d.repoUrl}
                                >
                                  <ExternalLink className="w-3 h-3" /> GitHub
                                </a>
                              ) : (
                                <span className="text-muted-foreground font-mono text-xs">—</span>
                              )}
                            </TableCell>
                            <TableCell className="font-mono text-right text-foreground/80">
                              {(d.dependentCount || 0).toLocaleString()}
                            </TableCell>
                            <TableCell className="text-right pr-6">
                              <Button
                                onClick={() => handleDraftIssue(d)}
                                variant="outline"
                                size="sm"
                                className="text-xs h-7 hover:bg-destructive hover:text-white hover:border-destructive transition-colors"
                              >
                                Draft Issue
                              </Button>
                            </TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </div>
                </CardContent>
              </Card>
            )}
          </div>
        )}

        {/* Footer */}
        <footer className="mt-10 pt-6 border-t border-border text-xs text-muted-foreground flex justify-between items-center flex-wrap gap-2">
          <span>
            Data sources: <span className="font-mono text-foreground/60">OSV.dev</span> ·{' '}
            <span className="font-mono text-foreground/60">deps.dev</span> ·{' '}
            <span className="font-mono text-foreground/60">ecosyste.ms</span>
          </span>
          <span className="font-mono">No data is stored. All scans are ephemeral.</span>
        </footer>
      </main>

      {/* Draft Issue Modal */}
      <Dialog open={modalOpen} onOpenChange={setModalOpen}>
        <DialogContent className="max-w-2xl">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Package2 className="w-5 h-5 text-primary" />
              No GitHub repo detected
            </DialogTitle>
            <DialogDescription>
              <span className="font-mono">{modal?.dependent}</span> has no linked GitHub
              repository. Copy the issue text below and file it manually with the maintainer.
            </DialogDescription>
          </DialogHeader>
          <textarea
            readOnly
            value={modal?.text || ''}
            className="w-full h-72 bg-secondary border border-border rounded-lg p-3 text-xs font-mono focus:outline-none focus:ring-2 focus:ring-primary/50 resize-none"
          />
          <div className="flex gap-2 justify-end items-center">
            {copyStatus && (
              <span className="text-xs text-green-400 mr-2 flex items-center gap-1">
                <Check className="w-3.5 h-3.5" /> {copyStatus}
              </span>
            )}
            <Button onClick={copyModalText} variant="outline" className="gap-2">
              <Copy className="w-4 h-4" /> Copy to Clipboard
            </Button>
            <Button onClick={() => setModalOpen(false)} className="bg-destructive hover:bg-destructive/90 text-white">
              Close
            </Button>
          </div>
        </DialogContent>
      </Dialog>
    </div>
  )
}
