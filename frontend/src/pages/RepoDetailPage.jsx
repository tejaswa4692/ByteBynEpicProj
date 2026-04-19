import React, { useState, useEffect, useCallback } from 'react'
import { useParams, useLocation, Link } from 'react-router-dom'
import { getGithubRepos, getReport, getRepos, scanRepo, certifyRepo, moderateRepo } from '@/api'
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
  FolderOpen, FileText, CheckCircle2, XCircle, AlertCircle, FileDown, Award
} from 'lucide-react'
import {
  PieChart, Pie, Cell, Tooltip, ResponsiveContainer,
  BarChart, Bar, XAxis, YAxis
} from 'recharts'
import { jsPDF } from 'jspdf'
import autoTable from 'jspdf-autotable'

const LoadingSkeleton = () => (
  <div className="min-h-screen bg-background">
    <NavBar />
    <main className="max-w-6xl mx-auto px-6 py-8 space-y-8">
      <Skeleton className="h-8 w-64" />
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <Skeleton className="h-40 w-full" />
        <Skeleton className="h-40 w-full" />
        <Skeleton className="h-40 w-full" />
      </div>
    </main>
  </div>
)

const SEV_COLORS = {
  CRITICAL: '#ef4444',
  HIGH: '#f97316',
  MEDIUM: '#eab308',
  LOW: '#22c55e',
}

const chartTooltipStyle = {
  backgroundColor: 'oklch(0.2 0 0)',
  border: '1px solid oklch(1 0 0 / 10%)',
  borderRadius: '8px',
  fontSize: '12px',
}

const riskColor = score =>
  score >= 8 ? 'text-red-400' : score >= 5 ? 'text-orange-400' : 'text-green-400'

const inferManifest = v => v?.source_manifest || v?.affected_file?.split('/')?.[0] || null

const DependencyTree = ({ vulns, manifests }) => {
  const groups = {}
  vulns.forEach(v => {
    const key = v.source_manifest || 'root'
    if (!groups[key]) groups[key] = []
    groups[key].push(v)
  })
  const keys = [...new Set([...Object.keys(groups), ...(manifests || [])])]
  if (!keys.length) return null
  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="text-sm font-medium text-muted-foreground flex items-center gap-2">
          <FolderOpen className="w-4 h-4" /> Dependency Tree
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-3">
        {keys.map(k => (
          <div key={k} className="p-3 rounded-lg bg-secondary/50 border border-border">
            <p className="font-mono text-xs text-primary mb-2 flex items-center gap-1.5">
              <FileText className="w-3.5 h-3.5" /> {k}
            </p>
            {(groups[k] || []).map((v, i) => (
              <div key={i} className="flex items-center gap-2 text-xs text-muted-foreground pl-4 py-0.5">
                <span className="font-mono text-blue-300">{v.package_name}@{v.installed_version}</span>
                <span style={{ color: SEV_COLORS[v.severity] ?? '#71717a' }}>{v.severity}</span>
              </div>
            ))}
          </div>
        ))}
      </CardContent>
    </Card>
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
  const [expanded, setExpanded] = useState({})
  const [certifying, setCertifying] = useState(false)
  const [certError, setCertError] = useState('')
  const [certSuccess, setCertSuccess] = useState('')

  const toggle = i => setExpanded(p => ({ ...p, [i]: !p[i] }))

  const loadReport = useCallback(async (id) => {
    const data = await getReport(id)
    setReport(data)
  }, [])
  
  const handleCertify = async () => {
    setCertifying(true)
    setCertError('')
    setCertSuccess('')
    try {
      const res = await certifyRepo(repoId)
      setCertSuccess(res.ipfs_hash)
    } catch (e) {
      setCertError(e.message || 'Minting failed.')
    } finally {
      setCertifying(false)
      loadReport(repoId)
    }
  }

  useEffect(() => {
    const init = async () => {
      try {
        let id = repoId
        let url = repoUrl

        if (!id) {
          // Try to find it in either repo list
          const [githubRepos, savedRepos] = await Promise.all([
            getGithubRepos().catch(() => []),
            getRepos().catch(() => []),
          ])
          const all = [...(Array.isArray(githubRepos) ? githubRepos : []), ...(Array.isArray(savedRepos) ? savedRepos : [])]
          
          // Case-insensitive match since owner casing can differ
          const match = all.find(r =>
            r.owner?.toLowerCase() === owner?.toLowerCase() &&
            r.repo_name?.toLowerCase() === name?.toLowerCase()
          )
          
          if (match?.id) {
            id = match.id
            url = match.url ?? `https://github.com/${match.owner}/${match.repo_name}`
          } else {
            // Construct the URL manually and trigger a save via moderateRepo
            url = `https://github.com/${owner}/${name}`
            const mod = await moderateRepo(url, owner, name, false).catch(() => null)
            if (mod?.repo_id) {
              id = mod.repo_id
            } else {
              setError(`Could not load "${owner}/${name}". Make sure this repo exists and you have access to it.`)
              return
            }
          }
          setRepoId(id)
          setRepoUrl(url)
        } else if (!url) {
          const [githubRepos, savedRepos] = await Promise.all([
            getGithubRepos().catch(() => []),
            getRepos().catch(() => []),
          ])
          const match = [...(Array.isArray(githubRepos) ? githubRepos : []), ...(Array.isArray(savedRepos) ? savedRepos : [])].find(r => String(r.id) === String(id))
          if (match) {
            url = match.url
            setRepoUrl(url)
          }
        }

        await loadReport(id)
      } catch (e) {
        setError('Failed to load vulnerability report. Is the backend running?')
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

  const downloadPdf = async () => {
    try {
      const vulns = report?.vulnerabilities ?? []
      const doc = new jsPDF({ orientation: 'landscape', unit: 'mm', format: 'a4' })
      const pageWidth = doc.internal.pageSize.getWidth()

      // ── Header bar ──────────────────────────────────────────────
      doc.setFillColor(79, 70, 229)
      doc.rect(0, 0, pageWidth, 22, 'F')
      doc.setFontSize(16)
      doc.setTextColor(255, 255, 255)
      doc.setFont('helvetica', 'bold')
      doc.text('RepodoGG  ·  Security Vulnerability Report', 14, 14)

      // ── Meta ────────────────────────────────────────────────────
      doc.setFontSize(10)
      doc.setTextColor(60, 60, 80)
      doc.setFont('helvetica', 'normal')
      doc.text(`Repository: ${owner}/${name}`, 14, 30)
      doc.text(`Generated: ${new Date().toLocaleString()}`, 14, 36)
      doc.text(`Scanned by: RepodoGG Intelligence Platform`, 14, 42)

      // ── Summary pills ────────────────────────────────────────────
      const crit  = vulns.filter(v => v.severity === 'CRITICAL').length
      const high  = vulns.filter(v => v.severity === 'HIGH').length
      const med   = vulns.filter(v => v.severity === 'MEDIUM').length
      const low   = vulns.filter(v => v.severity === 'LOW').length

      const pills = [
        { label: 'CRITICAL', count: crit,  color: [239, 68,  68]  },
        { label: 'HIGH',     count: high,  color: [249, 115, 22]  },
        { label: 'MEDIUM',   count: med,   color: [234, 179, 8]   },
        { label: 'LOW',      count: low,   color: [34,  197, 94]  },
        { label: 'TOTAL',    count: vulns.length, color: [79, 70, 229] },
      ]

      let px = 14
      pills.forEach(p => {
        doc.setFillColor(...p.color)
        doc.roundedRect(px, 48, 44, 12, 2, 2, 'F')
        doc.setFontSize(7)
        doc.setTextColor(255, 255, 255)
        doc.setFont('helvetica', 'bold')
        doc.text(p.label, px + 22, 52.5, { align: 'center' })
        doc.setFontSize(11)
        doc.text(String(p.count), px + 22, 57.5, { align: 'center' })
        px += 48
      })

      // ── Vulnerability table ───────────────────────────────────────
      const tableData = vulns.map((v, idx) => [
        idx + 1,
        v.package_name ?? '—',
        v.installed_version ?? '—',
        v.severity ?? 'UNKNOWN',
        v.risk_score != null ? String(v.risk_score) : 'N/A',
        v.vuln_id ?? '—',
        v.affected_file ? `${v.affected_file}${v.line_number ? ':' + v.line_number : ''}` : '—',
        (v.summary ?? 'No summary available.').substring(0, 80),
        (v.fix_suggestion ?? 'Update to patched version.').substring(0, 80),
      ])

      const sevColor = sev => {
        if (sev === 'CRITICAL') return [239, 68,  68]
        if (sev === 'HIGH')     return [249, 115, 22]
        if (sev === 'MEDIUM')   return [234, 179, 8]
        return [34, 197, 94]
      }

      autoTable(doc, {
        startY: 66,
        head: [['#', 'Package', 'Version', 'Severity', 'Risk', 'CVE/ID', 'Location', 'Summary', 'Fix Suggestion']],
        body: tableData,
        theme: 'grid',
        headStyles: {
          fillColor: [79, 70, 229],
          textColor: [255, 255, 255],
          fontStyle: 'bold',
          fontSize: 8,
          cellPadding: 3,
        },
        columnStyles: {
          0: { cellWidth: 8,  halign: 'center' },
          1: { cellWidth: 28, fontStyle: 'bold' },
          2: { cellWidth: 22 },
          3: { cellWidth: 20, halign: 'center' },
          4: { cellWidth: 14, halign: 'center' },
          5: { cellWidth: 28 },
          6: { cellWidth: 28 },
          7: { cellWidth: 'auto' },
          8: { cellWidth: 'auto' },
        },
        styles: { fontSize: 7.5, cellPadding: 2.5, overflow: 'linebreak' },
        alternateRowStyles: { fillColor: [248, 248, 255] },
        didParseCell: (data) => {
          if (data.column.index === 3 && data.section === 'body') {
            const sev = data.cell.raw
            data.cell.styles.textColor = sevColor(sev)
            data.cell.styles.fontStyle = 'bold'
          }
          if (data.column.index === 4 && data.section === 'body') {
            const score = parseFloat(data.cell.raw)
            if (!isNaN(score)) {
              data.cell.styles.textColor = score >= 8 ? [239,68,68] : score >= 5 ? [249,115,22] : [34,197,94]
              data.cell.styles.fontStyle = 'bold'
            }
          }
        },
      })

      // ── Footer ───────────────────────────────────────────────────
      const totalPages = doc.internal.getNumberOfPages()
      for (let p = 1; p <= totalPages; p++) {
        doc.setPage(p)
        doc.setFontSize(7)
        doc.setTextColor(160)
        doc.setFont('helvetica', 'normal')
        doc.text(
          `RepodoGG Security Report  ·  ${owner}/${name}  ·  Page ${p} of ${totalPages}`,
          pageWidth / 2,
          doc.internal.pageSize.getHeight() - 6,
          { align: 'center' }
        )
      }

      doc.save(`RepodoGG_${owner}_${name}_SecurityReport.pdf`)
    } catch (err) {
      console.error('PDF generation failed:', err)
      alert(`PDF export failed: ${err.message}`)
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
            <Button 
              variant="outline"
              onClick={downloadPdf} 
              className="gap-2 border-indigo-500/30 text-indigo-400 hover:bg-indigo-500/10" 
              disabled={vulns.length === 0}
            >
              <FileDown className="w-4 h-4" />
              Export PDF
            </Button>
            {vulns.length === 0 && !neverScanned && (
              <Button 
                onClick={handleCertify} 
                disabled={certifying || !!report?.repo?.ipfs_hash || !!certSuccess}
                className={`gap-2 ${report?.repo?.ipfs_hash || certSuccess ? 'bg-amber-500/20 text-amber-500 border border-amber-500 hover:bg-amber-500/30' : 'bg-gradient-to-r from-amber-500 to-orange-500 hover:from-amber-600 hover:to-orange-600'} text-white border-0 shadow-lg`}
              >
                <Award className="w-4 h-4" />
                {certifying ? 'Minting...' : (report?.repo?.ipfs_hash || certSuccess ? 'Certified' : 'Mint Certificate')}
              </Button>
            )}
            <Button onClick={() => setPrOpen(true)} className="gap-2" disabled={vulns.length === 0}>
              <GitPullRequest className="w-4 h-4" />
              Fix PR
            </Button>
          </div>
        </div>

        {/* IPFS Cert Success */}
        {(certSuccess || report?.repo?.ipfs_hash) && (
          <div className="p-4 rounded-xl border border-amber-500/40 bg-gradient-to-r from-amber-500/10 to-transparent flex items-center justify-between gap-4">
            <div className="flex items-center gap-3">
              <div className="p-2 bg-amber-500/20 rounded-full">
                <Award className="w-6 h-6 text-amber-500" />
              </div>
              <div>
                <p className="font-bold text-amber-500 flex items-center gap-2">
                  Verified Immutable Certificate
                  <span className="px-2 py-0.5 text-[10px] uppercase font-bold tracking-wider bg-amber-500 text-white rounded-full">IPFS Minted</span>
                </p>
                <p className="text-muted-foreground text-xs mt-1 font-mono">
                  IPFS Hash: <span className="text-foreground">{certSuccess || report?.repo?.ipfs_hash}</span>
                </p>
              </div>
            </div>
            <a 
              href={`http://localhost:8000/repos/${repoId}/certificate.pdf?token=${localStorage.getItem('token')}`} 
              target="_blank" 
              rel="noreferrer"
            >
              <Button variant="outline" className="gap-2 border-amber-500/30 text-amber-500 hover:bg-amber-500/10">
                <ExternalLink className="w-4 h-4" /> View Certificate
              </Button>
            </a>
          </div>
        )}
        
        {/* Cert Error */}
        {certError && (
          <div className="p-3 rounded-lg bg-destructive/10 border border-destructive/20 text-destructive text-sm flex items-center gap-2">
            <AlertCircle className="w-4 h-4" />
            {certError}
          </div>
        )}

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
                        <TableHead className="max-w-xs">Summary</TableHead>
                        <TableHead>Source</TableHead>
                        <TableHead>Advisory</TableHead>
                        <TableHead className="pr-6 text-right">Action</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {vulns.map((v, i) => (
                        <React.Fragment key={i}>
                          <TableRow className="cursor-pointer hover:bg-muted/50 transition-colors border-b border-border" onClick={() => toggle(i)}>
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
                            </TableCell>
                            <TableCell className="text-xs">
                              {inferManifest(v) ? (
                                <span className="font-mono text-muted-foreground text-[10px]">
                                  {inferManifest(v)}
                                </span>
                              ) : <span className="text-muted-foreground">—</span>}
                            </TableCell>
                            <TableCell>
                              {v.vuln_id ? (
                                <a href={`https://github.com/advisories/${v.vuln_id}`} target="_blank" rel="noreferrer" onClick={(e) => e.stopPropagation()}>
                                  <Button variant="ghost" size="sm" className="h-7 w-7 p-0">
                                    <ExternalLink className="w-3.5 h-3.5" />
                                  </Button>
                                </a>
                              ) : <span className="text-muted-foreground text-xs">—</span>}
                            </TableCell>
                            <TableCell className="pr-6 text-right text-primary font-medium text-xs">
                              {expanded[i] ? 'Hide' : 'Analyze'}
                            </TableCell>
                          </TableRow>
                          {expanded[i] && (
                            <TableRow className="bg-muted/30 hover:bg-muted/30">
                              <TableCell colSpan={9} className="p-6">
                                <div className="flex flex-col gap-3">
                                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                                    <div>
                                      <p className="text-muted-foreground text-[10px] uppercase tracking-wider font-semibold mb-1">Vulnerability Summary</p>
                                      <p className="text-sm font-medium leading-relaxed">{v.summary || 'No summary available.'}</p>
                                    </div>
                                    <div>
                                      <p className="text-muted-foreground text-[10px] uppercase tracking-wider font-semibold mb-1">Local Usage Detail</p>
                                      <p className="text-sm font-medium">
                                        {v.affected_file ? (
                                          <span className="font-mono text-yellow-500 bg-yellow-500/10 px-1.5 py-0.5 rounded border border-yellow-500/20">
                                            {v.affected_file}:{v.line_number}
                                          </span>
                                        ) : (
                                          <span className="text-muted-foreground italic">Not uniquely identified in AST</span>
                                        )}
                                      </p>
                                    </div>
                                  </div>

                                  <div className="mt-2 p-4 bg-primary/10 rounded-xl border border-primary/20 shadow-inner">
                                    <div className="flex items-center gap-2 mb-2">
                                      <span className="text-primary font-semibold text-sm flex items-center gap-1.5">
                                        🛠️ Actionable Fix
                                      </span>
                                      <span className="text-[10px] uppercase font-bold tracking-wider px-2 py-0.5 rounded-full bg-background border border-border text-foreground/80 ml-auto">
                                        Impact: <span className="text-destructive ml-1">{v.risk_impact || 'Moderate Issue'}</span>
                                      </span>
                                    </div>
                                    <p className="text-sm text-foreground/90 font-medium">{v.fix_suggestion || 'Update to the nearest safe patched version.'}</p>
                                  </div>
                                </div>
                              </TableCell>
                            </TableRow>
                          )}
                        </React.Fragment>
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
