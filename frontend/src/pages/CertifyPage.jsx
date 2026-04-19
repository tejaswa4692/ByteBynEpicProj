import { useState, useEffect } from 'react'
import { getGithubRepos, getReport } from '@/api'
import NavBar from '@/components/NavBar'
import SeverityBadge from '@/components/SeverityBadge'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription } from '@/components/ui/dialog'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Skeleton } from '@/components/ui/skeleton'
import { Separator } from '@/components/ui/separator'
import {
  Shield, Download, FileJson, CheckCircle2, XCircle, Award,
  AlertTriangle, Package2, Loader2
} from 'lucide-react'

function ScoreRing({ score }) {
  const color = score >= 80 ? '#4ade80' : score >= 50 ? '#fb923c' : '#f87171'
  const radius = 40
  const circumference = 2 * Math.PI * radius
  const offset = circumference - (score / 100) * circumference

  return (
    <div className="relative w-28 h-28 flex items-center justify-center">
      <svg className="absolute inset-0 -rotate-90" viewBox="0 0 100 100">
        <circle cx="50" cy="50" r={radius} fill="none" stroke="oklch(1 0 0 / 8%)" strokeWidth="8" />
        <circle
          cx="50" cy="50" r={radius}
          fill="none"
          stroke={color}
          strokeWidth="8"
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          style={{ transition: 'stroke-dashoffset 0.6s ease' }}
        />
      </svg>
      <div className="text-center">
        <p className="text-2xl font-bold" style={{ color }}>{score}</p>
        <p className="text-xs text-muted-foreground">/100</p>
      </div>
    </div>
  )
}

export default function CertifyPage() {
  const [repos, setRepos] = useState([])
  const [selectedId, setSelectedId] = useState('')
  const [report, setReport] = useState(null)
  const [loadingReport, setLoadingReport] = useState(false)
  const [sbom, setSbom] = useState(null)
  const [sbomOpen, setSbomOpen] = useState(false)
  const [certOpen, setCertOpen] = useState(false)

  useEffect(() => {
    getGithubRepos().then(data => {
      const monitored = (Array.isArray(data) ? data : []).filter(r => r.is_moderated && r.id)
      setRepos(monitored)
    })
  }, [])

  const handleSelect = async (id) => {
    setSelectedId(id)
    setReport(null)
    setSbom(null)
    setLoadingReport(true)
    try {
      const data = await getReport(id)
      setReport(data)
    } finally {
      setLoadingReport(false)
    }
  }

  const generateSbom = () => {
    if (!report) return
    const vulns = report.vulnerabilities ?? []
    const uniquePackages = [...new Map(vulns.map(v => [v.package_name, v])).values()]
    const selectedRepo = repos.find(r => String(r.id) === String(selectedId))

    const doc = {
      bomFormat: 'CycloneDX',
      specVersion: '1.4',
      serialNumber: `urn:uuid:${crypto.randomUUID()}`,
      version: 1,
      metadata: {
        timestamp: new Date().toISOString(),
        tools: [{ vendor: 'RepodoGG', name: 'RepodoGG Scanner', version: '1.0.0' }],
        component: {
          type: 'library',
          name: selectedRepo ? `${selectedRepo.owner}/${selectedRepo.repo_name}` : 'unknown',
        },
      },
      components: uniquePackages.map(p => ({
        type: 'library',
        name: p.package_name,
        version: p.installed_version,
        purl: `pkg:npm/${encodeURIComponent(p.package_name)}@${p.installed_version}`,
      })),
      vulnerabilities: vulns.map(v => ({
        id: v.vuln_id,
        source: { name: 'OSV', url: `https://osv.dev/vulnerability/${v.vuln_id}` },
        ratings: [{ severity: v.severity?.toLowerCase(), score: v.risk_score, method: 'CVSSv3' }],
        description: v.summary,
        affects: [{ ref: `pkg:npm/${encodeURIComponent(v.package_name)}@${v.installed_version}` }],
      })),
    }
    setSbom(doc)
    setSbomOpen(true)
  }

  const downloadSbom = () => {
    const selectedRepo = repos.find(r => String(r.id) === String(selectedId))
    const filename = `sbom-${selectedRepo?.repo_name ?? 'repo'}-${Date.now()}.json`
    const blob = new Blob([JSON.stringify(sbom, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = filename
    a.click()
    URL.revokeObjectURL(url)
  }

  const vulns = report?.vulnerabilities ?? []
  const critCount = vulns.filter(v => v.severity === 'CRITICAL').length
  const highCount = vulns.filter(v => v.severity === 'HIGH').length
  const score = report ? Math.max(0, Math.round(100 - critCount * 20 - highCount * 5)) : null
  const isCertifiable = critCount === 0 && highCount <= 2
  const uniquePackages = [...new Set(vulns.map(v => v.package_name))].length

  return (
    <div className="min-h-screen bg-background">
      <NavBar />
      <main className="max-w-4xl mx-auto px-6 py-8 space-y-8">

        {/* Header */}
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Certification</h1>
          <p className="text-muted-foreground mt-1 text-sm">
            Generate a Software Bill of Materials (SBOM) and certify your project's security posture.
          </p>
        </div>

        {/* Repo selector */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-base">Select Repository</CardTitle>
            <CardDescription>Only repositories with active scanning are eligible.</CardDescription>
          </CardHeader>
          <CardContent>
            {repos.length === 0 ? (
              <p className="text-sm text-muted-foreground">
                No monitored repositories found. Enable scanning on the{' '}
                <a href="/repos" className="text-primary underline underline-offset-2">Repositories</a> page first.
              </p>
            ) : (
              <Select onValueChange={handleSelect} value={selectedId}>
                <SelectTrigger className="w-full max-w-sm">
                  <SelectValue placeholder="Choose a repository…" />
                </SelectTrigger>
                <SelectContent>
                  {repos.map(r => (
                    <SelectItem key={r.id} value={String(r.id)}>
                      {r.owner}/{r.repo_name}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            )}
          </CardContent>
        </Card>

        {/* Loading */}
        {loadingReport && (
          <div className="flex items-center justify-center py-12 gap-3 text-muted-foreground">
            <Loader2 className="w-5 h-5 animate-spin" />
            <span className="text-sm">Loading vulnerability report…</span>
          </div>
        )}

        {/* Results */}
        {report && !loadingReport && (
          <div className="space-y-6">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">

              {/* Certification status */}
              <Card className={isCertifiable ? 'border-green-500/30' : 'border-red-500/30'}>
                <CardContent className="p-6">
                  <div className="flex items-start gap-4 mb-5">
                    <ScoreRing score={score} />
                    <div className="pt-2">
                      <div className="flex items-center gap-2 mb-1">
                        {isCertifiable
                          ? <CheckCircle2 className="w-5 h-5 text-green-400" />
                          : <XCircle className="w-5 h-5 text-red-400" />
                        }
                        <p className="font-semibold">
                          {isCertifiable ? 'Certifiable' : 'Not Certifiable'}
                        </p>
                      </div>
                      <p className="text-xs text-muted-foreground leading-relaxed">
                        {isCertifiable
                          ? 'This project meets RepodoGG security standards.'
                          : 'Resolve critical issues to qualify for certification.'
                        }
                      </p>
                    </div>
                  </div>

                  <Separator className="mb-4" />

                  <div className="space-y-2 text-sm mb-5">
                    {[
                      { label: 'Critical vulnerabilities', val: critCount, danger: critCount > 0 },
                      { label: 'High vulnerabilities', val: highCount, danger: highCount > 2 },
                      { label: 'Total vulnerabilities', val: vulns.length, danger: false },
                    ].map(({ label, val, danger }) => (
                      <div key={label} className="flex justify-between items-center">
                        <span className="text-muted-foreground">{label}</span>
                        <span className={danger ? 'text-red-400 font-bold' : val === 0 ? 'text-green-400' : 'text-foreground'}>
                          {val}
                        </span>
                      </div>
                    ))}
                  </div>

                  <Button
                    className="w-full gap-2"
                    variant={isCertifiable ? 'default' : 'outline'}
                    onClick={() => setCertOpen(true)}
                  >
                    <Award className="w-4 h-4" />
                    {isCertifiable ? 'Apply for Certification' : 'View Requirements'}
                  </Button>
                </CardContent>
              </Card>

              {/* SBOM card */}
              <Card>
                <CardContent className="p-6">
                  <div className="flex items-center gap-3 mb-5">
                    <div className="p-2.5 rounded-lg bg-blue-500/10 border border-blue-500/20">
                      <FileJson className="w-5 h-5 text-blue-400" />
                    </div>
                    <div>
                      <p className="font-semibold">Software Bill of Materials</p>
                      <p className="text-xs text-muted-foreground">CycloneDX 1.4 format</p>
                    </div>
                  </div>

                  <Separator className="mb-4" />

                  <div className="space-y-2 text-sm mb-5">
                    {[
                      { label: 'Components tracked', val: uniquePackages, icon: <Package2 className="w-3.5 h-3.5" /> },
                      { label: 'Vulnerabilities', val: vulns.length, icon: <AlertTriangle className="w-3.5 h-3.5" /> },
                      { label: 'Format', val: <Badge variant="secondary" className="text-xs">CycloneDX</Badge>, icon: <Shield className="w-3.5 h-3.5" /> },
                    ].map(({ label, val, icon }) => (
                      <div key={label} className="flex justify-between items-center">
                        <div className="flex items-center gap-1.5 text-muted-foreground">
                          {icon} {label}
                        </div>
                        <span>{val}</span>
                      </div>
                    ))}
                  </div>

                  <Button className="w-full gap-2" variant="outline" onClick={generateSbom}>
                    <FileJson className="w-4 h-4" />
                    Generate SBOM
                  </Button>
                </CardContent>
              </Card>
            </div>

            {/* Vulnerability breakdown */}
            {vulns.length > 0 && (
              <Card>
                <CardHeader className="pb-0">
                  <CardTitle className="text-sm font-medium text-muted-foreground">
                    Critical & High Issues ({critCount + highCount})
                  </CardTitle>
                </CardHeader>
                <CardContent className="pt-4">
                  <div className="space-y-2">
                    {vulns
                      .filter(v => v.severity === 'CRITICAL' || v.severity === 'HIGH')
                      .map((v, i) => (
                        <div key={i} className="flex items-center justify-between p-3 rounded-lg bg-secondary text-sm gap-4">
                          <div className="flex items-center gap-3 min-w-0">
                            <span className="font-mono text-xs text-blue-300 truncate">{v.package_name}</span>
                            <span className="text-xs text-muted-foreground shrink-0">{v.installed_version}</span>
                          </div>
                          <SeverityBadge severity={v.severity} />
                        </div>
                      ))}
                    {critCount + highCount === 0 && (
                      <div className="text-center py-6 text-green-400 text-sm">
                        <CheckCircle2 className="w-8 h-8 mx-auto mb-2" />
                        No critical or high severity issues found.
                      </div>
                    )}
                  </div>
                </CardContent>
              </Card>
            )}
          </div>
        )}
      </main>

      {/* SBOM preview dialog */}
      <Dialog open={sbomOpen} onOpenChange={setSbomOpen}>
        <DialogContent className="max-w-2xl max-h-[85vh] flex flex-col">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <FileJson className="w-5 h-5 text-blue-400" /> SBOM Preview
            </DialogTitle>
            <DialogDescription>
              CycloneDX 1.4 — {sbom?.components?.length ?? 0} components, {sbom?.vulnerabilities?.length ?? 0} vulnerabilities
            </DialogDescription>
          </DialogHeader>
          <div className="overflow-auto flex-1 rounded-lg bg-secondary border border-border p-4 min-h-0">
            <pre className="text-xs font-mono text-foreground/90 whitespace-pre-wrap break-words">
              {sbom ? JSON.stringify(sbom, null, 2) : ''}
            </pre>
          </div>
          <Button onClick={downloadSbom} className="gap-2 mt-2 shrink-0">
            <Download className="w-4 h-4" /> Download SBOM
          </Button>
        </DialogContent>
      </Dialog>

      {/* Certification dialog */}
      <Dialog open={certOpen} onOpenChange={setCertOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Award className="w-5 h-5 text-primary" /> RepodoGG Certification
            </DialogTitle>
            <DialogDescription>
              {isCertifiable
                ? 'Your project meets the requirements for RepodoGG security certification.'
                : 'Your project does not currently meet certification requirements.'}
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-3 text-sm text-muted-foreground">
            {isCertifiable ? (
              <p>
                Certification badge issuance and submission is coming soon. Your SBOM has been generated — download it to share your project's security posture.
              </p>
            ) : (
              <div className="space-y-2">
                <p>To qualify for certification, your project must:</p>
                <ul className="space-y-1 list-none">
                  <li className={`flex items-center gap-2 ${critCount === 0 ? 'text-green-400' : 'text-red-400'}`}>
                    {critCount === 0 ? <CheckCircle2 className="w-4 h-4" /> : <XCircle className="w-4 h-4" />}
                    Zero critical vulnerabilities (currently: {critCount})
                  </li>
                  <li className={`flex items-center gap-2 ${highCount <= 2 ? 'text-green-400' : 'text-orange-400'}`}>
                    {highCount <= 2 ? <CheckCircle2 className="w-4 h-4" /> : <XCircle className="w-4 h-4" />}
                    2 or fewer high severity issues (currently: {highCount})
                  </li>
                </ul>
              </div>
            )}
          </div>
        </DialogContent>
      </Dialog>
    </div>
  )
}
