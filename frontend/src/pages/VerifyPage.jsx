import { useState, useRef } from 'react'
import { Shield, Upload, CheckCircle2, XCircle, ExternalLink, FileText, Search, Loader2, X } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'

const API = import.meta.env.VITE_API_URL ?? 'http://localhost:8000'

export default function VerifyPage() {
  const [certId, setCertId] = useState('')
  const [dragOver, setDragOver] = useState(false)
  const [fileName, setFileName] = useState('')
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState(null)
  const [parseError, setParseError] = useState('')
  const fileRef = useRef()

  // Verify by Certificate ID string
  const verifyById = async (id) => {
    const cleaned = id.trim()
    if (!cleaned) return
    setLoading(true)
    setResult(null)
    setParseError('')
    try {
      const res = await fetch(`${API}/verify?cert_id=${encodeURIComponent(cleaned)}`)
      setResult(await res.json())
    } catch {
      setResult({ valid: false, message: 'Failed to reach verification server. Is the backend running?' })
    } finally {
      setLoading(false)
    }
  }

  // Verify by uploading the PDF — backend does all the extraction
  const verifyByFile = async (file) => {
    if (!file || file.type !== 'application/pdf') {
      setParseError('Please upload a valid PDF certificate.')
      return
    }
    setFileName(file.name)
    setParseError('')
    setResult(null)
    setLoading(true)
    try {
      const form = new FormData()
      form.append('file', file)
      const res = await fetch(`${API}/verify-pdf`, { method: 'POST', body: form })
      const data = await res.json()
      setResult(data)
      if (data.extracted_id) setCertId(data.extracted_id)
    } catch {
      setResult({ valid: false, message: 'Failed to reach verification server. Is the backend running?' })
    } finally {
      setLoading(false)
    }
  }

  const onDrop = (e) => {
    e.preventDefault()
    setDragOver(false)
    const file = e.dataTransfer.files[0]
    if (file) verifyByFile(file)
  }

  const clearAll = (e) => {
    e.stopPropagation()
    setFileName('')
    setCertId('')
    setResult(null)
    setParseError('')
  }

  return (
    <div className="min-h-screen bg-background flex flex-col">
      {/* Header */}
      <header className="border-b border-border bg-card/60 backdrop-blur-md sticky top-0 z-50">
        <div className="max-w-5xl mx-auto px-6 h-16 flex items-center justify-between">
          <a href="/" className="flex items-center gap-2.5 font-black text-lg tracking-tight">
            <div className="p-1.5 rounded-lg bg-primary/15 border border-primary/25">
              <Shield className="w-4 h-4 text-primary" />
            </div>
            repodogg
          </a>
          <span className="text-xs text-muted-foreground bg-secondary px-3 py-1 rounded-full font-medium">
            Certificate Verification Portal
          </span>
        </div>
      </header>

      <main className="flex-1 max-w-3xl mx-auto px-6 py-16 w-full space-y-10">
        {/* Hero */}
        <div className="text-center space-y-3">
          <div className="flex justify-center mb-4">
            <div className="p-4 rounded-2xl bg-primary/10 border border-primary/20">
              <Shield className="w-10 h-10 text-primary" />
            </div>
          </div>
          <h1 className="text-4xl font-black tracking-tight">Verify Security Certificate</h1>
          <p className="text-muted-foreground text-base max-w-lg mx-auto leading-relaxed">
            Upload a RepodoGG certificate PDF or paste the Certificate ID to instantly verify its authenticity and cryptographic proof.
          </p>
        </div>

        {/* Drop zone */}
        <div
          className={`relative border-2 border-dashed rounded-2xl p-10 text-center transition-all cursor-pointer ${
            dragOver
              ? 'border-primary bg-primary/10 scale-[1.01]'
              : 'border-border bg-card/40 hover:border-primary/50 hover:bg-primary/5'
          }`}
          onDragOver={(e) => { e.preventDefault(); setDragOver(true) }}
          onDragLeave={() => setDragOver(false)}
          onDrop={onDrop}
          onClick={() => fileRef.current?.click()}
        >
          <input
            ref={fileRef}
            type="file"
            accept="application/pdf"
            className="hidden"
            onChange={(e) => { if (e.target.files[0]) verifyByFile(e.target.files[0]) }}
          />
          {loading && fileName ? (
            <div className="flex flex-col items-center gap-3">
              <Loader2 className="w-8 h-8 animate-spin text-primary" />
              <p className="text-sm text-muted-foreground">Verifying <span className="text-foreground font-medium">{fileName}</span>…</p>
            </div>
          ) : fileName ? (
            <div className="flex items-center justify-center gap-2">
              <FileText className="w-4 h-4 text-primary" />
              <span className="text-sm font-medium text-foreground">{fileName}</span>
              <button className="text-muted-foreground hover:text-destructive" onClick={clearAll}>
                <X className="w-4 h-4" />
              </button>
            </div>
          ) : (
            <>
              <Upload className={`w-10 h-10 mx-auto mb-4 transition-colors ${dragOver ? 'text-primary' : 'text-muted-foreground'}`} />
              <p className="font-semibold text-sm">Drop your certificate PDF here</p>
              <p className="text-xs text-muted-foreground mt-1">or click to browse — the backend extracts the ID and verifies instantly</p>
            </>
          )}
        </div>

        {parseError && (
          <p className="text-sm text-destructive text-center">{parseError}</p>
        )}

        {/* Divider */}
        <div className="flex items-center gap-4">
          <div className="flex-1 h-px bg-border" />
          <span className="text-xs text-muted-foreground font-medium px-2">or paste Certificate ID manually</span>
          <div className="flex-1 h-px bg-border" />
        </div>

        {/* Manual input */}
        <div className="flex gap-3">
          <input
            value={certId}
            onChange={e => setCertId(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && verifyById(certId)}
            placeholder="bafkrei... or hx-abc123..."
            className="flex-1 px-4 py-3 rounded-xl bg-card border border-border text-sm font-mono focus:outline-none focus:ring-2 focus:ring-primary/50 focus:border-primary transition-all"
          />
          <Button onClick={() => verifyById(certId)} disabled={loading || !certId.trim()} className="gap-2 px-6">
            {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Search className="w-4 h-4" />}
            Verify
          </Button>
        </div>

        {/* Result */}
        {result && (
          <Card className={`border-2 ${result.valid ? 'border-green-500/40 bg-green-500/5' : 'border-destructive/40 bg-destructive/5'}`}>
            <CardContent className="p-6">
              {result.valid ? (
                <div className="space-y-5">
                  <div className="flex items-center gap-4">
                    <div className="p-3 rounded-full bg-green-500/15 border border-green-500/30">
                      <CheckCircle2 className="w-8 h-8 text-green-400" />
                    </div>
                    <div>
                      <p className="text-xl font-bold text-green-400">Certificate Verified ✓</p>
                      <p className="text-sm text-muted-foreground mt-0.5">This certificate is authentic and was issued by RepodoGG</p>
                    </div>
                    <span className="ml-auto px-3 py-1 text-xs font-bold uppercase tracking-wider bg-green-500 text-white rounded-full">
                      VALID
                    </span>
                  </div>

                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 pt-2">
                    {[
                      { label: 'Repository', value: `${result.owner}/${result.repo_name}` },
                      { label: 'Certified On', value: result.certified_at ? new Date(result.certified_at).toLocaleString() : 'N/A' },
                      { label: 'Issuer', value: 'RepodoGG Automated AST Scanner' },
                      { label: 'Vulnerability Count', value: '0 (Zero Vulnerabilities)' },
                    ].map(({ label, value }) => (
                      <div key={label} className="p-4 rounded-xl bg-background/60 border border-border">
                        <p className="text-[10px] uppercase tracking-wider text-muted-foreground font-semibold mb-1">{label}</p>
                        <p className="text-sm font-semibold truncate">{value}</p>
                      </div>
                    ))}
                  </div>

                  <div className="p-4 rounded-xl bg-background/60 border border-border">
                    <p className="text-[10px] uppercase tracking-wider text-muted-foreground font-semibold mb-1">Certificate ID</p>
                    <p className="text-xs font-mono break-all text-primary">{result.cert_id}</p>
                  </div>

                  <a href={result.repo_url} target="_blank" rel="noreferrer">
                    <Button variant="outline" className="gap-2 w-full border-green-500/30 text-green-400 hover:bg-green-500/10">
                      <ExternalLink className="w-4 h-4" /> View Repository on GitHub
                    </Button>
                  </a>
                </div>
              ) : (
                <div className="flex items-start gap-4">
                  <div className="p-3 rounded-full bg-destructive/15 border border-destructive/30 shrink-0">
                    <XCircle className="w-8 h-8 text-destructive" />
                  </div>
                  <div className="flex-1">
                    <p className="text-xl font-bold text-destructive">Invalid Certificate</p>
                    <p className="text-sm text-muted-foreground mt-1">{result.message}</p>
                    {result.extracted_id && (
                      <p className="text-xs font-mono text-muted-foreground mt-2">Extracted ID: {result.extracted_id}</p>
                    )}
                  </div>
                  <span className="px-3 py-1 text-xs font-bold uppercase tracking-wider bg-destructive text-white rounded-full shrink-0">
                    INVALID
                  </span>
                </div>
              )}
            </CardContent>
          </Card>
        )}

        <p className="text-center text-xs text-muted-foreground">
          Certificates are cryptographically sealed. The Certificate ID serves as an immutable tamper-proof record of zero-vulnerability compliance at the time of issuance.
        </p>
      </main>
    </div>
  )
}
