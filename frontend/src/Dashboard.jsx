import React, { useState, useEffect } from 'react'
import { scanRepo, getRepos, getReport, getCves, refreshCves, emailReport } from './api'

const badge = sev => {
  const styles = { CRITICAL: 'bg-red-900 text-red-300', HIGH: 'bg-orange-900 text-orange-300', MEDIUM: 'bg-yellow-900 text-yellow-300', LOW: 'bg-blue-900 text-blue-300' }
  return <span className={`px-2 py-0.5 rounded text-xs font-bold ${styles[sev] || 'bg-gray-700 text-gray-300'}`}>{sev || 'N/A'}</span>
}

const riskColor = s => s >= 8 ? 'text-red-400' : s >= 5 ? 'text-orange-400' : s >= 3 ? 'text-yellow-400' : 'text-green-400'

function VulnTable({ rows }) {
  const [expanded, setExpanded] = useState({})

  const toggle = i => setExpanded(p => ({ ...p, [i]: !p[i] }))

  if (!rows?.length) return <p className="text-green-400 text-center py-8">✅ No vulnerabilities found!</p>
  
  return (
    <div className="overflow-x-auto rounded-xl border border-gray-800">
      <table className="w-full text-sm">
        <thead className="bg-gray-800 text-gray-400">
          <tr>{['Package','Version','CVE / ID','Severity','Risk','Action'].map(h => <th key={h} className="text-left px-4 py-3">{h}</th>)}</tr>
        </thead>
        <tbody>
          {rows.map((r, i) => (
            <React.Fragment key={i}>
              <tr onClick={() => toggle(i)} className="border-t border-gray-800 hover:bg-gray-800/50 cursor-pointer transition">
                <td className="px-4 py-3 font-mono">{r.package_name}</td>
                <td className="px-4 py-3 font-mono text-gray-400">{r.installed_version}</td>
                <td className="px-4 py-3 font-mono text-xs">{r.vuln_id || '—'}</td>
                <td className="px-4 py-3">{badge(r.severity)}</td>
                <td className={`px-4 py-3 font-bold ${riskColor(r.risk_score)}`}>{r.risk_score}/10</td>
                <td className="px-4 py-3 text-indigo-400 font-medium text-xs">{expanded[i] ? 'Hide' : 'Analyze'}</td>
              </tr>
              {expanded[i] && (
                <tr className="bg-gray-900 border-b border-gray-800">
                  <td colSpan={6} className="px-6 py-4">
                    <div className="flex flex-col gap-2">
                       <p className="text-gray-300 text-xs"><strong>Summary:</strong> {r.summary || 'No summary available.'}</p>
                       <p className="text-gray-300 text-xs"><strong>Usage Found:</strong> {r.affected_file ? <span className="font-mono text-yellow-400">{r.affected_file}:{r.line_number}</span> : <span className="text-gray-500">Not found directly via AST imports</span>}</p>
                       <p className="text-gray-300 text-xs"><strong>Impact:</strong> <span className="text-red-400 font-semibold">{r.risk_impact || 'Moderate'}</span></p>
                       <div className="mt-2 p-3 bg-indigo-900/20 rounded-lg border border-indigo-500/30">
                          <p className="text-indigo-300 font-semibold mb-1">🛠️ Actionable Fix</p>
                          <p className="text-indigo-200 text-xs">{r.fix_suggestion || 'Update to the nearest safe patched version.'}</p>
                       </div>
                    </div>
                  </td>
                </tr>
              )}
            </React.Fragment>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function Scan() {
  const [url, setUrl]       = useState('')
  const [loading, setLoading] = useState(false)
  const [result, setResult]   = useState(null)
  const [err, setErr]         = useState('')

  const scan = async () => {
    setErr(''); setResult(null); setLoading(true)
    const data = await scanRepo(url)
    setLoading(false)
    if (data.detail) setErr(data.detail)
    else setResult(data)
  }

  return (
    <div>
      <h2 className="text-2xl font-semibold mb-4">Scan a GitHub Repository</h2>
      <div className="flex gap-3 mb-6">
        <input value={url} onChange={e => setUrl(e.target.value)} placeholder="https://github.com/owner/repo"
          className="flex-1 px-4 py-3 bg-gray-800 rounded-lg outline-none focus:ring-2 focus:ring-indigo-500" />
        <button onClick={scan} disabled={loading}
          className="px-6 py-3 bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 rounded-lg font-semibold transition">
          {loading ? '⏳ Scanning…' : 'Scan'}
        </button>
      </div>
      {err && <div className="p-4 bg-red-900 text-red-300 rounded-lg mb-4">{err}</div>}
      {result && (
        <>
          <div className="grid grid-cols-3 gap-4 mb-6">
            {[['Dependencies Scanned', result.dependencies_scanned, ''], ['Vulnerabilities Found', result.vulnerabilities_found, 'text-red-400'], ['Repo ID', result.repo_id, 'text-indigo-400']].map(([label, val, cls]) => (
              <div key={label} className="bg-gray-800 rounded-xl p-4 text-center">
                <div className={`text-3xl font-bold ${cls}`}>{val}</div>
                <div className="text-gray-400 text-sm mt-1">{label}</div>
              </div>
            ))}
          </div>
          <VulnTable rows={result.results} />
        </>
      )}
    </div>
  )
}

function Repos() {
  const [repos, setRepos]     = useState([])
  const [report, setReport]   = useState(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => { getRepos().then(d => { setRepos(d); setLoading(false) }) }, [])

  const openReport = async repo => {
    const data = await getReport(repo.id)
    setReport({ ...data, name: repo.repo_name })
  }

  if (loading) return <p className="text-gray-400 text-center py-10">Loading…</p>
  if (!repos.length) return <p className="text-gray-500 text-center py-10">No repos scanned yet. Go to Scan Repo!</p>

  return (
    <div>
      <h2 className="text-2xl font-semibold mb-4">My Scanned Repos</h2>
      <div className="overflow-x-auto rounded-xl border border-gray-800">
        <table className="w-full text-sm">
          <thead className="bg-gray-800 text-gray-400">
            <tr>{['Repository','Owner','Last Scanned',''].map(h => <th key={h} className="text-left px-4 py-3">{h}</th>)}</tr>
          </thead>
          <tbody>
            {repos.map(r => (
              <tr key={r.id} className="border-t border-gray-800 hover:bg-gray-800/50">
                <td className="px-4 py-3 font-mono text-indigo-300">{r.repo_name}</td>
                <td className="px-4 py-3 text-gray-400">{r.owner}</td>
                <td className="px-4 py-3 text-gray-400">{new Date(r.scanned_at).toLocaleString()}</td>
                <td className="px-4 py-3">
                  <button onClick={() => openReport(r)} className="px-3 py-1 bg-indigo-700 hover:bg-indigo-600 rounded text-xs font-semibold">View Report</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {report && (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4" onClick={() => setReport(null)}>
          <div className="bg-gray-900 rounded-2xl w-full max-w-3xl max-h-[80vh] overflow-y-auto p-6" onClick={e => e.stopPropagation()}>
            <div className="flex justify-between items-center mb-4">
              <h3 className="text-xl font-semibold">Report: {report.name}</h3>
              <div className="flex items-center gap-3">
                <button 
                  onClick={async () => {
                    const em = prompt("Enter the email address to send this PDF report to:");
                    if (em) {
                      try {
                        const res = await emailReport(report.repo.id || report.id, em);
                        if (res.success) alert(res.message);
                        else alert(`❌ Error: ${res.detail}`);
                      } catch(e) {
                         alert("Failed to send email.");
                      }
                    }
                  }} 
                  className="px-4 py-1.5 bg-green-600 hover:bg-green-500 rounded text-sm font-semibold">
                  📧 Email PDF Report
                </button>
                <button onClick={() => setReport(null)} className="text-gray-400 hover:text-white text-2xl">✕</button>
              </div>
            </div>
            <p className="text-gray-400 mb-4">{report.total_vulns} vulnerabilities</p>
            <VulnTable rows={report.vulnerabilities} />
          </div>
        </div>
      )}
    </div>
  )
}

function CVEs() {
  const [cves, setCves]       = useState([])
  const [sev, setSev]         = useState('')
  const [loading, setLoading] = useState(true)
  const [refreshing, setRefreshing] = useState(false)

  const load = async (s = sev) => {
    setLoading(true)
    const data = await getCves(s)
    setCves(data); setLoading(false)
  }

  useEffect(() => { load() }, [])

  const refresh = async () => {
    setRefreshing(true)
    const data = await refreshCves()
    setRefreshing(false)
    alert(`✅ Fetched ${data.fetched} advisories from GitHub`)
    load()
  }

  return (
    <div>
      <div className="flex items-center justify-between mb-4">
        <h2 className="text-2xl font-semibold">CVE Database (npm)</h2>
        <div className="flex gap-3">
          <select value={sev} onChange={e => { setSev(e.target.value); load(e.target.value) }}
            className="px-3 py-2 bg-gray-800 rounded-lg text-sm outline-none">
            <option value="">All severities</option>
            {['CRITICAL','HIGH','MEDIUM','LOW'].map(s => <option key={s}>{s}</option>)}
          </select>
          <button onClick={refresh} disabled={refreshing}
            className="px-4 py-2 bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 rounded-lg text-sm font-semibold">
            {refreshing ? '⏳ Fetching…' : '↻ Refresh from GitHub'}
          </button>
        </div>
      </div>

      {loading ? <p className="text-gray-400 text-center py-10">Loading…</p> : !cves.length
        ? <p className="text-gray-500 text-center py-10">No CVEs cached. Click "Refresh from GitHub".</p>
        : (
          <div className="overflow-x-auto rounded-xl border border-gray-800">
            <table className="w-full text-sm">
              <thead className="bg-gray-800 text-gray-400">
                <tr>{['GHSA ID','Package','Severity','CVSS','Published','Summary'].map(h => <th key={h} className="text-left px-4 py-3">{h}</th>)}</tr>
              </thead>
              <tbody>
                {cves.map((c, i) => (
                  <tr key={i} className="border-t border-gray-800 hover:bg-gray-800/50">
                    <td className="px-4 py-3 font-mono text-xs">
                      <a href={`https://github.com/advisories/${c.ghsa_id}`} target="_blank" className="text-indigo-300 hover:underline">{c.ghsa_id}</a>
                    </td>
                    <td className="px-4 py-3 font-mono">{c.package_name || '—'}</td>
                    <td className="px-4 py-3">{badge(c.severity)}</td>
                    <td className="px-4 py-3">{c.cvss ?? '—'}</td>
                    <td className="px-4 py-3 text-gray-400 text-xs">{c.published_at?.slice(0, 10) || '—'}</td>
                    <td className="px-4 py-3 text-gray-400 max-w-xs truncate">{c.summary || '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
    </div>
  )
}

const TABS = [['scan', 'Scan Repo'], ['repos', 'My Repos'], ['cves', 'CVE Database']]

export default function Dashboard({ onLogout }) {
  const [tab, setTab] = useState('scan')

  return (
    <div className="min-h-screen flex flex-col">
      <nav className="bg-gray-900 border-b border-gray-800 px-6 py-4 flex items-center justify-between">
        <h1 className="text-xl font-bold">🔐 HackHelix</h1>
        <div className="flex items-center gap-4">
          <span className="text-gray-400 text-sm">👤 {localStorage.getItem('username')}</span>
          <button onClick={onLogout} className="text-sm text-red-400 hover:text-red-300">Logout</button>
        </div>
      </nav>

      <div className="bg-gray-900 border-b border-gray-800 px-6 flex">
        {TABS.map(([id, label]) => (
          <button key={id} onClick={() => setTab(id)}
            className={`px-5 py-3 text-sm font-medium border-b-2 transition ${tab === id ? 'text-white border-indigo-500' : 'text-gray-400 border-transparent hover:text-white'}`}>
            {label}
          </button>
        ))}
      </div>

      <main className="flex-1 p-6 max-w-5xl w-full mx-auto">
        {tab === 'scan'  && <Scan />}
        {tab === 'repos' && <Repos />}
        {tab === 'cves'  && <CVEs />}
      </main>
    </div>
  )
}
