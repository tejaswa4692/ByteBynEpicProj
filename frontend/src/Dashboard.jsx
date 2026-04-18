import { useState, useEffect } from 'react'
import { getGithubRepos, getReport, getCves, refreshCves, moderateRepo } from './api'
import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer, BarChart, Bar, XAxis, YAxis } from 'recharts'

const badge = sev => {
  const styles = { CRITICAL: 'bg-red-900/40 text-red-400 border border-red-800/50', HIGH: 'bg-orange-900/40 text-orange-400 border border-orange-800/50', MEDIUM: 'bg-yellow-900/40 text-yellow-400 border border-yellow-800/50', LOW: 'bg-blue-900/40 text-blue-400 border border-blue-800/50' }
  return <span className={`px-2 py-1 rounded-md text-xs font-bold tracking-wide ${styles[sev] || 'bg-gray-800 text-gray-400 border border-gray-700'}`}>{sev || 'N/A'}</span>
}

const riskColor = s => s >= 8 ? 'text-red-400' : s >= 5 ? 'text-orange-400' : s >= 3 ? 'text-yellow-400' : 'text-green-400'

function VulnTable({ rows }) {
  if (!rows?.length) return <div className="text-green-400 text-center py-12 bg-green-900/10 rounded-xl border border-green-800/30">✅ Incredible! No vulnerabilities found across your entire repository.</div>
  return (
    <div className="overflow-x-auto rounded-xl border border-gray-800/60 bg-gray-900/50 shadow-inner">
      <table className="w-full text-sm">
        <thead className="bg-gray-800/80 text-gray-400 border-b border-gray-700/50 backdrop-blur-md">
          <tr>{['Package','Version','CVE / ID','Severity','Risk','Summary'].map(h => <th key={h} className="text-left px-5 py-4 font-medium">{h}</th>)}</tr>
        </thead>
        <tbody className="divide-y divide-gray-800/50">
          {rows.map((r, i) => (
            <tr key={i} className="hover:bg-gray-800/30 transition-colors">
              <td className="px-5 py-4 font-mono text-indigo-300">{r.package_name}</td>
              <td className="px-5 py-4 font-mono text-gray-400">{r.installed_version}</td>
              <td className="px-5 py-4 font-mono text-xs text-gray-300">{r.vuln_id || '—'}</td>
              <td className="px-5 py-4">{badge(r.severity)}</td>
              <td className={`px-5 py-4 font-bold ${riskColor(r.risk_score)}`}>{r.risk_score}/10</td>
              <td className="px-5 py-4 text-gray-400 max-w-xs truncate">{r.summary || '—'}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function ReportModal({ report, onClose }) {
  const vulns = report.vulnerabilities || []
  
  // Prepare Graph Data
  const sevCounts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 }
  vulns.forEach(v => { if (sevCounts[v.severity] !== undefined) sevCounts[v.severity]++ })
  const pieData = Object.entries(sevCounts).filter(([_, v]) => v > 0).map(([k, v]) => ({ name: k, value: v }))
  const COLORS = { CRITICAL: '#ef4444', HIGH: '#f97316', MEDIUM: '#eab308', LOW: '#3b82f6' }

  // Bar chart data for top 5 riskiest packages
  const barData = [...vulns].sort((a,b) => b.risk_score - a.risk_score).slice(0, 5).map(v => ({ name: v.package_name, risk: v.risk_score }))

  return (
    <div className="fixed inset-0 bg-black/80 backdrop-blur-sm flex items-center justify-center z-50 p-4" onClick={onClose}>
      <div className="bg-gray-900 border border-gray-800 rounded-2xl w-full max-w-5xl max-h-[90vh] overflow-y-auto shadow-2xl" onClick={e => e.stopPropagation()}>
        
        {/* Header */}
        <div className="sticky top-0 bg-gray-900/90 backdrop-blur-md border-b border-gray-800 px-8 py-6 flex justify-between items-center z-10">
          <div>
            <h3 className="text-2xl font-bold bg-clip-text text-transparent bg-gradient-to-r from-indigo-400 to-purple-400">{report.name}</h3>
            <p className="text-gray-400 mt-1 text-sm">{report.total_vulns} vulnerabilities discovered in repository</p>
          </div>
          <button onClick={onClose} className="text-gray-500 hover:text-white transition-colors p-2 rounded-full hover:bg-gray-800">✕</button>
        </div>

        <div className="p-8">
          {/* Graphs Section */}
          {vulns.length > 0 && (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-8">
              {/* Severity Pie Chart */}
              <div className="bg-gray-800/30 border border-gray-700/30 rounded-xl p-6 flex flex-col items-center">
                <h4 className="text-gray-300 font-medium mb-4">Vulnerability Severity</h4>
                <div className="h-64 w-full">
                  <ResponsiveContainer>
                    <PieChart>
                      <Pie data={pieData} innerRadius={60} outerRadius={80} paddingAngle={5} dataKey="value" stroke="none">
                        {pieData.map((entry, index) => <Cell key={`cell-${index}`} fill={COLORS[entry.name]} />)}
                      </Pie>
                      <Tooltip contentStyle={{ backgroundColor: '#1f2937', borderColor: '#374151', color: '#f3f4f6' }} />
                    </PieChart>
                  </ResponsiveContainer>
                </div>
                <div className="flex gap-4 mt-2">
                  {pieData.map(d => (
                    <div key={d.name} className="flex items-center gap-1.5 text-xs text-gray-400">
                      <div className="w-3 h-3 rounded-full" style={{ backgroundColor: COLORS[d.name] }}></div>
                      {d.name} ({d.value})
                    </div>
                  ))}
                </div>
              </div>

              {/* Top Riskiest Packages */}
              <div className="bg-gray-800/30 border border-gray-700/30 rounded-xl p-6 flex flex-col items-center">
                <h4 className="text-gray-300 font-medium mb-4">Top Risk Dependencies</h4>
                <div className="h-64 w-full">
                  <ResponsiveContainer>
                    <BarChart data={barData} layout="vertical" margin={{ left: 40, right: 20 }}>
                      <XAxis type="number" domain={[0, 10]} hide />
                      <YAxis dataKey="name" type="category" axisLine={false} tickLine={false} tick={{fill: '#9ca3af', fontSize: 12}} />
                      <Tooltip cursor={{fill: '#374151', opacity: 0.4}} contentStyle={{ backgroundColor: '#1f2937', borderColor: '#374151', color: '#f3f4f6' }} />
                      <Bar dataKey="risk" fill="#818cf8" radius={[0, 4, 4, 0]} barSize={20}>
                        {barData.map((entry, index) => (
                          <Cell key={`cell-${index}`} fill={entry.risk >= 8 ? '#ef4444' : entry.risk >= 5 ? '#f97316' : '#818cf8'} />
                        ))}
                      </Bar>
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              </div>
            </div>
          )}

          {/* Table */}
          <VulnTable rows={report.vulnerabilities} />
        </div>
      </div>
    </div>
  )
}

function Repos() {
  const [repos, setRepos]     = useState([])
  const [report, setReport]   = useState(null)
  const [loading, setLoading] = useState(true)
  const [refreshing, setRefreshing] = useState(false)

  const loadRepos = async () => {
    const d = await getGithubRepos()
    setRepos(d)
  }

  useEffect(() => { 
    loadRepos().then(() => setLoading(false))
  }, [])

  const handleRefresh = async () => {
    setRefreshing(true)
    await loadRepos()
    setRefreshing(false)
  }

  const openReport = async repo => {
    if (!repo.id) return;
    const data = await getReport(repo.id)
    setReport({ ...data, name: repo.repo_name })
  }

  const handleToggleModerate = async (repo) => {
    const newVal = !repo.is_moderated
    setRepos(repos.map(r => r.github_id === repo.github_id ? { ...r, is_moderated: newVal } : r))
    const res = await moderateRepo(repo.url, repo.owner, repo.repo_name, newVal)
    if (res.repo_id) {
        await loadRepos()
    }
  }

  if (loading) return <div className="flex flex-col items-center justify-center py-20"><div className="w-10 h-10 border-4 border-indigo-500/30 border-t-indigo-500 rounded-full animate-spin mb-4"></div><p className="text-gray-400">Loading GitHub Repositories…</p></div>
  if (!repos.length) return <div className="flex flex-col items-center justify-center py-20 bg-gray-800/20 rounded-2xl border border-gray-800 border-dashed"><p className="text-gray-500">No repositories found in your GitHub account.</p></div>

  return (
    <div className="animate-fade-in">
      <div className="flex justify-between items-center mb-8">
        <div>
          <h2 className="text-3xl font-bold tracking-tight text-white">My Projects</h2>
          <p className="text-gray-400 mt-1">Select repositories to actively monitor and analyze.</p>
        </div>
        <button onClick={handleRefresh} disabled={refreshing}
          className="px-5 py-2.5 bg-gray-800 hover:bg-gray-700 disabled:opacity-50 rounded-lg text-sm font-semibold transition-all shadow-lg flex items-center gap-2">
          {refreshing ? <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin"></div> : '↻'} 
          {refreshing ? 'Syncing...' : 'Sync GitHub'}
        </button>
      </div>

      <div className="mb-8 p-5 bg-gradient-to-r from-indigo-900/40 to-purple-900/40 border border-indigo-500/30 rounded-xl flex items-start gap-5 shadow-lg relative overflow-hidden">
        <div className="absolute top-0 right-0 w-64 h-64 bg-indigo-500/10 blur-3xl rounded-full translate-x-1/2 -translate-y-1/2"></div>
        <div className="text-indigo-400 text-3xl shrink-0 drop-shadow-lg">✨</div>
        <div className="relative z-10">
          <h3 className="text-lg font-bold text-indigo-100">Deep Repository Scanning</h3>
          <p className="text-sm text-indigo-200/70 mt-1 leading-relaxed">
            HackHelix now automatically crawls your entire repository, finding and analyzing every <code className="bg-black/30 px-1.5 py-0.5 rounded text-indigo-300">package.json</code> file across all directories and microservices. 
          </p>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
        {repos.map(r => (
          <div key={r.github_id} className={`group relative p-5 rounded-xl border transition-all duration-300 ${r.is_moderated ? 'bg-gray-800/80 border-indigo-500/50 shadow-[0_0_20px_rgba(99,102,241,0.1)]' : 'bg-gray-900/50 border-gray-800 hover:border-gray-700'}`}>
            <div className="flex justify-between items-start mb-4">
              <div>
                <h4 className="font-bold text-lg text-gray-100 truncate w-48"><a href={r.url} target="_blank" rel="noreferrer" className="hover:text-indigo-400 transition-colors">{r.repo_name}</a></h4>
                <p className="text-xs text-gray-500 mt-1">{r.owner}</p>
              </div>
              
              {/* iOS style toggle */}
              <label className="relative inline-flex items-center cursor-pointer">
                <input type="checkbox" className="sr-only peer" checked={r.is_moderated} onChange={() => handleToggleModerate(r)} />
                <div className="w-11 h-6 bg-gray-700 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-indigo-500 shadow-inner"></div>
              </label>
            </div>

            <div className="flex items-center justify-between mt-6">
              <span className="text-xs text-gray-500 flex items-center gap-1">
                📅 {new Date(r.updated_at).toLocaleDateString()}
              </span>
              {r.is_moderated && r.id ? (
                <button onClick={() => openReport(r)} className="px-4 py-1.5 bg-indigo-600/20 text-indigo-400 hover:bg-indigo-600/40 hover:text-indigo-300 border border-indigo-500/30 rounded-md text-xs font-bold transition-all backdrop-blur-sm">
                  View Analysis
                </button>
              ) : (
                <span className="text-xs font-medium text-gray-600">Inactive</span>
              )}
            </div>
          </div>
        ))}
      </div>

      {report && <ReportModal report={report} onClose={() => setReport(null)} />}
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

const TABS = [['repos', 'My Repos'], ['cves', 'CVE Database']]

export default function Dashboard({ onLogout }) {
  const [tab, setTab] = useState('repos')

  const avatar = localStorage.getItem('avatar_url')

  return (
    <div className="min-h-screen flex flex-col">
      <nav className="bg-gray-900 border-b border-gray-800 px-6 py-4 flex items-center justify-between">
        <h1 className="text-xl font-bold">🔐 HackHelix</h1>
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-2">
            {avatar && <img src={avatar} alt="avatar" className="w-8 h-8 rounded-full border border-gray-700" />}
            <span className="text-gray-400 text-sm font-medium">{localStorage.getItem('username')}</span>
          </div>
          <button onClick={onLogout} className="text-sm px-3 py-1.5 bg-red-900/30 text-red-400 hover:bg-red-900/50 hover:text-red-300 rounded-lg transition">Logout</button>
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
        {tab === 'repos' && <Repos />}
        {tab === 'cves'  && <CVEs />}
      </main>
    </div>
  )
}
