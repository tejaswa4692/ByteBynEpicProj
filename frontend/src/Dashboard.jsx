import { useState, useEffect } from 'react'
import { getGithubRepos, getReport, getCves, refreshCves, moderateRepo } from './api'
import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer, BarChart, Bar, XAxis, YAxis } from 'recharts'

const badge = sev => {
  const styles = { CRITICAL: 'text-red-500 bg-red-500/10 border border-red-500/20', HIGH: 'text-orange-500 bg-orange-500/10 border border-orange-500/20', MEDIUM: 'text-yellow-500 bg-yellow-500/10 border border-yellow-500/20', LOW: 'text-blue-500 bg-blue-500/10 border border-blue-500/20' }
  return <span className={`px-2 py-0.5 rounded text-[11px] font-medium tracking-wide ${styles[sev] || 'text-[#888] bg-[#222] border border-[#333]'}`}>{sev || 'N/A'}</span>
}

const riskColor = s => s >= 8 ? 'text-red-500' : s >= 5 ? 'text-orange-500' : s >= 3 ? 'text-yellow-500' : 'text-emerald-500'

function VulnTable({ rows }) {
  if (!rows?.length) return <div className="text-[#888] text-center py-12 text-sm border border-[#222] rounded-lg">No vulnerabilities found. Codebase is secure.</div>
  return (
    <div className="overflow-x-auto rounded-lg border border-[#222] bg-[#050505]">
      <table className="w-full text-sm">
        <thead className="bg-[#0a0a0a] text-[#888] border-b border-[#222]">
          <tr>{['Package','Version','CVE / ID','Risk Level','Usage Location','Recommendation'].map(h => <th key={h} className="text-left px-5 py-3 font-normal text-[12px] whitespace-nowrap">{h}</th>)}</tr>
        </thead>
        <tbody className="divide-y divide-[#222]">
          {rows.map((r, i) => (
            <tr key={i} className="hover:bg-[#111] transition-colors">
              <td className="px-5 py-4 font-mono text-[13px] text-white">{r.package_name}</td>
              <td className="px-5 py-4 font-mono text-[13px] text-[#888]">{r.installed_version}</td>
              <td className="px-5 py-4 font-mono text-[12px] text-[#888]">{r.vuln_id || '—'}</td>
              <td className="px-5 py-4">
                <div className={`font-medium text-[13px] ${riskColor(r.risk_score)}`}>{r.risk_score}/10</div>
                <div className="text-[11px] mt-1 text-[#888]">{r.risk_impact || r.severity}</div>
              </td>
              <td className="px-5 py-4 text-[#888] text-[12px]">
                {r.affected_file ? (
                  <span className="font-mono bg-[#222] px-1.5 py-0.5 rounded text-white">{r.affected_file}:{r.line_number}</span>
                ) : <span className="italic">Not Found</span>}
              </td>
              <td className="px-5 py-4 text-[#888] max-w-sm text-[12px] leading-relaxed">
                {r.fix_suggestion || r.summary || '—'}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function ReportModal({ report, onClose }) {
  const vulns = report.vulnerabilities || []
  
  const sevCounts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 }
  vulns.forEach(v => { if (sevCounts[v.severity] !== undefined) sevCounts[v.severity]++ })
  const pieData = Object.entries(sevCounts).filter(([_, v]) => v > 0).map(([k, v]) => ({ name: k, value: v }))
  const COLORS = { CRITICAL: '#ef4444', HIGH: '#f97316', MEDIUM: '#eab308', LOW: '#3b82f6' }

  const barData = [...vulns].sort((a,b) => b.risk_score - a.risk_score).slice(0, 5).map(v => ({ name: v.package_name, risk: v.risk_score }))

  return (
    <div className="fixed inset-0 bg-black/80 backdrop-blur-sm flex items-center justify-center z-[100] p-4 animate-in fade-in duration-200" onClick={onClose}>
      <div className="bg-[#050505] border border-[#222] rounded-xl w-full max-w-5xl max-h-[85vh] overflow-hidden flex flex-col shadow-2xl animate-in slide-in-from-bottom-4 duration-300" onClick={e => e.stopPropagation()}>
        
        <div className="flex justify-between items-center px-8 py-6 border-b border-[#222] bg-[#050505] z-10 shrink-0">
          <div>
            <h3 className="text-xl font-medium text-white tracking-tight">{report.name}</h3>
            <p className="text-[#888] text-sm mt-1">{report.total_vulns} vulnerabilities found</p>
          </div>
          <button onClick={onClose} className="text-[#888] hover:text-white transition-colors">
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M18 6L6 18M6 6l12 12"></path></svg>
          </button>
        </div>

        <div className="p-8 overflow-y-auto">
          {vulns.length > 0 && (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-8">
              <div className="bg-[#0a0a0a] border border-[#222] rounded-lg p-6">
                <h4 className="text-[#888] font-medium text-sm mb-6">Severity Distribution</h4>
                <div className="h-56 w-full">
                  <ResponsiveContainer>
                    <PieChart>
                      <Pie data={pieData} innerRadius={60} outerRadius={80} paddingAngle={2} dataKey="value" stroke="none">
                        {pieData.map((entry, index) => <Cell key={`cell-${index}`} fill={COLORS[entry.name]} />)}
                      </Pie>
                      <Tooltip contentStyle={{ backgroundColor: '#000', borderColor: '#222', color: '#fff', borderRadius: '6px' }} itemStyle={{ color: '#fff' }} />
                    </PieChart>
                  </ResponsiveContainer>
                </div>
                <div className="flex flex-wrap gap-4 mt-2 justify-center">
                  {pieData.map(d => (
                    <div key={d.name} className="flex items-center gap-2 text-xs text-[#888]">
                      <div className="w-2 h-2 rounded-full" style={{ backgroundColor: COLORS[d.name] }}></div>
                      {d.name} ({d.value})
                    </div>
                  ))}
                </div>
              </div>

              <div className="bg-[#0a0a0a] border border-[#222] rounded-lg p-6">
                <h4 className="text-[#888] font-medium text-sm mb-6">Top Risk Dependencies</h4>
                <div className="h-56 w-full">
                  <ResponsiveContainer>
                    <BarChart data={barData} layout="vertical" margin={{ left: 10, right: 10 }}>
                      <XAxis type="number" domain={[0, 10]} hide />
                      <YAxis dataKey="name" type="category" axisLine={false} tickLine={false} tick={{fill: '#888', fontSize: 12}} width={100} />
                      <Tooltip cursor={{fill: '#111'}} contentStyle={{ backgroundColor: '#000', borderColor: '#222', borderRadius: '6px', color: '#fff' }} />
                      <Bar dataKey="risk" fill="#fff" radius={[2, 2, 2, 2]} barSize={16}>
                        {barData.map((entry, index) => (
                          <Cell key={`cell-${index}`} fill={entry.risk >= 8 ? '#ef4444' : entry.risk >= 5 ? '#f97316' : '#fff'} />
                        ))}
                      </Bar>
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              </div>
            </div>
          )}
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

  useEffect(() => { loadRepos().then(() => setLoading(false)) }, [])

  const handleRefresh = async () => {
    setRefreshing(true); await loadRepos(); setRefreshing(false)
  }

  const openReport = async repo => {
    if (!repo.id) return;
    const data = await getReport(repo.id)
    setReport({ ...data, name: repo.repo_name })
  }

  const handleToggleModerate = async (repo) => {
    const newVal = !repo.is_moderated
    setRepos(repos.map(r => r.github_id === repo.github_id ? { ...r, is_moderated: newVal } : r))
    const res = await moderateRepo(repo.url, repo.owner, repo.repo_name, newVal, repo.scan_path || "")
    if (res.repo_id) await loadRepos()
  }

  const handleScanPathChange = (github_id, val) => {
    setRepos(repos.map(r => r.github_id === github_id ? { ...r, scan_path: val } : r))
  }

  if (loading) return <div className="py-32 text-center text-[#888] text-sm animate-pulse">Loading repositories...</div>
  if (!repos.length) return <div className="py-32 text-center border border-[#222] rounded-lg text-[#888] text-sm">No repositories found.</div>

  return (
    <div className="animate-in fade-in duration-300">
      <div className="flex justify-between items-end mb-8">
        <div>
          <h2 className="text-xl font-medium text-white tracking-tight">Repositories</h2>
          <p className="text-[#888] text-sm mt-1">Select repositories to monitor</p>
        </div>
        <button onClick={handleRefresh} disabled={refreshing}
          className="px-4 py-2 bg-white text-black hover:bg-gray-200 disabled:opacity-50 rounded-md text-sm font-medium transition-colors flex items-center gap-2">
          {refreshing ? 'Syncing...' : 'Sync GitHub'}
        </button>
      </div>

      <div className="flex flex-col gap-3">
        {repos.map(r => (
          <div key={r.github_id} className={`group p-4 rounded-lg border transition-colors flex flex-col md:flex-row md:items-center justify-between gap-4 ${r.is_moderated ? 'bg-[#0a0a0a] border-[#333]' : 'bg-[#000] border-[#222] hover:border-[#333]'}`}>
            
            <div className="flex-1 min-w-0 flex items-center gap-4">
              <div className="min-w-0">
                <div className="flex items-center gap-2">
                  <h4 className="font-medium text-[15px] text-white truncate"><a href={r.url} target="_blank" rel="noreferrer" className="hover:underline">{r.repo_name}</a></h4>
                  {r.is_moderated && <span className="w-1.5 h-1.5 rounded-full bg-emerald-500"></span>}
                </div>
                <p className="text-[13px] text-[#888] mt-0.5">{r.owner}</p>
              </div>
            </div>

            <div className="w-full md:w-64">
              <input 
                type="text" 
                placeholder="Target path (e.g. backend/)" 
                className="w-full bg-transparent border border-[#333] focus:border-white rounded-md px-3 py-1.5 text-[13px] text-white outline-none transition-colors placeholder-[#555] disabled:opacity-40 font-mono"
                value={r.scan_path || ''}
                onChange={e => handleScanPathChange(r.github_id, e.target.value)}
                disabled={r.is_moderated}
              />
            </div>

            <div className="flex items-center gap-4 shrink-0">
              {r.is_moderated && r.id ? (
                <button onClick={() => openReport(r)} className="px-3 py-1.5 bg-[#111] hover:bg-[#222] border border-[#333] text-white rounded-md text-[13px] font-medium transition-colors">
                  Report
                </button>
              ) : (
                <span className="text-[13px] text-[#555] w-14 text-right">Inactive</span>
              )}
              
              <label className="relative inline-flex items-center cursor-pointer">
                <input type="checkbox" className="sr-only peer" checked={r.is_moderated} onChange={() => handleToggleModerate(r)} />
                <div className="w-9 h-5 bg-[#222] peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-[#888] after:rounded-full after:h-4 after:w-4 after:transition-all peer-checked:bg-white peer-checked:after:bg-black"></div>
              </label>
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

  const load = async (s = sev) => { setLoading(true); setCves(await getCves(s)); setLoading(false) }
  useEffect(() => { load() }, [])

  const refresh = async () => {
    setRefreshing(true)
    await refreshCves()
    setRefreshing(false)
    load()
  }

  return (
    <div className="animate-in fade-in duration-300">
      <div className="flex items-end justify-between mb-8">
        <div>
          <h2 className="text-xl font-medium text-white tracking-tight">Vulnerability Database</h2>
          <p className="text-[#888] text-sm mt-1">Global NPM advisories</p>
        </div>
        <div className="flex gap-3">
          <select value={sev} onChange={e => { setSev(e.target.value); load(e.target.value) }}
            className="px-3 py-2 bg-transparent border border-[#333] rounded-md text-[13px] text-white outline-none focus:border-white cursor-pointer hover:bg-[#111] transition-colors">
            <option value="" className="bg-[#050505]">All Severities</option>
            {['CRITICAL','HIGH','MEDIUM','LOW'].map(s => <option key={s} className="bg-[#050505]">{s}</option>)}
          </select>
          <button onClick={refresh} disabled={refreshing}
            className="px-4 py-2 bg-white text-black hover:bg-gray-200 disabled:opacity-50 rounded-md text-[13px] font-medium transition-colors">
            {refreshing ? 'Fetching...' : 'Refresh'}
          </button>
        </div>
      </div>

      {loading ? <div className="py-32 text-center text-[#888] text-sm animate-pulse">Loading...</div> : !cves.length
        ? <div className="text-center py-32 border border-[#222] rounded-lg text-[#888] text-sm">No CVEs cached.</div>
        : (
          <div className="overflow-x-auto rounded-lg border border-[#222] bg-[#050505]">
            <table className="w-full text-sm">
              <thead className="bg-[#0a0a0a] text-[#888] border-b border-[#222]">
                <tr>{['GHSA ID','Package','Severity','CVSS','Published','Summary'].map(h => <th key={h} className="text-left px-5 py-3 font-normal text-[12px]">{h}</th>)}</tr>
              </thead>
              <tbody className="divide-y divide-[#222]">
                {cves.map((c, i) => (
                  <tr key={i} className="hover:bg-[#111] transition-colors">
                    <td className="px-5 py-4 font-mono text-[13px]">
                      <a href={`https://github.com/advisories/${c.ghsa_id}`} target="_blank" rel="noreferrer" className="text-white hover:underline">{c.ghsa_id}</a>
                    </td>
                    <td className="px-5 py-4 font-mono text-[13px] text-white">{c.package_name || '—'}</td>
                    <td className="px-5 py-4">{badge(c.severity)}</td>
                    <td className="px-5 py-4 font-medium text-[13px] text-[#888]">{c.cvss ?? '—'}</td>
                    <td className="px-5 py-4 text-[#888] text-[13px]">{c.published_at?.slice(0, 10) || '—'}</td>
                    <td className="px-5 py-4 text-[#888] max-w-sm truncate text-[13px]">{c.summary || '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
    </div>
  )
}

const TABS = [['repos', 'Repositories'], ['cves', 'Advisories']]

export default function Dashboard({ onLogout }) {
  const [tab, setTab] = useState('repos')
  const avatar = localStorage.getItem('avatar_url')

  return (
    <div className="min-h-screen flex flex-col bg-black text-gray-200 font-sans selection:bg-white/20">
      
      <nav className="sticky top-0 z-50 bg-black/80 backdrop-blur-md border-b border-[#222] px-6 py-4 flex items-center justify-between">
        <div className="flex items-center gap-8">
          <h1 className="text-[15px] font-semibold text-white tracking-tight flex items-center gap-2">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5"/></svg>
            HackHelix
          </h1>
          <div className="hidden md:flex gap-1">
            {TABS.map(([id, label]) => (
              <button key={id} onClick={() => setTab(id)}
                className={`px-3 py-1.5 text-[13px] font-medium rounded-md transition-colors ${tab === id ? 'text-white bg-[#111]' : 'text-[#888] hover:text-white hover:bg-[#111]'}`}>
                {label}
              </button>
            ))}
          </div>
        </div>

        <div className="flex items-center gap-4">
          <div className="flex items-center gap-2">
            {avatar && <img src={avatar} alt="avatar" className="w-5 h-5 rounded-full" />}
            <span className="text-[#888] text-[13px] font-medium hidden md:block">{localStorage.getItem('username')}</span>
          </div>
          <button onClick={onLogout} className="text-[13px] text-[#888] hover:text-white transition-colors">Sign Out</button>
        </div>
      </nav>

      {/* Mobile Tabs */}
      <div className="md:hidden border-b border-[#222] flex px-4">
        {TABS.map(([id, label]) => (
          <button key={id} onClick={() => setTab(id)}
            className={`px-4 py-3 text-[13px] font-medium border-b-2 transition-colors ${tab === id ? 'text-white border-white' : 'text-[#888] border-transparent'}`}>
            {label}
          </button>
        ))}
      </div>

      <main className="flex-1 p-6 max-w-5xl w-full mx-auto mt-4 mb-20">
        {tab === 'repos' && <Repos />}
        {tab === 'cves'  && <CVEs />}
      </main>
    </div>
  )
}
