const API = 'http://localhost:8000'
const auth = () => ({ 'Content-Type': 'application/json', Authorization: `Bearer ${localStorage.getItem('token')}` })
const json = r => r.json()

export const githubLogin  = code => fetch(`${API}/auth/github`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ code }) }).then(json)
export const getGithubRepos = () => fetch(`${API}/github/repos`, { headers: auth() }).then(json)
export const moderateRepo = (url, owner, name, isMod, scanPath = "") => fetch(`${API}/repos/moderate`, { method: 'POST', headers: auth(), body: JSON.stringify({ repo_url: url, owner, repo_name: name, is_moderated: isMod, scan_path: scanPath }) }).then(json)
export const getRepos     = ()   => fetch(`${API}/repos`,               { headers: auth() }).then(json)
export const getReport    = id   => fetch(`${API}/repos/${id}/report`,  { headers: auth() }).then(json)
export const getCves      = sev  => fetch(`${API}/cves${sev ? `?severity=${sev}` : ''}`, { headers: auth() }).then(json)
export const refreshCves  = ()   => fetch(`${API}/cves/refresh`,        { method: 'POST', headers: auth() }).then(json)
