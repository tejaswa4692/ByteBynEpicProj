const API = 'http://localhost:8000'
const auth = () => ({ 'Content-Type': 'application/json', Authorization: `Bearer ${localStorage.getItem('token')}` })
const json = r => r.json()

export const login    = (u, p) => fetch(`${API}/auth/login`,    { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username: u, password: p }) }).then(json)
export const register = (u, p) => fetch(`${API}/auth/register`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username: u, password: p }) }).then(json)
export const scanRepo     = url  => fetch(`${API}/scan`,               { method: 'POST', headers: auth(), body: JSON.stringify({ repo_url: url }) }).then(json)
export const getRepos     = ()   => fetch(`${API}/repos`,               { headers: auth() }).then(json)
export const getReport    = id   => fetch(`${API}/repos/${id}/report`,  { headers: auth() }).then(json)
export const getCves      = sev  => fetch(`${API}/cves${sev ? `?severity=${sev}` : ''}`, { headers: auth() }).then(json)
export const refreshCves  = ()   => fetch(`${API}/cves/refresh`,        { method: 'POST', headers: auth() }).then(json)
