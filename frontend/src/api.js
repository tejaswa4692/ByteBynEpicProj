const API = import.meta.env.VITE_API_URL ?? 'http://localhost:8000'

const authHeaders = () => ({
  'Content-Type': 'application/json',
  Authorization: `Bearer ${localStorage.getItem('token')}`,
})

const parseJson = async res => {
  let data
  try { data = await res.json() } catch { data = {} }
  if (!res.ok) throw new Error(data?.detail ?? `Request failed (HTTP ${res.status})`)
  return data
}

// Auth
export const githubLogin = code =>
  fetch(`${API}/auth/github`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ code }),
  }).then(parseJson)

// Repos
export const getGithubRepos = () =>
  fetch(`${API}/github/repos`, { headers: authHeaders() }).then(parseJson)

export const getRepos = () =>
  fetch(`${API}/repos`, { headers: authHeaders() }).then(parseJson)

export const moderateRepo = (url, owner, name, isMod) =>
  fetch(`${API}/repos/moderate`, {
    method: 'POST',
    headers: authHeaders(),
    body: JSON.stringify({ repo_url: url, owner, repo_name: name, is_moderated: isMod }),
  }).then(parseJson)

// Reports & scanning
export const getReport = id =>
  fetch(`${API}/repos/${id}/report`, { headers: authHeaders() }).then(parseJson)

export const scanRepo = url =>
  fetch(`${API}/scan`, {
    method: 'POST',
    headers: authHeaders(),
    body: JSON.stringify({ repo_url: url }),
  }).then(parseJson)

export const certifyRepo = id =>
  fetch(`${API}/repos/${id}/certify`, {
    method: 'POST',
    headers: authHeaders()
  }).then(parseJson)

// CVEs
export const getCves = severity =>
  fetch(`${API}/cves${severity ? `?severity=${severity}` : ''}`, { headers: authHeaders() }).then(parseJson)

export const refreshCves = () =>
  fetch(`${API}/cves/refresh`, { method: 'POST', headers: authHeaders() }).then(parseJson)
