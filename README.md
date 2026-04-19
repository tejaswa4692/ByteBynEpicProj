# Blast Radius

**Map the downstream impact of open-source CVEs across the npm ecosystem.**

Paste a CVE ID (or a package + affected version range) and Blast Radius resolves
the affected npm package, walks the public dependency graph outward, and gives
you a ranked, filterable table of downstream packages that are transitively
exposed. One click per row generates a pre-filled GitHub issue for the
maintainer.

![screenshot](docs/screenshot.png)

---

## Stack

- **Backend:** Node.js 18+ / Express (single-file `server/server.js`)
- **Frontend:** React + Vite + TailwindCSS (`client/`)
- **No database. No auth. No persistence.** Everything is stateless.

### Data sources

- [OSV.dev](https://osv.dev) — resolves `CVE-XXXX-XXXXX` → `{ npm package, affected range, severity, summary }`
- [deps.dev](https://deps.dev) (Google) — total dependent count for the vulnerable package
- [ecosyste.ms](https://ecosyste.ms) — actual list of dependent npm packages (deps.dev's public API exposes only counts, not the list, so we enrich with ecosyste.ms' free public aggregator)

---

## Run locally

You need **Node.js 18+** (native `fetch`).

Open two terminals.

### Terminal 1 — backend

```bash
cd server
npm install
node server.js
```

Server listens on `http://localhost:3001`.

### Terminal 2 — frontend

```bash
cd client
npm install
npm run dev
```

Vite dev server listens on `http://localhost:5173` and proxies `/api/*` to the
backend. Open http://localhost:5173 in a browser.

---

## 3-minute demo script

**0:00 — Open the app.** The CVE input is pre-seeded with `CVE-2022-25883`
(semver ReDoS). Point out the three **Example CVEs** chips below the input:
semver, lodash, braces — all real, high-impact npm CVEs.

**0:20 — Click "Scan Blast Radius."** Call out the loading states cycling
through *Resolving CVE… → Querying dependency graph… → Ranking by impact… →
Generating report…*. This is hitting OSV first, then ecosyste.ms for the
dependents list, then deps.dev for the aggregate count.

**0:45 — Summary card.** Point to the four stats:
- Number of affected dependents shown
- CVE ID
- Vulnerable package @ affected range (note: `<7.5.2`)
- Severity (pulled from OSV)

**1:15 — Results table.** Explain the ranking: packages are sorted by *their
own* dependent count — i.e., the ones that will propagate the CVE furthest
appear first. Type `react` into the filter to demo the live search. Click
"Download as JSON" to show the exportable ecosystem report.

**2:00 — Draft an issue.** Pick any row with a green ✓ GitHub badge and click
**Draft Issue**. A new tab opens on `github.com/owner/repo/issues/new` with a
pre-filled, respectful, maintainer-tone message that:
- Names the CVE and the vulnerable dependency
- Links the OSV advisory
- Suggests the patched range
- Discloses that it was opened via an automated ecosystem scan

**2:30 — Fallback case.** Click **Draft Issue** on a row with no GitHub link
(`—`). A modal pops up with the same text, copy-able to clipboard, so the user
can file it wherever the package is actually hosted.

**2:50 — Try CVE-2021-23337 (lodash).** One click on the chip re-runs the whole
flow. Show how one tool handles any advisory that OSV indexes for npm.

---

## API

All endpoints are `POST` on port `3001` (proxied by Vite at `/api/*` in dev).

### `POST /api/resolve-cve`
```json
// input (either one):
{ "cveId": "CVE-2022-25883" }
{ "packageName": "lodash", "version": "<4.17.21" }

// output:
{
  "package": "semver",
  "affectedVersions": ">=7.0.0 <7.5.2",
  "severity": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H",
  "summary": "semver vulnerable to Regular Expression Denial of Service",
  "cveId": "CVE-2022-25883"
}
```

### `POST /api/blast-radius`
```json
// input:
{ "packageName": "semver", "version": ">=7.0.0 <7.5.2" }

// output:
{
  "dependents": [
    { "name": "eslint", "version": "9.x", "repoUrl": "https://github.com/eslint/eslint",
      "dependentCount": 412309, "directDependent": true },
    ...
  ],
  "totalCount": 5823114,
  "shownCount": 100
}
```

### `POST /api/draft-issue`
```json
// input:
{
  "vulnerablePackage": "semver",
  "affectedVersions": ">=7.0.0 <7.5.2",
  "cveId": "CVE-2022-25883",
  "dependentPackage": "some-lib",
  "repoUrl": "https://github.com/owner/some-lib"
}

// output:
{ "issueUrl": "https://github.com/owner/some-lib/issues/new?title=...&body=..." }
// or, if no repoUrl:
{ "issueUrl": null, "copyableText": "Security: ...\n\nHi maintainers..." }
```

---

## Error handling

| Case                        | Behavior                                                      |
| --------------------------- | ------------------------------------------------------------- |
| CVE not found in OSV        | `404 CVE not found in OSV database`                           |
| CVE exists, not npm         | `404 CVE exists, but does not affect any npm package.`        |
| No public dependents        | `No public dependents found — this package may be leaf or unindexed` |
| Dependents API rate-limited | Auto-retry once with 1s backoff, then `429 Rate limited, try again in a minute` |
| Network error               | Error banner with a **Retry** button                          |

---

## Project layout

```
blast-radius/
├── server/
│   ├── package.json
│   └── server.js          # single-file Express backend
├── client/
│   ├── package.json
│   ├── vite.config.js
│   ├── tailwind.config.js
│   ├── postcss.config.js
│   ├── index.html
│   └── src/
│       ├── main.jsx
│       ├── index.css
│       └── App.jsx
└── README.md
```

---

## What this is NOT

- Not a replacement for `npm audit` or Snyk — this is an **outward** propagation
  tool (given a vuln, who's exposed?), not an inward audit of your `package.json`.
- Not a private-registry scanner — only hits public data (OSV, deps.dev,
  ecosyste.ms).
- Not authoritative — "no public dependents" means exactly that; a package may
  still be depended on by private code.
