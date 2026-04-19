import React, { useEffect, useMemo, useRef, useState } from 'react';

const EXAMPLE_CVES = [
  { id: 'CVE-2022-25883', label: 'semver ReDoS' },
  { id: 'CVE-2021-23337', label: 'lodash command injection' },
  { id: 'CVE-2024-4068', label: 'braces DoS' },
];

const LOADING_MESSAGES = [
  'Resolving CVE...',
  'Querying dependency graph...',
  'Ranking by impact...',
  'Generating report...',
];

function severityClass(sev) {
  const s = String(sev || '').toUpperCase();
  if (s.includes('CRITICAL') || s.startsWith('CVSS:3') || s.includes('HIGH')) return 'text-danger';
  if (s.includes('MEDIUM') || s.includes('MODERATE')) return 'text-amber-400';
  if (s.includes('LOW')) return 'text-yellow-300';
  return 'text-neutral-300';
}

export default function App() {
  const [mode, setMode] = useState('cve');
  const [cveInput, setCveInput] = useState('CVE-2022-25883');
  const [pkgName, setPkgName] = useState('');
  const [pkgVersion, setPkgVersion] = useState('');

  const [loading, setLoading] = useState(false);
  const [loadingIdx, setLoadingIdx] = useState(0);

  const [error, setError] = useState('');
  const [retryAvailable, setRetryAvailable] = useState(false);
  const lastScanArgs = useRef(null);

  const [results, setResults] = useState(null);
  const [filter, setFilter] = useState('');
  const [modal, setModal] = useState(null);
  const [copyStatus, setCopyStatus] = useState('');

  useEffect(() => {
    if (!loading) return;
    setLoadingIdx(0);
    const id = setInterval(() => {
      setLoadingIdx((i) => (i + 1) % LOADING_MESSAGES.length);
    }, 900);
    return () => clearInterval(id);
  }, [loading]);

  async function runScan(overrideCve) {
    setError('');
    setRetryAvailable(false);
    setResults(null);
    setFilter('');
    setLoading(true);

    try {
      let resolveBody;
      if (overrideCve) {
        resolveBody = { cveId: overrideCve };
      } else if (mode === 'cve') {
        const id = cveInput.trim();
        if (!id) throw new Error('Enter a CVE ID');
        resolveBody = { cveId: id };
      } else {
        const name = pkgName.trim();
        if (!name) throw new Error('Enter a package name');
        resolveBody = { packageName: name, version: pkgVersion.trim() };
      }

      lastScanArgs.current = resolveBody;

      const resolveRes = await fetch('/api/resolve-cve', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(resolveBody),
      });
      const resolved = await resolveRes.json();
      if (!resolveRes.ok) throw new Error(resolved.error || 'Resolve failed');

      const brRes = await fetch('/api/blast-radius', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          packageName: resolved.package,
          version: resolved.affectedVersions,
        }),
      });
      const blast = await brRes.json();
      if (!brRes.ok) throw new Error(blast.error || 'Blast radius scan failed');

      setResults({ resolved, blast });
    } catch (err) {
      setError(err.message || 'Something went wrong');
      setRetryAvailable(true);
    } finally {
      setLoading(false);
    }
  }

  async function draftIssue(dep) {
    if (!results) return;
    const resolved = results.resolved;
    try {
      const r = await fetch('/api/draft-issue', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          vulnerablePackage: resolved.package,
          affectedVersions: resolved.affectedVersions,
          cveId: resolved.cveId,
          dependentPackage: dep.name,
          repoUrl: dep.repoUrl,
        }),
      });
      const data = await r.json();
      if (!r.ok) throw new Error(data.error || 'draft-issue failed');
      if (data.issueUrl) {
        window.open(data.issueUrl, '_blank', 'noopener,noreferrer');
      } else {
        setModal({
          title: data.title,
          body: data.body,
          text: data.copyableText,
          dependent: dep.name,
        });
      }
    } catch (err) {
      setError(err.message);
    }
  }

  function copyModalText() {
    if (!modal) return;
    navigator.clipboard.writeText(modal.text).then(
      () => {
        setCopyStatus('Copied!');
        setTimeout(() => setCopyStatus(''), 1500);
      },
      () => setCopyStatus('Copy failed')
    );
  }

  function downloadJson() {
    if (!results) return;
    const payload = {
      generatedAt: new Date().toISOString(),
      ...results,
    };
    const blob = new Blob([JSON.stringify(payload, null, 2)], {
      type: 'application/json',
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    const safeId = (results.resolved.cveId || 'scan').replace(/[^A-Za-z0-9_-]/g, '_');
    a.download = `blast-radius-${safeId}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }

  const filteredDeps = useMemo(() => {
    const list = results?.blast?.dependents || [];
    if (!filter.trim()) return list;
    const q = filter.toLowerCase();
    return list.filter((d) => d.name.toLowerCase().includes(q));
  }, [filter, results]);

  return (
    <div className="min-h-screen">
      <div className="max-w-6xl mx-auto px-6 py-8">
        {/* Header */}
        <header className="mb-8">
          <div className="flex items-baseline gap-3 flex-wrap">
            <h1 className="text-4xl font-extrabold tracking-tight">
              <span className="text-danger">Blast</span> Radius
            </h1>
            <span className="text-[10px] font-mono uppercase tracking-widest text-neutral-500 border border-edge rounded px-2 py-0.5">
              v1.0 · demo
            </span>
          </div>
          <p className="text-lg text-neutral-300 mt-1">
            Map the downstream impact of open-source CVEs
          </p>
          <p className="text-xs text-neutral-500 mt-1 uppercase tracking-wider">
            Outward-facing CVE propagation for the npm ecosystem
          </p>
        </header>

        {/* Input */}
        <section className="bg-card border border-edge rounded-lg p-6 mb-6">
          <div className="flex gap-2 mb-4">
            <button
              onClick={() => setMode('cve')}
              className={`px-3 py-1.5 rounded text-sm font-medium transition-colors ${
                mode === 'cve'
                  ? 'bg-danger text-white'
                  : 'bg-neutral-900 text-neutral-400 border border-edge hover:text-neutral-200'
              }`}
            >
              Search by CVE ID
            </button>
            <button
              onClick={() => setMode('package')}
              className={`px-3 py-1.5 rounded text-sm font-medium transition-colors ${
                mode === 'package'
                  ? 'bg-danger text-white'
                  : 'bg-neutral-900 text-neutral-400 border border-edge hover:text-neutral-200'
              }`}
            >
              Search by Package
            </button>
          </div>

          {mode === 'cve' ? (
            <input
              type="text"
              value={cveInput}
              onChange={(e) => setCveInput(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && runScan()}
              placeholder="CVE-2022-25883"
              spellCheck={false}
              className="w-full bg-neutral-950 border border-edge rounded px-3 py-2.5 font-mono text-sm focus:outline-none focus:border-danger focus:ring-1 focus:ring-danger/40 transition-colors"
            />
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              <input
                type="text"
                value={pkgName}
                onChange={(e) => setPkgName(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && runScan()}
                placeholder="lodash"
                spellCheck={false}
                className="bg-neutral-950 border border-edge rounded px-3 py-2.5 font-mono text-sm focus:outline-none focus:border-danger focus:ring-1 focus:ring-danger/40 transition-colors"
              />
              <input
                type="text"
                value={pkgVersion}
                onChange={(e) => setPkgVersion(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && runScan()}
                placeholder="<4.17.21"
                spellCheck={false}
                className="bg-neutral-950 border border-edge rounded px-3 py-2.5 font-mono text-sm focus:outline-none focus:border-danger focus:ring-1 focus:ring-danger/40 transition-colors"
              />
            </div>
          )}

          <div className="mt-4 flex items-center gap-4 flex-wrap">
            <button
              onClick={() => runScan()}
              disabled={loading}
              className="bg-danger hover:bg-red-600 disabled:opacity-50 disabled:cursor-not-allowed text-white font-semibold px-5 py-2.5 rounded shadow-lg shadow-red-900/30 transition-colors"
            >
              {loading ? 'Scanning...' : 'Scan Blast Radius'}
            </button>
            {loading && (
              <div className="flex items-center gap-2 text-sm text-neutral-400">
                <div className="br-spinner" />
                <span className="font-mono">{LOADING_MESSAGES[loadingIdx]}</span>
              </div>
            )}
          </div>

          <div className="mt-5 flex flex-wrap gap-2 items-center">
            <span className="text-[10px] text-neutral-500 uppercase tracking-widest mr-1">
              Example CVEs:
            </span>
            {EXAMPLE_CVES.map((ex) => (
              <button
                key={ex.id}
                disabled={loading}
                onClick={() => {
                  setMode('cve');
                  setCveInput(ex.id);
                  runScan(ex.id);
                }}
                className="text-xs font-mono bg-neutral-950 border border-edge rounded px-2.5 py-1 hover:border-danger hover:text-white text-neutral-300 disabled:opacity-50 transition-colors"
              >
                {ex.id} <span className="text-neutral-500">· {ex.label}</span>
              </button>
            ))}
          </div>

          {error && (
            <div className="mt-4 bg-red-950/40 border border-danger/60 rounded p-3 text-sm">
              <div className="flex items-start justify-between gap-3">
                <div>
                  <div className="font-semibold text-danger mb-0.5">Error</div>
                  <div className="text-neutral-200">{error}</div>
                </div>
                {retryAvailable && (
                  <button
                    onClick={() => runScan()}
                    className="bg-neutral-900 border border-edge text-xs px-3 py-1 rounded hover:border-danger"
                  >
                    Retry
                  </button>
                )}
              </div>
            </div>
          )}
        </section>

        {/* Results */}
        {results && (
          <section className="br-fade-in-up">
            {/* Summary */}
            <div className="bg-card border border-edge rounded-lg p-6 mb-4">
              <div className="grid grid-cols-2 md:grid-cols-4 gap-6">
                <div>
                  <div className="text-[10px] text-neutral-500 uppercase tracking-widest">
                    Affected
                  </div>
                  <div className="text-3xl font-bold text-danger font-mono mt-1 leading-none">
                    {results.blast.dependents.length}
                  </div>
                  <div className="text-xs text-neutral-500 mt-1">
                    public dependents shown
                    {results.blast.totalCount &&
                    results.blast.totalCount !== results.blast.dependents.length
                      ? ` · ${results.blast.totalCount.toLocaleString()} total`
                      : ''}
                  </div>
                </div>
                <div>
                  <div className="text-[10px] text-neutral-500 uppercase tracking-widest">
                    CVE
                  </div>
                  <div className="text-sm font-mono mt-1 break-all">
                    {results.resolved.cveId}
                  </div>
                </div>
                <div>
                  <div className="text-[10px] text-neutral-500 uppercase tracking-widest">
                    Vulnerable
                  </div>
                  <div className="text-sm font-mono mt-1 break-all">
                    <span className="text-neutral-100">{results.resolved.package}</span>
                    <span className="text-neutral-500">
                      @{results.resolved.affectedVersions}
                    </span>
                  </div>
                </div>
                <div>
                  <div className="text-[10px] text-neutral-500 uppercase tracking-widest">
                    Severity
                  </div>
                  <div
                    className={`text-sm font-mono mt-1 font-semibold ${severityClass(
                      results.resolved.severity
                    )}`}
                  >
                    {results.resolved.severity}
                  </div>
                </div>
              </div>
              {results.resolved.summary && (
                <div className="text-sm text-neutral-300 border-t border-edge mt-4 pt-4 leading-relaxed">
                  {results.resolved.summary}
                </div>
              )}
            </div>

            {/* Filter + download */}
            <div className="flex items-center gap-3 mb-3">
              <input
                type="text"
                value={filter}
                onChange={(e) => setFilter(e.target.value)}
                placeholder="Filter by package name..."
                spellCheck={false}
                className="flex-1 bg-neutral-950 border border-edge rounded px-3 py-2 text-sm font-mono focus:outline-none focus:border-danger focus:ring-1 focus:ring-danger/40 transition-colors"
              />
              <button
                onClick={downloadJson}
                className="bg-neutral-900 hover:bg-neutral-800 border border-edge text-sm px-4 py-2 rounded transition-colors"
              >
                Download as JSON
              </button>
            </div>

            {/* Table */}
            {filteredDeps.length === 0 ? (
              <div className="bg-card border border-edge rounded-lg p-8 text-center text-neutral-400 text-sm">
                {results.blast.dependents.length === 0
                  ? 'No public dependents found — this package may be leaf or unindexed.'
                  : 'No dependents match your filter.'}
              </div>
            ) : (
              <div className="bg-card border border-edge rounded-lg overflow-hidden">
                <div className="overflow-x-auto">
                  <table className="w-full text-sm">
                    <thead className="bg-neutral-900/60 text-neutral-400 text-[10px] uppercase tracking-widest">
                      <tr>
                        <th className="text-left px-4 py-3 w-14">Rank</th>
                        <th className="text-left px-4 py-3">Package Name</th>
                        <th className="text-left px-4 py-3">Version</th>
                        <th className="text-left px-4 py-3">Has Repo</th>
                        <th className="text-right px-4 py-3">Downstream Deps</th>
                        <th className="text-right px-4 py-3">Action</th>
                      </tr>
                    </thead>
                    <tbody>
                      {filteredDeps.map((d, idx) => (
                        <tr
                          key={`${d.name}-${idx}`}
                          className="border-t border-edge hover:bg-neutral-900/40 transition-colors"
                        >
                          <td className="px-4 py-3 font-mono text-neutral-500">
                            #{idx + 1}
                          </td>
                          <td className="px-4 py-3 font-mono text-neutral-100">
                            {d.name}
                          </td>
                          <td className="px-4 py-3 font-mono text-neutral-400">
                            {d.version}
                          </td>
                          <td className="px-4 py-3">
                            {d.repoUrl ? (
                              <a
                                href={d.repoUrl}
                                target="_blank"
                                rel="noopener noreferrer"
                                className="text-green-400 hover:underline font-mono text-xs"
                                title={d.repoUrl}
                              >
                                ✓ GitHub
                              </a>
                            ) : (
                              <span className="text-neutral-600 font-mono text-xs">—</span>
                            )}
                          </td>
                          <td className="px-4 py-3 font-mono text-right text-neutral-200">
                            {(d.dependentCount || 0).toLocaleString()}
                          </td>
                          <td className="px-4 py-3 text-right">
                            <button
                              onClick={() => draftIssue(d)}
                              className="bg-neutral-900 hover:bg-danger hover:text-white hover:border-danger border border-edge text-xs font-medium px-3 py-1.5 rounded transition-colors"
                            >
                              Draft Issue
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}
          </section>
        )}

        <footer className="mt-10 pt-6 border-t border-edge text-xs text-neutral-600 flex justify-between items-center flex-wrap gap-2">
          <span>
            Data sources: <span className="font-mono text-neutral-400">OSV.dev</span> ·{' '}
            <span className="font-mono text-neutral-400">deps.dev</span> ·{' '}
            <span className="font-mono text-neutral-400">ecosyste.ms</span>
          </span>
          <span className="font-mono">No data is stored. All scans are ephemeral.</span>
        </footer>
      </div>

      {modal && (
        <div
          className="fixed inset-0 bg-black/75 backdrop-blur-sm flex items-center justify-center p-6 z-50"
          onClick={() => setModal(null)}
        >
          <div
            className="bg-card border border-edge rounded-lg p-6 max-w-2xl w-full shadow-2xl"
            onClick={(e) => e.stopPropagation()}
          >
            <h3 className="text-lg font-bold mb-1">No GitHub repo detected</h3>
            <p className="text-sm text-neutral-400 mb-3">
              <span className="font-mono">{modal.dependent}</span> has no linked GitHub
              repository. Copy the issue text below and file it manually with the maintainer.
            </p>
            <textarea
              readOnly
              value={modal.text}
              className="w-full h-72 bg-neutral-950 border border-edge rounded p-3 text-xs font-mono focus:outline-none focus:border-danger"
            />
            <div className="flex gap-2 justify-end mt-3 items-center">
              {copyStatus && (
                <span className="text-xs text-green-400 mr-2">{copyStatus}</span>
              )}
              <button
                onClick={copyModalText}
                className="bg-neutral-900 hover:bg-neutral-800 border border-edge text-sm px-4 py-2 rounded"
              >
                Copy to Clipboard
              </button>
              <button
                onClick={() => setModal(null)}
                className="bg-danger hover:bg-red-600 text-white text-sm px-4 py-2 rounded"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
