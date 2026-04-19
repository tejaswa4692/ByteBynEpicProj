import express from 'express';
import cors from 'cors';

const app = express();
app.use(cors());
app.use(express.json({ limit: '1mb' }));

const PORT = process.env.PORT || 3001;

// ---------- helpers ----------

async function fetchWithRetry(url, opts = {}, retries = 1) {
  let lastRes;
  for (let attempt = 0; attempt <= retries; attempt++) {
    try {
      const res = await fetch(url, opts);
      if (res.status === 429 && attempt < retries) {
        await new Promise((r) => setTimeout(r, 1000));
        continue;
      }
      return res;
    } catch (err) {
      lastRes = err;
      if (attempt < retries) {
        await new Promise((r) => setTimeout(r, 1000));
        continue;
      }
      throw err;
    }
  }
  return lastRes;
}

function formatVersionRange(ranges) {
  if (!Array.isArray(ranges) || ranges.length === 0) return 'all versions';
  const events = ranges[0].events || [];
  const introduced = events.find((e) => 'introduced' in e)?.introduced;
  const fixed = events.find((e) => 'fixed' in e)?.fixed;
  const lastAffected = events.find((e) => 'last_affected' in e)?.last_affected;
  if (introduced && introduced !== '0' && fixed) return `>=${introduced} <${fixed}`;
  if (fixed) return `<${fixed}`;
  if (lastAffected) return `<=${lastAffected}`;
  if (introduced && introduced !== '0') return `>=${introduced}`;
  return 'all versions';
}

function extractSeverity(vuln) {
  const score = vuln.severity?.find((s) => s.type?.toUpperCase().includes('CVSS'))?.score;
  if (score) return score;
  const dbSev = vuln.database_specific?.severity;
  if (dbSev) return String(dbSev).toUpperCase();
  return 'UNKNOWN';
}

function parseRepoUrl(url) {
  if (!url) return null;
  const cleaned = url.replace(/^git\+/, '').replace(/\.git$/, '');
  const match = cleaned.match(/github\.com[:/]+([^/]+)\/([^/?#]+)/i);
  if (!match) return null;
  return { owner: match[1], repo: match[2].replace(/\.git$/, '') };
}

// ---------- endpoints ----------

app.get('/api/health', (_req, res) => {
  res.json({ ok: true, service: 'blast-radius', time: new Date().toISOString() });
});

// POST /api/resolve-cve
app.post('/api/resolve-cve', async (req, res) => {
  try {
    const { cveId, packageName, version } = req.body || {};

    // Package-only mode: echo the input as the "vulnerable" target.
    if (!cveId && packageName) {
      return res.json({
        package: packageName,
        affectedVersions: version || 'all versions',
        severity: 'USER-DEFINED',
        summary: 'Scanning dependents for user-supplied package and version range.',
        cveId: 'USER-INPUT',
      });
    }

    if (!cveId) {
      return res.status(400).json({ error: 'Provide a cveId or packageName.' });
    }

    const cleanId = String(cveId).trim().toUpperCase();
    console.log(`[resolve-cve] Step 1 — Fetching OSV data for: ${cleanId}`);

    const osvRes = await fetchWithRetry(`https://api.osv.dev/v1/vulns/${encodeURIComponent(cleanId)}`);

    if (osvRes.status === 404) {
      console.log(`[resolve-cve] OSV returned 404 for ${cleanId}`);
      return res.status(404).json({ error: 'CVE not found in OSV database' });
    }
    if (!osvRes.ok) {
      console.log(`[resolve-cve] OSV returned non-OK status ${osvRes.status} for ${cleanId}`);
      return res.status(502).json({ error: `OSV API error (${osvRes.status})` });
    }

    const data = await osvRes.json();
    const allEcosystems = new Set();

    // -- helper: find the first npm affected entry in an OSV response object --
    function findNpmAffected(vulnData) {
      for (const a of vulnData.affected || []) {
        const eco = a.package?.ecosystem || '';
        allEcosystems.add(eco);
        if (eco === 'npm') return { affected: a, vulnData };
      }
      return null;
    }

    // Step 2 — look for npm entry in the direct CVE response
    console.log(`[resolve-cve] Step 2 — Scanning ${(data.affected || []).length} affected entries for ecosystem "npm"`);
    let result = findNpmAffected(data);

    // Step 3 — if not found, chase GHSA aliases
    if (!result) {
      const aliases = data.aliases || [];
      const ghsaAliases = aliases.filter((a) => String(a).startsWith('GHSA-'));
      console.log(`[resolve-cve] Step 3 — No npm entry on ${cleanId}. Found ${ghsaAliases.length} GHSA alias(es): ${ghsaAliases.join(', ') || '(none)'}`);

      for (const alias of ghsaAliases) {
        console.log(`[resolve-cve]   Fetching alias: ${alias}`);
        const aliasRes = await fetchWithRetry(`https://api.osv.dev/v1/vulns/${encodeURIComponent(alias)}`);
        if (!aliasRes.ok) {
          console.log(`[resolve-cve]   Alias ${alias} returned ${aliasRes.status}, skipping`);
          continue;
        }
        const aliasData = await aliasRes.json();
        console.log(`[resolve-cve]   Alias ${alias} has ${(aliasData.affected || []).length} affected entries`);
        result = findNpmAffected(aliasData);
        if (result) {
          console.log(`[resolve-cve]   ✓ Found npm entry via alias ${alias}`);
          break;
        }
      }
    }

    // Step 4 — no npm entry anywhere
    if (!result) {
      const ecoList = allEcosystems.size > 0
        ? Array.from(allEcosystems).join(', ')
        : 'none';
      console.log(`[resolve-cve] Step 4 — No npm entry found. Ecosystems encountered: ${ecoList}`);
      return res.status(404).json({
        error: `CVE exists but does not affect any npm package. Ecosystems found: ${ecoList}`,
      });
    }

    // Step 5 — extract fields from the matched entry
    const { affected, vulnData } = result;
    const pkgName = affected.package.name;
    const versionRange = formatVersionRange(affected.ranges);
    const severity = extractSeverity(vulnData);
    const summary =
      vulnData.summary ||
      (vulnData.details ? vulnData.details.split('\n')[0].slice(0, 240) : 'See CVE details');

    console.log(`[resolve-cve] Step 5 — Extracted:`);
    console.log(`  package        : ${pkgName}`);
    console.log(`  affectedVersions: ${versionRange}`);
    console.log(`  severity       : ${severity}`);
    console.log(`  summary        : ${summary.slice(0, 80)}…`);

    res.json({
      package: pkgName,
      affectedVersions: versionRange,
      severity: severity.toString(),
      summary,
      cveId: cleanId,
    });
  } catch (err) {
    console.error('resolve-cve error:', err);
    res.status(500).json({ error: err.message || 'resolve-cve failed' });
  }
});

// POST /api/blast-radius
// ⚠️  DEMO DATA — this endpoint returns hardcoded dependents for a reliable
// demo experience.  No external API calls are made.  Replace with live
// ecosyste.ms / deps.dev integration when ready for production.
app.post('/api/blast-radius', (req, res) => {
  try {
    const { packageName, severity: reqSeverity } = req.body || {};
    if (!packageName) return res.status(400).json({ error: 'Missing packageName' });

    const sev = reqSeverity || 'HIGH';

    // Helper to build an entry quickly
    const e = (name, version, dependentCount, org) => ({
      name,
      version,
      repoUrl: `https://github.com/${org || name}/${org ? name : name}`,
      dependentCount,
      severity: sev,
    });

    const DEMO_DATA = {
      lodash: [
        e('express-validator', '7.0.1', 15320, 'express-validator'),
        e('react-scripts',     '5.0.1', 12450, 'facebook'),
        e('webpack',           '5.91.0', 11204, 'webpack'),
        e('babel-loader',      '9.1.3',  8923, 'babel'),
        e('eslint-config-airbnb', '19.0.4', 7841, 'airbnb'),
        e('gulp',              '4.0.2',  6532, 'gulpjs'),
        e('yeoman-generator',  '7.1.0',  5190, 'yeoman'),
        e('grunt',             '1.6.1',  4876, 'gruntjs'),
        e('karma',             '6.4.3',  4310, 'karma-runner'),
        e('nodemon',           '3.1.0',  3952, 'remy'),
        e('pm2',               '5.3.1',  3641, 'Unitech'),
        e('jest',              '29.7.0', 3287, 'jestjs'),
        e('mocha',             '10.4.0', 2847, 'mochajs'),
        e('chai',              '5.1.0',  2614, 'chaijs'),
        e('sinon',             '17.0.1', 2398, 'sinonjs'),
        e('commander',         '12.0.0', 2105, 'tj'),
        e('inquirer',          '9.2.15', 1843, 'SBoudrias'),
        e('ora',               '8.0.1',  1527, 'sindresorhus'),
        e('chalk',             '5.3.0',  1390, 'chalk'),
        e('debug',             '4.3.4',  1204, 'debug-js'),
      ],

      braces: [
        e('micromatch',         '4.0.5', 18740, 'micromatch'),
        e('chokidar',           '3.6.0', 16215, 'paulmillr'),
        e('anymatch',           '3.1.3', 12580, 'micromatch'),
        e('glob-parent',        '6.0.2', 10930, 'gulpjs'),
        e('readdirp',           '3.6.0',  9475, 'paulmillr'),
        e('fast-glob',          '3.3.2',  8310, 'mrmlnc'),
        e('globby',             '14.0.1', 7126, 'sindresorhus'),
        e('watchpack',          '2.4.1',  6248, 'webpack'),
        e('webpack-dev-server', '5.0.4',  5590, 'webpack'),
        e('nodemon',            '3.1.0',  4817, 'remy'),
        e('rollup',             '4.14.1', 3942, 'rollup'),
        e('vite',               '5.2.8',  3510, 'vitejs'),
        e('jest',               '29.7.0', 2976, 'jestjs'),
        e('@babel/core',        '7.24.4', 2430, 'babel'),
        e('postcss',            '8.4.38', 1895, 'postcss'),
      ],

      semver: [
        e('npm',                 '10.5.0', 24310, 'npm'),
        e('yarn',                '1.22.22', 19870, 'yarnpkg'),
        e('eslint',              '9.1.0',  17540, 'eslint'),
        e('typescript',          '5.4.5',  15280, 'microsoft'),
        e('webpack',             '5.91.0', 13420, 'webpack'),
        e('lerna',               '8.1.2',  10950, 'lerna'),
        e('@babel/core',         '7.24.4',  9310, 'babel'),
        e('rollup',              '4.14.1',  7680, 'rollup'),
        e('create-react-app',    '5.0.1',   6240, 'facebook'),
        e('nx',                  '18.2.4',  5470, 'nrwl'),
        e('storybook',           '8.0.8',   4310, 'storybookjs'),
        e('jest',                '29.7.0',  3850, 'jestjs'),
        e('prettier',            '3.2.5',   2940, 'prettier'),
        e('husky',               '9.0.11',  2180, 'typicode'),
        e('standard-version',    '9.5.0',   1625, 'conventional-changelog'),
      ],
    };

    // Generic fallback for any other package
    const GENERIC_FALLBACK = [
      e('webpack',       '5.91.0', 8420, 'webpack'),
      e('eslint',        '9.1.0',  7310, 'eslint'),
      e('jest',          '29.7.0', 5840, 'jestjs'),
      e('rollup',        '4.14.1', 4520, 'rollup'),
      e('vite',          '5.2.8',  3890, 'vitejs'),
      e('@babel/core',   '7.24.4', 3240, 'babel'),
      e('typescript',    '5.4.5',  2780, 'microsoft'),
      e('nodemon',       '3.1.0',  2150, 'remy'),
      e('prettier',      '3.2.5',  1640, 'prettier'),
      e('husky',         '9.0.11', 1120, 'typicode'),
    ];

    const key = packageName.toLowerCase();
    const dependents = (DEMO_DATA[key] || GENERIC_FALLBACK)
      .slice()
      .sort((a, b) => b.dependentCount - a.dependentCount);

    console.log(`[blast-radius] Returning ${dependents.length} demo dependents for "${packageName}"`);

    res.json({
      dependents,
      totalCount: dependents.reduce((s, d) => s + d.dependentCount, 0),
      shownCount: dependents.length,
    });
  } catch (err) {
    console.error('blast-radius error:', err);
    res.status(500).json({ error: err.message || 'blast-radius failed' });
  }
});

// POST /api/draft-issue
app.post('/api/draft-issue', (req, res) => {
  try {
    const {
      vulnerablePackage,
      affectedVersions,
      cveId,
      dependentPackage,
      repoUrl,
    } = req.body || {};

    if (!vulnerablePackage || !dependentPackage) {
      return res.status(400).json({ error: 'Missing vulnerablePackage or dependentPackage' });
    }

    const advisoryUrl =
      cveId && cveId !== 'USER-INPUT'
        ? `https://osv.dev/vulnerability/${encodeURIComponent(cveId)}`
        : null;

    const title = `Security: Update \`${vulnerablePackage}\` to patched version (${cveId || 'advisory'})`;

    const body = [
      `Hi maintainers of \`${dependentPackage}\`,`,
      '',
      `An automated ecosystem scan flagged that \`${dependentPackage}\` depends on \`${vulnerablePackage}\` in a version range affected by **${cveId || 'a published advisory'}** (\`${affectedVersions || 'see advisory'}\`).`,
      '',
      '**Details**',
      `- Vulnerable package: \`${vulnerablePackage}\``,
      `- Affected range: \`${affectedVersions || 'see advisory'}\``,
      advisoryUrl ? `- Advisory: ${advisoryUrl}` : '- Advisory: (user-supplied)',
      '',
      '**Suggested action**',
      `Please consider bumping \`${vulnerablePackage}\` to a patched version, or pinning an override/resolution in the lockfile if a direct update is not yet feasible.`,
      '',
      `This issue was opened via an automated scan that walks the dependency graph outward from a published CVE. Happy to close it if the exposure has already been addressed, or if you'd prefer patches come via PR — thanks for maintaining \`${dependentPackage}\`.`,
    ].join('\n');

    const parsed = parseRepoUrl(repoUrl);

    if (!parsed) {
      return res.json({
        issueUrl: null,
        copyableText: `${title}\n\n${body}`,
        title,
        body,
      });
    }

    const issueUrl =
      `https://github.com/${parsed.owner}/${parsed.repo}/issues/new` +
      `?title=${encodeURIComponent(title)}` +
      `&body=${encodeURIComponent(body)}`;

    res.json({ issueUrl, title, body });
  } catch (err) {
    console.error('draft-issue error:', err);
    res.status(500).json({ error: err.message || 'draft-issue failed' });
  }
});

app.listen(PORT, () => {
  console.log(`Blast Radius server listening on http://localhost:${PORT}`);
});
