const vscode = require('vscode');
const axios = require('axios');
const path = require('path');
const fs = require('fs');

const SEVERITY_WEIGHT = { CRITICAL: 1.0, HIGH: 0.8, MEDIUM: 0.5, LOW: 0.2 };
let diagnosticCollection;

function escapeRegex(str) {
    return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function escapeHtml(str) {
    return String(str ?? '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
}

async function fetchOSV(packageName) {
    try {
        const res = await axios.post("https://api.osv.dev/v1/query", {
            package: { name: packageName, ecosystem: "npm" }
        });
        return res.data.vulns || [];
    } catch (e) {
        return [];
    }
}

async function scanLocalCodebase(pkgName) {
    const files = await vscode.workspace.findFiles('**/*.{js,jsx,ts,tsx}', '**/node_modules/**');
    const regex = new RegExp(`['"\`]${escapeRegex(pkgName)}['"\`]`);
    
    for (const file of files) {
        try {
            const content = fs.readFileSync(file.fsPath, 'utf8');
            const lines = content.split('\n');
            for (let i = 0; i < lines.length; i++) {
                if ((lines[i].includes('import') || lines[i].includes('require')) && regex.test(lines[i])) {
                    return { file: vscode.workspace.asRelativePath(file), line: i + 1 };
                }
            }
        } catch(e) {}
    }
    return { file: null, line: null };
}

async function scanProject() {
    vscode.window.showInformationMessage('RepodoGG: Scanning project...');
    
    const workspaceFolders = vscode.workspace.workspaceFolders;
    if (!workspaceFolders) {
        vscode.window.showErrorMessage('No workspace open');
        return;
    }

    const packageFiles = await vscode.workspace.findFiles('**/package.json', '**/node_modules/**');
    if (packageFiles.length === 0) {
        vscode.window.showErrorMessage('No package.json found anywhere in your workspace!');
        return;
    }

    let targetPackageJson = packageFiles[0].fsPath;
    if (vscode.window.activeTextEditor) {
        const activePath = vscode.window.activeTextEditor.document.uri.fsPath;
        const matching = packageFiles.find(f => activePath.startsWith(path.dirname(f.fsPath)));
        if (matching) targetPackageJson = matching.fsPath;
    }

    let deps = {};
    try {
        const pkg = JSON.parse(fs.readFileSync(targetPackageJson, 'utf8'));
        deps = { ...(pkg.dependencies || {}), ...(pkg.devDependencies || {}) };
    } catch (e) {
        vscode.window.showErrorMessage('Failed to parse package.json');
        return;
    }

    const hits = [];
    
    await vscode.window.withProgress({
        location: vscode.ProgressLocation.Notification,
        title: "RepodoGG: Analyzing Dependencies & Source Code",
        cancellable: false
    }, async (progress) => {
        const keys = Object.keys(deps);
        let current = 0;
        
        for (const [pkgName, version] of Object.entries(deps)) {
            current++;
            progress.report({ message: `Evaluating ${pkgName}...`, increment: (100 / keys.length) });
            
            const vulns = await fetchOSV(pkgName);
            for (const vuln of vulns) {
                const vulnId = (vuln.aliases || []).find(a => a.startsWith('CVE-')) || vuln.id;
                const sev = vuln.database_specific?.severity || 'LOW';
                
                let cvssScore = null;
                for (const s of (vuln.severity || [])) {
                    if (s.type === 'CVSS_V3' && s.score) {
                        try {
                            cvssScore = parseFloat(s.score);
                            if (isNaN(cvssScore)) cvssScore = null;
                        } catch (e) {}
                    }
                }
                
                let base = cvssScore || (sev === 'CRITICAL' ? 9.5 : sev === 'HIGH' ? 7.5 : sev === 'MODERATE' ? 5.0 : 2.5);
                let mult = SEVERITY_WEIGHT[sev.toUpperCase()] || 0.5;
                let riskScore = Math.min(base * mult, 10.0).toFixed(2);
                
                let summary = (vuln.summary || '').toLowerCase();
                let fix = `Upgrade ${pkgName} to the latest patched version.`;
                let impact = 'Moderate Issue';
                
                if (summary.includes('prototype pollution')) {
                    fix = `Remove deep merges using ${pkgName} or upgrade to a safe version.`;
                    impact = 'High (Prototype Pollution)';
                } else if (summary.includes('xss') || summary.includes('cross-site scripting')) {
                    fix = `Sanitize user input before passing to ${pkgName} or upgrade.`;
                    impact = 'Critical (XSS / Client-side Exec)';
                } else if (summary.includes('redos') || summary.includes('regular expression')) {
                    fix = `Implement request timeouts or upgrade ${pkgName} to avoid ReDoS.`;
                    impact = 'Medium (Denial of Service)';
                }

                const usage = await scanLocalCodebase(pkgName);

                hits.push({
                    package: pkgName,
                    version: version,
                    vulnId,
                    severity: sev,
                    riskScore: parseFloat(riskScore),
                    summary: vuln.summary,
                    fix,
                    impact,
                    affectedFile: usage.file,
                    lineNumber: usage.line
                });
            }
        }
        
        hits.sort((a, b) => b.riskScore - a.riskScore);
        showReportPanel(hits);
    });
}

function showReportPanel(hits) {
    const panel = vscode.window.createWebviewPanel(
        'repodoggReport',
        'RepodoGG Vulnerability Report',
        vscode.ViewColumn.One,
        { enableScripts: true }
    );

    let html = `
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <style>
                body { font-family: var(--vscode-font-family); color: var(--vscode-editor-foreground); padding: 20px; line-height: 1.5; }
                table { width: 100%; border-collapse: collapse; margin-top: 10px; }
                th, td { border-bottom: 1px solid var(--vscode-panel-border); padding: 12px 10px; text-align: left; vertical-align: top; }
                th { color: var(--vscode-textPreformat-foreground); }
                .risk-high { color: #f87171; font-weight: bold; font-size: 1.2em; }
                .risk-med { color: #fbbf24; font-weight: bold; font-size: 1.2em; }
                .risk-low { color: #34d399; font-weight: bold; font-size: 1.2em; }
                .badge { padding: 3px 6px; border-radius: 4px; font-size: 11px; font-weight: bold; background: #374151; color: white; display: inline-block; margin-bottom: 5px; }
                .action { color: #818cf8; font-weight: 500; }
                .file-tag { background: rgba(251, 191, 36, 0.1); color: #fbbf24; padding: 2px 6px; border-radius: 4px; font-family: monospace; }
            </style>
        </head>
        <body>
            <h1 style="border-bottom: 2px solid #4f46e5; padding-bottom: 10px;">🛡️ RepodoGG Local Scanner</h1>
            ${hits.length === 0 ? '<p style="color: #34d399;">✅ Great job! No vulnerabilities directly found in your local package.json.</p>' : ''}
            
            ${hits.length > 0 ? `
            <table>
                <tr>
                    <th>Package Details</th>
                    <th>Risk Score</th>
                    <th>Vulnerability Context</th>
                    <th>Usage Detected</th>
                    <th>Actionable Fix</th>
                </tr>
                ${hits.map(h => `
                    <tr>
                        <td>
                            <strong>${escapeHtml(h.package)}</strong><br>
                            <span style="color:#6b7280; font-size: 12px;">v${escapeHtml(h.version)}</span>
                        </td>
                        <td class="${h.riskScore >= 7 ? 'risk-high' : h.riskScore >= 4 ? 'risk-med' : 'risk-low'}">
                            ${escapeHtml(h.riskScore)}/10
                        </td>
                        <td>
                            <strong>${escapeHtml(h.vulnId)}</strong><br>
                            <span class="badge" style="background:${h.severity === 'CRITICAL' ? '#991b1b' : h.severity === 'HIGH' ? '#c2410c' : '#374151'}">${escapeHtml(h.severity)}</span>
                            <span style="color:#f87171; font-size: 12px;">${escapeHtml(h.impact)}</span>
                        </td>
                        <td>
                            ${h.affectedFile
                                ? `<span class="file-tag">${escapeHtml(h.affectedFile)}</span><br><span style="color:#9ca3af; font-size: 12px;">Line: ${escapeHtml(h.lineNumber)}</span>`
                                : '<span style="color:#6b7280; font-style: italic;">Not explicitly imported</span>'}
                        </td>
                        <td class="action">${escapeHtml(h.fix)}</td>
                    </tr>
                `).join('')}
            </table>
            ` : ''}
        </body>
        </html>
    `;
    panel.webview.html = html;
}

async function analyzePackageJson(document) {
    if (!document.fileName.endsWith('package.json')) return;

    const text = document.getText();
    let pkg;
    try {
        pkg = JSON.parse(text);
    } catch (e) { return; }

    const deps = { ...(pkg.dependencies || {}), ...(pkg.devDependencies || {}) };
    if (Object.keys(deps).length === 0) return;

    const diagnostics = [];

    for (const [pkgName, version] of Object.entries(deps)) {
        const vulns = await fetchOSV(pkgName);
        if (!vulns || vulns.length === 0) continue;

        let highestRiskScore = 0;
        let severityClass = vscode.DiagnosticSeverity.Warning;
        let summaryText = "";
        let impact = "Moderate";
        let fix = "Upgrade dependency.";

        for (const vuln of vulns) {
            const sev = vuln.database_specific?.severity || 'LOW';
            let cvssScore = null;
            for (const s of (vuln.severity || [])) {
                if (s.type === 'CVSS_V3' && s.score) {
                    cvssScore = parseFloat(s.score);
                    if (isNaN(cvssScore)) cvssScore = null;
                }
            }
            let base = cvssScore || (sev === 'CRITICAL' ? 9.5 : sev === 'HIGH' ? 7.5 : sev === 'MODERATE' ? 5.0 : 2.5);
            let mult = SEVERITY_WEIGHT[sev.toUpperCase()] || 0.5;
            let riskScore = Math.min(base * mult, 10.0);

            if (riskScore > highestRiskScore) {
                highestRiskScore = riskScore;
                summaryText = vuln.summary || "Security vulnerability found";
                if (sev === 'CRITICAL' || sev === 'HIGH') {
                    severityClass = vscode.DiagnosticSeverity.Error;
                }
                const summaryLower = summaryText.toLowerCase();
                if (summaryLower.includes('prototype pollution')) {
                    impact = 'High (Prototype Pollution)';
                    fix = `Remove deep merges using ${pkgName} or upgrade.`;
                } else if (summaryLower.includes('xss') || summaryLower.includes('cross-site scripting')) {
                    impact = 'Critical (XSS / Client-side Exec)';
                    fix = "Sanitize inputs or upgrade.";
                } else if (summaryLower.includes('redos')) {
                    impact = "Medium (Denial of Service)";
                } else {
                    impact = `${sev} vulnerability`;
                    fix = "Upgrade to a patched version.";
                }
            }
        }

        if (highestRiskScore > 0) {
            const regex = new RegExp(`"${pkgName}"\\s*:\\s*"[^"]*"`, 'g');
            let match;
            while ((match = regex.exec(text)) !== null) {
                const startPos = document.positionAt(match.index);
                const endPos = document.positionAt(match.index + match[0].length);
                const range = new vscode.Range(startPos, endPos);
                
                const message = `🛡️ RepodoGG Vuln Detected: ${pkgName}\n\n⚠️ Impact: ${impact}\n🛠️ Fix: ${fix}\n\n📚 Context:\n${summaryText}`;
                const diagnostic = new vscode.Diagnostic(range, message, severityClass);
                diagnostics.push(diagnostic);
            }
        }
    }

    if (diagnosticCollection) {
        diagnosticCollection.set(document.uri, diagnostics);
    }
}

function activate(context) {
    let disposable = vscode.commands.registerCommand('repodogg.scanLocalProject', function () {
        scanProject();
    });
    context.subscriptions.push(disposable);

    diagnosticCollection = vscode.languages.createDiagnosticCollection('repodogg');
    context.subscriptions.push(diagnosticCollection);

    context.subscriptions.push(vscode.workspace.onDidSaveTextDocument(doc => {
        analyzePackageJson(doc);
    }));

    context.subscriptions.push(vscode.workspace.onDidOpenTextDocument(doc => {
        analyzePackageJson(doc);
    }));

    if (vscode.window.activeTextEditor) {
        analyzePackageJson(vscode.window.activeTextEditor.document);
    }
}

function deactivate() {
    if (diagnosticCollection) {
        diagnosticCollection.dispose();
    }
}

module.exports = {
    activate,
    deactivate
}
