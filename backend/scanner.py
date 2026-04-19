import os
import requests
from dotenv import load_dotenv
from packaging.version import Version, InvalidVersion

load_dotenv()
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
OSV_URL = "https://api.osv.dev/v1/query"

SEVERITY_WEIGHT = {"CRITICAL": 1.0, "HIGH": 0.8, "MEDIUM": 0.5, "LOW": 0.2}
SEVERITY_CVSS   = {"CRITICAL": 9.5, "HIGH": 7.5, "MEDIUM": 5.0, "LOW": 2.5}


# ── GitHub repo ────────────────────────────────────────────────────────────────

def get_deps(repo_url, target_path=""):
    parts = repo_url.strip("/").split("/")
    owner, repo = parts[3], parts[4]

    headers = {}
    if GITHUB_TOKEN:
        headers["Authorization"] = f"Bearer {GITHUB_TOKEN}"

    # Get default branch
    branch = "main"
    r_repo = requests.get(f"https://api.github.com/repos/{owner}/{repo}", headers=headers, timeout=10)
    if r_repo.status_code == 200:
        branch = r_repo.json().get("default_branch", "main")

    tree_url = f"https://api.github.com/repos/{owner}/{repo}/git/trees/{branch}?recursive=1"
    r_tree = requests.get(tree_url, headers=headers, timeout=15)
    
    deps = {}
    if r_tree.status_code == 200:
        tree = r_tree.json().get("tree", [])
        # Find all package.json files not in node_modules
        pkg_paths = [item["path"] for item in tree if item["path"].endswith("package.json") and "node_modules" not in item["path"]]
        
        if target_path and target_path != "/" and target_path != "":
            tp = target_path.strip("/")
            pkg_paths = [p for p in pkg_paths if p.startswith(tp + "/") or p == f"{tp}/package.json" or p == tp]
            
        for path in pkg_paths:
            raw_url = f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{path}"
            r_pkg = requests.get(raw_url, timeout=10)
            if r_pkg.status_code == 200:
                try:
                    pkg_data = r_pkg.json()
                    new_deps = pkg_data.get("dependencies", {})
                    for k, v in new_deps.items():
                        deps[k] = v  # Overwrites duplicates, keeping one version
                except Exception:
                    pass
    else:
        # Fallback to direct raw request if tree API fails
        file_path = "package.json"
        url = f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{file_path}"
        res = requests.get(url, timeout=10)
        if res.status_code == 200:
            deps = res.json().get("dependencies", {})
            
    return deps, owner, repo


# ── OSV.dev ────────────────────────────────────────────────────────────────────

def fetch_osv(package_name):
    res = requests.post(OSV_URL, json={"package": {"name": package_name, "ecosystem": "npm"}}, timeout=10)
    return res.json().get("vulns", [])


# ── GitHub Advisory ────────────────────────────────────────────────────────────

GH_QUERY = """
query($after: String) {
  securityAdvisories(first: 100, after: $after, orderBy: {field: PUBLISHED_AT, direction: DESC}) {
    pageInfo { hasNextPage endCursor }
    nodes {
      ghsaId summary publishedAt severity
      cvss { score }
      vulnerabilities(first: 10) {
        nodes { package { name ecosystem } }
      }
    }
  }
}
"""

def fetch_github_advisories():
    if not GITHUB_TOKEN:
        raise ValueError("GITHUB_TOKEN not set in .env")

    headers = {"Authorization": f"Bearer {GITHUB_TOKEN}"}
    results, cursor = [], None

    for _ in range(5):  # max 5 pages = 500 advisories
        res = requests.post(
            "https://api.github.com/graphql",
            json={"query": GH_QUERY, "variables": {"after": cursor}},
            headers=headers, timeout=15
        )
        data = res.json()["data"]["securityAdvisories"]

        for node in data["nodes"]:
            for vuln in node["vulnerabilities"]["nodes"]:
                pkg = vuln.get("package") or {}
                if pkg.get("ecosystem", "").lower() != "npm":
                    continue
                results.append({
                    "ghsa_id":      node["ghsaId"],
                    "package_name": pkg.get("name"),
                    "severity":     node.get("severity"),
                    "cvss":         (node.get("cvss") or {}).get("score"),
                    "summary":      node.get("summary"),
                    "published_at": node.get("publishedAt"),
                })

        if not data["pageInfo"]["hasNextPage"]:
            break
        cursor = data["pageInfo"]["endCursor"]

    return results


# ── risk scoring ───────────────────────────────────────────────────────────────

def _is_affected(installed, affected_list):
    try:
        ver = Version(installed.lstrip("^~>=<! "))
    except InvalidVersion:
        return True

    for entry in (affected_list or []):
        for r in entry.get("ranges", []):
            if r.get("type") not in ("SEMVER", "ECOSYSTEM"):
                continue
            introduced = fixed = None
            for event in r.get("events", []):
                if "introduced" in event: introduced = event["introduced"]
                if "fixed" in event:      fixed = event["fixed"]
            try:
                ok = not introduced or introduced == "0" or ver >= Version(introduced)
                if fixed: ok = ok and ver < Version(fixed)
                if ok: return True
            except InvalidVersion:
                return True
    return False


def risk_score(cvss, severity, installed, affected):
    if not _is_affected(installed, affected):
        return None
    base = cvss if cvss else SEVERITY_CVSS.get((severity or "").upper(), 5.0)
    mult = SEVERITY_WEIGHT.get((severity or "").upper(), 0.5)
    return round(min(base * mult, 10.0), 2)


import re
import zipfile
import io

# ── full scan ──────────────────────────────────────────────────────────────────

def enrich_with_codebase_analysis(owner, repo, branch, base_path, hits):
    if not hits:
        return hits

    url = f"https://github.com/{owner}/{repo}/archive/refs/heads/{branch}.zip"
    js_files = {}
    try:
        res = requests.get(url, timeout=15)
        res.raise_for_status()
        with zipfile.ZipFile(io.BytesIO(res.content)) as z:
            for name in z.namelist():
                if name.endswith((".js", ".jsx", ".ts", ".tsx")):
                    js_files[name] = z.read(name).decode("utf-8", errors="ignore").splitlines()
    except Exception as e:
        print(f"Failed to download zip for analysis: {e}")
        pass

    for h in hits:
        pkg = h["package_name"]
        summary = (h.get("summary") or "").lower()
        
        if "prototype pollution" in summary:
            h["fix_suggestion"] = f"Remove deep merges using {pkg} or upgrade to a safe version."
            h["risk_impact"] = "High (Prototype Pollution)"
        elif "xss" in summary or "cross-site scripting" in summary:
            h["fix_suggestion"] = f"Sanitize user input before passing to {pkg} or upgrade."
            h["risk_impact"] = "Critical (XSS)"
        elif "redos" in summary or "regular expression" in summary:
            h["fix_suggestion"] = f"Implement request timeouts or upgrade {pkg} to avoid ReDoS."
            h["risk_impact"] = "Medium (Denial of Service)"
        else:
            h["fix_suggestion"] = f"Upgrade {pkg} to the latest patched version."
            h["risk_impact"] = "Moderate"

        h["affected_file"] = None
        h["line_number"] = None

        pattern = re.compile(rf"['\"]{re.escape(pkg)}['\"]")
        
        found = False
        for name, lines in js_files.items():
            if found: break
            parts = name.split("/", 1)
            if len(parts) > 1:
                rel_path = parts[1]
                if base_path and not rel_path.startswith(base_path.strip("/") + "/"):
                    continue
                
                for idx, line in enumerate(lines):
                    if ("import " in line or "require(" in line) and pattern.search(line):
                        h["affected_file"] = rel_path
                        h["line_number"] = idx + 1
                        found = True
                        break

    return hits

def scan_repo(repo_url, target_path=""):
    deps, owner, repo_name = get_deps(repo_url, target_path)
    
    # Try to find branch name for zip download
    branch = "main"
    headers = {}
    if GITHUB_TOKEN: headers["Authorization"] = f"Bearer {GITHUB_TOKEN}"
    r_repo = requests.get(f"https://api.github.com/repos/{owner}/{repo_name}", headers=headers, timeout=10)
    if r_repo.status_code == 200:
        branch = r_repo.json().get("default_branch", "main")

    hits = []

    for pkg_name, version in deps.items():
        for vuln in fetch_osv(pkg_name):
            aliases = vuln.get("aliases", [])
            vuln_id = next((a for a in aliases if a.startswith("CVE-")), vuln.get("id", ""))
            sev     = vuln.get("database_specific", {}).get("severity", "") or ""
            cvss = None
            for s in vuln.get("severity", []):
                if s.get("type") == "CVSS_V3" and s.get("score"):
                    try:
                        cvss = float(s["score"])
                        break
                    except ValueError:
                        pass

            score = risk_score(cvss, sev, version, vuln.get("affected"))
            if score is None:
                continue

            fixed_version = None
            for entry in vuln.get("affected", []):
                for r in entry.get("ranges", []):
                    for event in r.get("events", []):
                        if "fixed" in event:
                            fixed_version = event["fixed"]
                            break
                    if fixed_version: break
                if fixed_version: break

            hits.append({
                "package_name":      pkg_name,
                "installed_version": version,
                "vuln_id":           vuln_id,
                "severity":          sev or None,
                "cvss":              cvss,
                "risk_score":        score,
                "summary":           vuln.get("summary"),
                "fixed_version":     fixed_version
            })

    hits.sort(key=lambda h: h["risk_score"], reverse=True)
    hits = enrich_with_codebase_analysis(owner, repo_name, branch, target_path, hits)
    return hits, owner, repo_name, len(deps)
