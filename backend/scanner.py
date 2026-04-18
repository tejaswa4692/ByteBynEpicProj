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

def get_deps(repo_url):
    parts = repo_url.strip("/").split("/")
    owner, repo = parts[3], parts[4]
    branch, path = "main", ""
    if "tree" in parts:
        i = parts.index("tree")
        branch, path = parts[i + 1], "/".join(parts[i + 2:])
    elif "blob" in parts:
        i = parts.index("blob")
        branch, path = parts[i + 1], "/".join(parts[i + 2:])

    file_path = f"{path}/package.json" if path else "package.json"
    url = f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{file_path}"
    res = requests.get(url, timeout=10)
    if res.status_code != 200:
        raise ValueError("package.json not found in this repo")

    pkg = res.json()
    return pkg.get("dependencies", {}), owner, repo


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


# ── full scan ──────────────────────────────────────────────────────────────────

def scan_repo(repo_url):
    deps, owner, repo_name = get_deps(repo_url)
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

            hits.append({
                "package_name":      pkg_name,
                "installed_version": version,
                "vuln_id":           vuln_id,
                "severity":          sev or None,
                "cvss":              cvss,
                "risk_score":        score,
                "summary":           vuln.get("summary"),
            })

    hits.sort(key=lambda h: h["risk_score"], reverse=True)
    return hits, owner, repo_name, len(deps)
