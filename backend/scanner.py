import io
import os
import re
import zipfile

import requests
from dotenv import load_dotenv
from packaging.version import InvalidVersion, Version

load_dotenv()
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
OSV_URL = "https://api.osv.dev/v1/query"

SEVERITY_WEIGHT = {"CRITICAL": 1.0, "HIGH": 0.8, "MEDIUM": 0.5, "LOW": 0.2}
SEVERITY_CVSS   = {"CRITICAL": 9.5, "HIGH": 7.5, "MEDIUM": 5.0, "LOW": 2.5}


# ── GitHub repo ────────────────────────────────────────────────────────────────

def _github_headers():
    headers = {"Accept": "application/vnd.github+json"}
    if GITHUB_TOKEN:
        headers["Authorization"] = f"Bearer {GITHUB_TOKEN}"
    return headers


def _github_request(method, url, **kwargs):
    headers = kwargs.pop("headers", None) or _github_headers()
    response = requests.request(method, url, headers=headers, **kwargs)

    # If a configured token is stale/invalid, retry once without auth.
    if (
        response.status_code in (401, 403)
        and headers.get("Authorization")
    ):
        fallback_headers = {k: v for k, v in headers.items() if k.lower() != "authorization"}
        response = requests.request(method, url, headers=fallback_headers, **kwargs)

    return response


def _public_get(url, **kwargs):
    return requests.get(url, timeout=kwargs.pop("timeout", 10), **kwargs)


def _parse_repo_url(repo_url):
    parts = repo_url.strip("/").split("/")
    if len(parts) < 5 or parts[2] != "github.com":
        raise ValueError("Invalid GitHub repository URL")

    owner = parts[3]
    repo = parts[4].removesuffix(".git")
    branch = None
    base_path = ""

    if len(parts) > 6 and parts[5] in ("tree", "blob"):
        branch = parts[6]
        base_path = "/".join(parts[7:])

    return owner, repo, branch, base_path


def _resolve_branch(owner, repo, requested_branch=None):
    if requested_branch:
        return requested_branch

    r_repo = _github_request("GET", f"https://api.github.com/repos/{owner}/{repo}", timeout=10)
    if r_repo.status_code == 200:
        return r_repo.json().get("default_branch", "main")
    return "main"


def _normalize_analysis_path(base_path):
    if not base_path:
        return ""
    if base_path.endswith("package.json"):
        return base_path.rsplit("/", 1)[0] if "/" in base_path else ""
    return base_path


def _manifest_scope(manifest_path):
    if not manifest_path or manifest_path == "package.json":
        return ""
    return manifest_path.rsplit("/", 1)[0] if "/" in manifest_path else ""


def get_deps(repo_url):
    owner, repo, requested_branch, base_path = _parse_repo_url(repo_url)
    branch = _resolve_branch(owner, repo, requested_branch)
    normalized_base_path = _normalize_analysis_path(base_path)

    tree_url = f"https://api.github.com/repos/{owner}/{repo}/git/trees/{branch}?recursive=1"
    r_tree = _github_request("GET", tree_url, timeout=15)

    deps = {}
    if r_tree.status_code == 200:
        tree = r_tree.json().get("tree", [])
        pkg_paths = []

        for item in tree:
            path = item.get("path", "")
            if not path.endswith("package.json") or "node_modules" in path:
                continue
            if normalized_base_path and not (
                path == f"{normalized_base_path}/package.json"
                or path.startswith(f"{normalized_base_path}/")
            ):
                continue
            pkg_paths.append(path)

        manifest_deps = {}
        for path in pkg_paths:
            raw_url = f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{path}"
            r_pkg = _public_get(raw_url, timeout=10)
            if r_pkg.status_code == 200:
                try:
                    pkg_data = r_pkg.json()
                    new_deps = {
                        **pkg_data.get("dependencies", {}),
                        **pkg_data.get("devDependencies", {}),
                    }
                    if new_deps:
                        manifest_deps[path] = new_deps
                    for k, v in new_deps.items():
                        deps[k] = v
                except Exception:
                    pass
    else:
        file_path = f"{normalized_base_path}/package.json" if normalized_base_path else "package.json"
        url = f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{file_path}"
        res = _public_get(url, timeout=10)
        if res.status_code == 200:
            pkg_data = res.json()
            deps = {
                **pkg_data.get("dependencies", {}),
                **pkg_data.get("devDependencies", {}),
            }
            manifest_deps = {file_path: deps} if deps else {}
        else:
            manifest_deps = {}

    if not deps:
        raise ValueError(
            "No npm dependencies found. Make sure the repository contains a "
            "package.json with a 'dependencies' or 'devDependencies' section."
        )

    return deps, owner, repo, branch, normalized_base_path, manifest_deps


# ── OSV.dev ────────────────────────────────────────────────────────────────────

def fetch_osv(package_name):
    try:
        res = requests.post(
            OSV_URL,
            json={"package": {"name": package_name, "ecosystem": "npm"}},
            timeout=10,
        )
        if not res.ok:
            print(f"OSV API error for {package_name}: HTTP {res.status_code}")
            return []
        return res.json().get("vulns", [])
    except Exception as e:
        print(f"OSV fetch failed for {package_name}: {e}")
        return []


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

def enrich_with_codebase_analysis(owner, repo, branch, base_path, hits):
    if not hits:
        return hits

    url = f"https://github.com/{owner}/{repo}/archive/refs/heads/{branch}.zip"
    js_files = {}
    try:
        res = _public_get(url, timeout=20)
        res.raise_for_status()
        with zipfile.ZipFile(io.BytesIO(res.content)) as zipped_repo:
            for name in zipped_repo.namelist():
                if name.endswith((".js", ".jsx", ".ts", ".tsx")):
                    js_files[name] = zipped_repo.read(name).decode("utf-8", errors="ignore").splitlines()
    except Exception:
        return hits

    repo_base_path = _normalize_analysis_path(base_path)

    for hit in hits:
        pkg = hit["package_name"]
        summary = (hit.get("summary") or "").lower()
        manifest_scope = _manifest_scope(hit.get("source_manifest"))
        analysis_base_path = manifest_scope or repo_base_path

        if "prototype pollution" in summary:
            hit["fix_suggestion"] = f"Remove deep merges using {pkg} or upgrade to a safe version."
            hit["risk_impact"] = "High (Prototype Pollution)"
        elif "xss" in summary or "cross-site scripting" in summary:
            hit["fix_suggestion"] = f"Sanitize user input before passing to {pkg} or upgrade."
            hit["risk_impact"] = "Critical (XSS)"
        elif "redos" in summary or "regular expression" in summary:
            hit["fix_suggestion"] = f"Implement request timeouts or upgrade {pkg} to avoid ReDoS."
            hit["risk_impact"] = "Medium (Denial of Service)"
        else:
            hit["fix_suggestion"] = f"Upgrade {pkg} to the latest patched version."
            hit["risk_impact"] = "Moderate"

        hit["affected_file"] = None
        hit["line_number"] = None

        pattern = re.compile(rf"['\"]{re.escape(pkg)}['\"]")
        found = False

        for name, lines in js_files.items():
            if found:
                break

            parts = name.split("/", 1)
            if len(parts) < 2:
                continue

            rel_path = parts[1]
            if analysis_base_path and not (
                rel_path == analysis_base_path
                or rel_path.startswith(f"{analysis_base_path}/")
            ):
                continue

            for idx, line in enumerate(lines):
                has_import = "import " in line or "require(" in line
                if has_import and pattern.search(line):
                    hit["affected_file"] = rel_path
                    hit["line_number"] = idx + 1
                    found = True
                    break

    return hits


def scan_repo(repo_url):
    _, owner, repo_name, branch, base_path, manifest_deps = get_deps(repo_url)
    hits = []
    dep_count = 0
    seen_hits = set()

    for manifest_path, deps in manifest_deps.items():
        for pkg_name, version in deps.items():
            dep_count += 1
            try:
                osv_vulns = fetch_osv(pkg_name)
            except Exception as e:
                print(f"Skipping {pkg_name} from {manifest_path}: {e}")
                continue

            for vuln in osv_vulns:
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

                hit_key = (manifest_path, pkg_name, version, vuln_id or vuln.get("id", ""))
                if hit_key in seen_hits:
                    continue
                seen_hits.add(hit_key)

                hits.append({
                    "package_name":      pkg_name,
                    "installed_version": version,
                    "vuln_id":           vuln_id,
                    "severity":          sev or None,
                    "cvss":              cvss,
                    "risk_score":        score,
                    "summary":           vuln.get("summary"),
                    "source_manifest":   manifest_path,
                })

    hits.sort(key=lambda h: h["risk_score"], reverse=True)
    hits = enrich_with_codebase_analysis(owner, repo_name, branch, base_path, hits)
    manifest_paths = list(manifest_deps.keys())
    return hits, owner, repo_name, dep_count, manifest_paths
