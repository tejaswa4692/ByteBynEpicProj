import os
from supabase import create_client
from dotenv import load_dotenv

load_dotenv()
sb = create_client(os.getenv("SUPABASE_URL"), os.getenv("SUPABASE_KEY"))


# ── users ──────────────────────────────────────────────────────────────────────

def get_user(user_id):
    res = sb.table("hx_users").select("*").eq("id", user_id).limit(1).execute()
    return res.data[0] if res.data else None

def get_user_by_github(github_id):
    res = sb.table("hx_users").select("*").eq("github_id", github_id).limit(1).execute()
    return res.data[0] if res.data else None

def upsert_user_github(github_id, username, github_token, avatar_url=None, email=None):
    # Try to find existing
    existing = get_user_by_github(github_id)
    if existing:
        res = sb.table("hx_users").update({
            "username": username,
            "github_token": github_token,
            "avatar_url": avatar_url,
            "email": email
        }).eq("id", existing["id"]).execute()
        return existing["id"]
    else:
        res = sb.table("hx_users").insert({
            "github_id": github_id,
            "username": username,
            "github_token": github_token,
            "avatar_url": avatar_url,
            "email": email,
            "password_hash": "github_oauth"
        }).execute()
        return res.data[0]["id"]


# ── repositories ──────────────────────────────────────────────────────────────

def upsert_repo(user_id, url, owner, repo_name, is_moderated=True):
    res = sb.table("hx_repositories").upsert(
        {"user_id": user_id, "url": url, "owner": owner, "repo_name": repo_name, "is_moderated": is_moderated, "scanned_at": "now()"},
        on_conflict="user_id,url"
    ).execute()
    return res.data[0]["id"]

def set_repo_moderation(repo_id, user_id, is_moderated):
    res = sb.table("hx_repositories").update({"is_moderated": is_moderated}).eq("id", repo_id).eq("user_id", user_id).execute()
    return res.data[0] if res.data else None

def get_repos(user_id):
    res = sb.table("hx_repositories").select("*").eq("user_id", user_id).order("scanned_at", desc=True).execute()
    return res.data

def get_repo_by_name(user_id, repo_name):
    res = sb.table("hx_repositories").select("*").eq("user_id", user_id).eq("repo_name", repo_name).limit(1).execute()
    return res.data[0] if res.data else None

def set_repo_ipfs_hash(repo_id, ipfs_hash, cert_pdf: bytes = None):
    data = {"ipfs_hash": ipfs_hash}
    sb.table("hx_repositories").update(data).eq("id", repo_id).execute()

def verify_certificate(cert_id: str):
    """Public lookup — finds a repo by its ipfs_hash (Certificate ID). No user auth needed."""
    res = sb.table("hx_repositories").select("id,owner,repo_name,scanned_at,ipfs_hash,url").eq("ipfs_hash", cert_id).limit(1).execute()
    return res.data[0] if res.data else None


def get_repo_report(repo_id, user_id):
    repo_res = sb.table("hx_repositories").select("*").eq("id", repo_id).eq("user_id", user_id).limit(1).execute()
    if not repo_res.data:
        return None, []
    results_res = sb.table("hx_scan_results").select("*").eq("repo_id", repo_id).order("risk_score", desc=True).execute()
    return repo_res.data[0], results_res.data


def get_repos_by_url(url):
    res = sb.table("hx_repositories").select("*").eq("url", url).execute()
    return res.data


# ── scan results ──────────────────────────────────────────────────────────────

def save_scan_results(repo_id, results):
    sb.table("hx_scan_results").delete().eq("repo_id", repo_id).execute()
    if results:
        rows = [{**r, "repo_id": repo_id} for r in results]
        sb.table("hx_scan_results").insert(rows).execute()


# ── cve cache ─────────────────────────────────────────────────────────────────

def upsert_cves(cves):
    if cves:
        sb.table("hx_cve_cache").upsert(cves, on_conflict="ghsa_id").execute()


def get_all_cves(severity=None):
    q = sb.table("hx_cve_cache").select("*").order("fetched_at", desc=True)
    if severity:
        q = q.eq("severity", severity.upper())
    return q.execute().data
