import os
from supabase import create_client
from dotenv import load_dotenv

load_dotenv()
sb = create_client(os.getenv("SUPABASE_URL"), os.getenv("SUPABASE_KEY"))


# ── users ──────────────────────────────────────────────────────────────────────

def get_user(username):
    res = sb.table("users").select("*").eq("username", username).limit(1).execute()
    return res.data[0] if res.data else None


def create_user(username, password_hash):
    res = sb.table("users").insert({"username": username, "password_hash": password_hash}).execute()
    return res.data[0]["id"]


# ── repositories ──────────────────────────────────────────────────────────────

def upsert_repo(user_id, url, owner, repo_name):
    res = sb.table("repositories").upsert(
        {"user_id": user_id, "url": url, "owner": owner, "repo_name": repo_name, "scanned_at": "now()"},
        on_conflict="user_id,url"
    ).execute()
    return res.data[0]["id"]


def get_repos(user_id):
    res = sb.table("repositories").select("*").eq("user_id", user_id).order("scanned_at", desc=True).execute()
    return res.data


def get_repo_report(repo_id, user_id):
    repo_res = sb.table("repositories").select("*").eq("id", repo_id).eq("user_id", user_id).limit(1).execute()
    if not repo_res.data:
        return None, []
    results_res = sb.table("scan_results").select("*").eq("repo_id", repo_id).order("risk_score", desc=True).execute()
    return repo_res.data[0], results_res.data


# ── scan results ──────────────────────────────────────────────────────────────

def save_scan_results(repo_id, results):
    sb.table("scan_results").delete().eq("repo_id", repo_id).execute()
    if results:
        rows = [{**r, "repo_id": repo_id} for r in results]
        sb.table("scan_results").insert(rows).execute()


# ── cve cache ─────────────────────────────────────────────────────────────────

def upsert_cves(cves):
    if cves:
        sb.table("cve_cache").upsert(cves, on_conflict="ghsa_id").execute()


def get_all_cves(severity=None):
    q = sb.table("cve_cache").select("*").order("fetched_at", desc=True)
    if severity:
        q = q.eq("severity", severity.upper())
    return q.execute().data
