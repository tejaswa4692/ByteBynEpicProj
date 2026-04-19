import os
import jwt
import bcrypt
import hmac
import hashlib
from datetime import datetime, timedelta, timezone
from fastapi import FastAPI, HTTPException, Header, Depends, Request, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from dotenv import load_dotenv
from db import (upsert_user_github, get_user, upsert_repo, get_repos,
                get_repo_report, save_scan_results, upsert_cves, get_all_cves, get_repos_by_url, set_repo_moderation, get_repo_by_name)
from scanner import scan_repo, fetch_github_advisories
import requests

load_dotenv()
SECRET = os.getenv("JWT_SECRET", "supersecret")
GITHUB_WEBHOOK_SECRET = os.getenv("GITHUB_WEBHOOK_SECRET", "")
GITHUB_CLIENT_ID = os.getenv("GITHUB_CLIENT_ID", "")
GITHUB_CLIENT_SECRET = os.getenv("GITHUB_CLIENT_SECRET", "")
SMTP_EMAIL = os.getenv("SMTP_EMAIL", "")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")

import smtplib
from email.message import EmailMessage

def send_alert_email(to_email, repo_name, vulns):
    if not SMTP_EMAIL or not SMTP_PASSWORD or not to_email:
        print(f"Skipping email alert for {repo_name} (Missing SMTP creds or user email)")
        return
        
    crit_count = sum(1 for v in vulns if v["severity"] == "CRITICAL")
    high_count = sum(1 for v in vulns if v["severity"] == "HIGH")
    
    msg = EmailMessage()
    msg['Subject'] = f"🚨 HackHelix Alert: Vulnerabilities Found in {repo_name}"
    msg['From'] = SMTP_EMAIL
    msg['To'] = to_email
    
    content = f"Hello,\n\nHackHelix has completed a deep scan of your repository '{repo_name}' and found {len(vulns)} vulnerabilities.\n\n"
    content += f"Critical: {crit_count}\nHigh: {high_count}\n\n"
    content += "Top Riskiest Dependencies:\n"
    
    for v in sorted(vulns, key=lambda x: x["risk_score"], reverse=True)[:5]:
        content += f"- {v['package_name']} ({v['installed_version']}) [Risk: {v['risk_score']}/10] - {v.get('severity', 'UNKNOWN')}\n"
        
    content += "\nPlease log into your HackHelix Dashboard to view the full report and remediation steps.\n\nStay secure,\nHackHelix System"
    msg.set_content(content)
    
    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(SMTP_EMAIL, SMTP_PASSWORD)
            server.send_message(msg)
            print(f"✅ Successfully sent alert email to {to_email} for {repo_name}")
    except Exception as e:
        print(f"❌ Failed to send email: {e}")

app = FastAPI(title="CVE Dependency Mapper")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])


# ── auth helpers ───────────────────────────────────────────────────────────────

def make_token(user_id, username):
    payload = {
        "sub": str(user_id),
        "username": username,
        "exp": datetime.now(timezone.utc) + timedelta(days=7),
    }
    return jwt.encode(payload, SECRET, algorithm="HS256")


def get_current_user(authorization: str = Header()):
    try:
        token = authorization.replace("Bearer ", "")
        return jwt.decode(token, SECRET, algorithms=["HS256"])
    except Exception:
        raise HTTPException(401, detail="Invalid or expired token")


# ── auth routes ────────────────────────────────────────────────────────────────

class GitHubAuthBody(BaseModel):
    code: str

@app.post("/auth/github")
def github_login(body: GitHubAuthBody):
    if not GITHUB_CLIENT_ID or not GITHUB_CLIENT_SECRET:
        raise HTTPException(500, detail="GitHub OAuth not configured on server")
        
    token_url = "https://github.com/login/oauth/access_token"
    headers = {"Accept": "application/json"}
    data = {
        "client_id": GITHUB_CLIENT_ID,
        "client_secret": GITHUB_CLIENT_SECRET,
        "code": body.code
    }
    r = requests.post(token_url, headers=headers, data=data)
    if r.status_code != 200 or "access_token" not in r.json():
        raise HTTPException(400, detail="Invalid GitHub code")
    
    access_token = r.json()["access_token"]
    
    user_url = "https://api.github.com/user"
    user_r = requests.get(user_url, headers={"Authorization": f"Bearer {access_token}"})
    if user_r.status_code != 200:
        raise HTTPException(400, detail="Failed to fetch GitHub user")
    
    user_data = user_r.json()
    github_id = user_data["id"]
    username = user_data["login"]
    avatar_url = user_data.get("avatar_url", "")
    
    email = user_data.get("email")
    if not email:
        emails_r = requests.get("https://api.github.com/user/emails", headers={"Authorization": f"Bearer {access_token}"})
        if emails_r.status_code == 200:
            for e in emails_r.json():
                if e.get("primary") and e.get("verified"):
                    email = e.get("email")
                    break
    
    uid = upsert_user_github(github_id, username, access_token, avatar_url, email)
    return {"token": make_token(uid, username), "username": username, "avatar_url": avatar_url}


# ── scan ───────────────────────────────────────────────────────────────────────

class ScanRequest(BaseModel):
    repo_url: str


@app.post("/scan")
def scan(body: ScanRequest, user: dict = Depends(get_current_user)):
    try:
        results, owner, repo_name, dep_count, manifests = scan_repo(body.repo_url)
    except ValueError as e:
        raise HTTPException(400, detail=str(e))

    repo_id = upsert_repo(int(user["sub"]), body.repo_url, owner, repo_name)
    try:
        save_scan_results(repo_id, results)
    except Exception as e:
        err_str = str(e)
        if 'source_manifest' in err_str or 'PGRST204' in err_str:
            raise HTTPException(500, detail="Database schema out of date! Please go to Supabase SQL editor and run the 'alter table' commands from setup.sql (including source_manifest). Then run 'NOTIFY pgrst, reload_schema;'.")
        raise HTTPException(500, detail=f"Database error during save: {err_str}")
    return {
        "repo_id": repo_id,
        "repo_url": body.repo_url,
        "dependencies_scanned": dep_count,
        "vulnerabilities_found": len(results),
        "manifests": manifests,
        "results": results,
    }


# ── repos ──────────────────────────────────────────────────────────────────────

@app.get("/repos")
def list_repos(user: dict = Depends(get_current_user)):
    return get_repos(int(user["sub"]))

@app.get("/github/repos")
def list_github_repos(user: dict = Depends(get_current_user)):
    db_user = get_user(int(user["sub"]))
    if not db_user:
        raise HTTPException(404, detail="User not found")
        
    access_token = db_user.get("github_token")
    if not access_token:
        raise HTTPException(400, detail="No GitHub token found for user")
        
    r = requests.get("https://api.github.com/user/repos?per_page=100&sort=updated", 
                     headers={"Authorization": f"Bearer {access_token}", "Accept": "application/vnd.github.v3+json"})
    if r.status_code != 200:
        raise HTTPException(400, detail="Failed to fetch repos from GitHub")
        
    gh_repos = r.json()
    db_repos = get_repos(int(user["sub"]))
    db_repo_map = {repo["repo_name"]: repo for repo in db_repos}
    
    result = []
    for gr in gh_repos:
        repo_name = gr["name"]
        db_repo = db_repo_map.get(repo_name)
        is_moderated = db_repo["is_moderated"] if db_repo else False
        
        result.append({
            "id": db_repo["id"] if db_repo else None,
            "github_id": gr["id"],
            "repo_name": repo_name,
            "full_name": gr["full_name"],
            "owner": gr["owner"]["login"],
            "url": gr["html_url"],
            "is_moderated": is_moderated,
            "updated_at": gr["updated_at"],
            "language": gr.get("language")
        })
    return result

class ModerateRequest(BaseModel):
    is_moderated: bool
    repo_url: str
    owner: str
    repo_name: str

@app.post("/repos/moderate")
def moderate_repo(body: ModerateRequest, background_tasks: BackgroundTasks, user: dict = Depends(get_current_user)):
    user_id = int(user["sub"])
    repo_id = upsert_repo(user_id, body.repo_url, body.owner, body.repo_name, is_moderated=body.is_moderated)
    
    if body.is_moderated:
        def scan_and_alert():
            try:
                results, _, repo_name, _, _ = scan_repo(body.repo_url)
                save_scan_results(repo_id, results)
                if results:
                    db_user = get_user(user_id)
                    if db_user and db_user.get("email"):
                        send_alert_email(db_user["email"], repo_name, results)
            except Exception as e:
                print(f"Failed initial scan for {body.repo_url}: {e}")
        
        background_tasks.add_task(scan_and_alert)
            
    return {"repo_id": repo_id, "is_moderated": body.is_moderated}


@app.get("/repos/{repo_id}/report")
def repo_report(repo_id: int, user: dict = Depends(get_current_user)):
    repo, results = get_repo_report(repo_id, int(user["sub"]))
    if not repo:
        raise HTTPException(404, detail="Repo not found")
    return {"repo": repo, "total_vulns": len(results), "vulnerabilities": results}


# ── cves ───────────────────────────────────────────────────────────────────────

@app.post("/cves/refresh")
def refresh_cves(user: dict = Depends(get_current_user)):
    try:
        cves = fetch_github_advisories()
    except ValueError as e:
        raise HTTPException(400, detail=str(e))
    upsert_cves(cves)
    return {"fetched": len(cves)}


@app.get("/cves")
def list_cves(severity: str = None, user: dict = Depends(get_current_user)):
    return get_all_cves(severity)


# ── webhooks ───────────────────────────────────────────────────────────────────

def background_scan_repo(repo_url: str):
    # Find all users tracking this repo
    repos = get_repos_by_url(repo_url)
    if not repos:
        return

    # Perform the scan once
    try:
        results, _, repo_name, _, _ = scan_repo(repo_url)
    except Exception as e:
        print(f"Background scan failed for {repo_url}: {e}")
        return

    # Save results for all tracking instances and send emails
    emailed_users = set()
    for repo in repos:
        save_scan_results(repo["id"], results)
        if results and repo["user_id"] not in emailed_users:
            user = get_user(repo["user_id"])
            if user and user.get("email"):
                send_alert_email(user["email"], repo_name, results)
                emailed_users.add(repo["user_id"])

@app.post("/webhook/github")
async def github_webhook(request: Request, background_tasks: BackgroundTasks):
    if not GITHUB_WEBHOOK_SECRET:
        raise HTTPException(500, detail="Webhook secret not configured")

    signature = request.headers.get("x-hub-signature-256")
    if not signature:
        raise HTTPException(401, detail="Missing signature")

    # Read the raw body
    body = await request.body()
    
    # Verify the signature
    mac = hmac.new(GITHUB_WEBHOOK_SECRET.encode(), msg=body, digestmod=hashlib.sha256)
    expected_signature = "sha256=" + mac.hexdigest()
    if not hmac.compare_digest(expected_signature, signature):
        raise HTTPException(401, detail="Invalid signature")

    # Parse JSON payload
    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(400, detail="Invalid JSON payload")

    event = request.headers.get("x-github-event")
    
    if event == "push":
        repo_url = payload.get("repository", {}).get("html_url")
        if repo_url:
            background_tasks.add_task(background_scan_repo, repo_url)
            
    # Return 202 immediately to let GitHub know we received it
    return {"status": "accepted"}
