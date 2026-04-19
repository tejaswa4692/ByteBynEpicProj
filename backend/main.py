import os
import jwt
import bcrypt
import hmac
import hashlib
from datetime import datetime, timedelta, timezone
from fastapi import FastAPI, HTTPException, Header, Depends, Request, BackgroundTasks, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from dotenv import load_dotenv
from db import (upsert_user_github, get_user, upsert_repo, get_repos,
                get_repo_report, save_scan_results, upsert_cves, get_all_cves, get_repos_by_url, set_repo_moderation, get_repo_by_name, set_repo_ipfs_hash, verify_certificate)
from scanner import scan_repo, fetch_github_advisories
import requests
import io

load_dotenv()
SECRET = os.getenv("JWT_SECRET", "supersecret")
GITHUB_WEBHOOK_SECRET = os.getenv("GITHUB_WEBHOOK_SECRET", "repodogg-auto-secret-123")
GITHUB_CLIENT_ID = os.getenv("GITHUB_CLIENT_ID", "")
GITHUB_CLIENT_SECRET = os.getenv("GITHUB_CLIENT_SECRET", "")
SMTP_EMAIL = os.getenv("SMTP_EMAIL", "")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")

import smtplib
from email.message import EmailMessage
from fpdf import FPDF

def generate_pdf_report(repo_name, vulns):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Helvetica", style="B", size=16)
    pdf.cell(200, 10, txt=f"RepodoGG Vulnerability Report: {repo_name}", ln=True, align='C')
    pdf.ln(10)
    
    crit_count = sum(1 for v in vulns if v["severity"] == "CRITICAL")
    high_count = sum(1 for v in vulns if v["severity"] == "HIGH")
    
    pdf.set_font("Helvetica", size=12)
    pdf.cell(200, 10, txt=f"Total Vulnerabilities: {len(vulns)} (Critical: {crit_count}, High: {high_count})", ln=True)
    pdf.ln(5)
    
    for v in sorted(vulns, key=lambda x: x["risk_score"], reverse=True):
        pdf.set_font("Helvetica", style="B", size=11)
        pdf.cell(200, 8, txt=f"Package: {v['package_name']} (v{v['installed_version']}) - {v.get('severity', 'UNKNOWN')}", ln=True)
        pdf.set_font("Helvetica", size=10)
        pdf.cell(200, 6, txt=f"Risk Score: {v.get('risk_score', 'N/A')} | Vuln ID: {v.get('vuln_id', 'N/A')}", ln=True)
        summary = (v.get('summary') or 'No summary').replace('\n', ' ')[:100] + '...'
        pdf.cell(200, 6, txt=f"Summary: {summary}", ln=True)
        pdf.ln(4)
        
    return pdf.output()

def send_alert_email(to_email, repo_name, vulns):
    if not SMTP_EMAIL or not SMTP_PASSWORD or not to_email:
        print(f"Skipping email alert for {repo_name} (Missing SMTP creds or user email)")
        return
        
    crit_count = sum(1 for v in vulns if v["severity"] == "CRITICAL")
    high_count = sum(1 for v in vulns if v["severity"] == "HIGH")
    
    msg = EmailMessage()
    msg['Subject'] = f"🚨 RepodoGG Alert: Vulnerabilities Found in {repo_name}"
    msg['From'] = SMTP_EMAIL
    msg['To'] = to_email
    
    content = f"Hello,\n\nRepodoGG has completed a deep scan of your repository '{repo_name}' and found {len(vulns)} vulnerabilities.\n\n"
    content += f"Critical: {crit_count}\nHigh: {high_count}\n\n"
    content += "Top Riskiest Dependencies:\n"
    
    for v in sorted(vulns, key=lambda x: x["risk_score"], reverse=True)[:5]:
        content += f"- {v['package_name']} ({v['installed_version']}) [Risk: {v['risk_score']}/10] - {v.get('severity', 'UNKNOWN')}\n"
        
    content += "\nPlease log into your RepodoGG Dashboard to view the full report and remediation steps.\n\nStay secure,\nRepodoGG System"
    msg.set_content(content)
    
    try:
        pdf_bytes = generate_pdf_report(repo_name, vulns)
        msg.add_attachment(pdf_bytes, maintype='application', subtype='pdf', filename=f'RepodoGG_Report_{repo_name}.pdf')
    except Exception as e:
        print(f"Failed to generate PDF attachment: {e}")
    
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
        
        # Auto-save repo to the database if it doesn't exist
        if not db_repo:
            new_id = upsert_repo(int(user["sub"]), gr["html_url"], gr["owner"]["login"], repo_name, is_moderated=False)
            db_repo = {"id": new_id, "is_moderated": False}
            db_repo_map[repo_name] = db_repo
            
        is_moderated = db_repo["is_moderated"]
        
        result.append({
            "id": db_repo["id"],
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
        db_user = get_user(user_id)
        
        # 1. Automatically Configure GitHub Webhook
        if db_user and db_user.get("github_token"):
            webhook_url = os.getenv("WEBHOOK_URL", "https://your-public-url.com/webhook/github")
            gh_headers = {
                "Authorization": f"Bearer {db_user['github_token']}",
                "Accept": "application/vnd.github.v3+json"
            }
            hook_payload = {
                "name": "web",
                "active": True,
                "events": ["push"],
                "config": {
                    "url": webhook_url,
                    "content_type": "json",
                    "secret": GITHUB_WEBHOOK_SECRET
                }
            }
            try:
                requests.post(
                    f"https://api.github.com/repos/{body.owner}/{body.repo_name}/hooks",
                    json=hook_payload,
                    headers=gh_headers,
                    timeout=5
                )
            except Exception as e:
                print(f"Failed to auto-configure webhook for {body.repo_name}: {e}")

        # 2. Trigger initial baseline scan
        def scan_and_alert():
            try:
                results, _, repo_name, _, _ = scan_repo(body.repo_url)
                save_scan_results(repo_id, results)
                if results and db_user and db_user.get("email"):
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

@app.post("/repos/{repo_id}/certify")
def certify_repo(repo_id: int, user: dict = Depends(get_current_user)):
    repo, results = get_repo_report(repo_id, int(user["sub"]))
    if not repo:
        raise HTTPException(404, detail="Repo not found")
    
    if len(results) > 0:
        raise HTTPException(400, detail="Repository must have 0 vulnerabilities to be certified.")
        
    if repo.get("ipfs_hash"):
        return {"ipfs_hash": repo["ipfs_hash"], "message": "Already certified."}
        
    # Generate the certificate PDF
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Helvetica", style="B", size=24)
    pdf.set_text_color(40, 40, 40)
    pdf.cell(200, 30, txt="REPODOGG SECURITY CERTIFICATE", ln=True, align='C')
    
    pdf.set_font("Helvetica", style="I", size=14)
    pdf.set_text_color(100, 100, 100)
    pdf.cell(200, 15, txt="This document certifies that the following repository", ln=True, align='C')
    
    pdf.set_font("Helvetica", style="B", size=20)
    pdf.set_text_color(79, 70, 229)
    pdf.cell(200, 20, txt=f"{repo.get('owner')}/{repo.get('repo_name')}", ln=True, align='C')
    
    pdf.set_font("Helvetica", size=14)
    pdf.set_text_color(40, 40, 40)
    pdf.cell(200, 15, txt="passed all vulnerability scans with ZERO detected threats.", ln=True, align='C')
    
    pdf.ln(10)
    pdf.set_font("Helvetica", size=12)
    timestamp = repo.get('scanned_at') or datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    pdf.cell(200, 10, txt=f"Certified Date: {timestamp}", ln=True, align='C')
    pdf.cell(200, 10, txt=f"Analyzed by: RepodoGG Automated AST Scanner", ln=True, align='C')
    pdf.ln(10)
    pdf.set_font("Helvetica", style="I", size=9)
    pdf.set_text_color(150, 150, 150)
    pdf.cell(200, 8, txt="This certificate is cryptographically sealed. The SHA-256 hash of this document", ln=True, align='C')
    pdf.cell(200, 8, txt="serves as an immutable proof of security compliance at the time of issuance.", ln=True, align='C')
    
    pdf_bytes = bytes(pdf.output())
    
    # Generate SHA-256 hash as the immutable certificate ID (like an IPFS CID)
    cert_hash = "hx-" + hashlib.sha256(pdf_bytes).hexdigest()
    
    # Try Pinata upload in background — if blocked, fall back to local cert_hash
    pinata_cid = None
    try:
        jwt_key = os.getenv("PINATA_JWT")
        api_key = os.getenv("PINATA_API_KEY")
        api_secret = os.getenv("PINATA_SECRET_API_KEY")
        if jwt_key:
            r = requests.post(
                "https://uploads.pinata.cloud/v3/files",
                headers={"Authorization": f"Bearer {jwt_key}"},
                files={"file": ("RepodoGG_Certificate.pdf", pdf_bytes, "application/pdf")},
                data={"name": f"RepodoGG_Cert_{repo.get('repo_name')}"},
                timeout=5
            )
            if r.ok:
                pinata_cid = r.json().get("data", {}).get("cid")
        if not pinata_cid and api_key and api_secret:
            r = requests.post(
                "https://api.pinata.cloud/pinning/pinFileToIPFS",
                headers={"pinata_api_key": api_key, "pinata_secret_api_key": api_secret},
                files={"file": ("RepodoGG_Certificate.pdf", pdf_bytes, "application/pdf")},
                timeout=5
            )
            if r.ok:
                pinata_cid = r.json().get("IpfsHash")
    except Exception as e:
        print(f"Pinata upload skipped (network restricted): {e}")
    
    # Use Pinata CID if available, otherwise use local hash
    final_hash = pinata_cid if pinata_cid else cert_hash
    
    set_repo_ipfs_hash(repo_id, final_hash, cert_pdf=pdf_bytes)
    return {
        "ipfs_hash": final_hash,
        "is_local": pinata_cid is None,
        "message": "Successfully certified." if pinata_cid else "Certified locally (IPFS upload unavailable on this network)."
    }

@app.get("/repos/{repo_id}/certificate.pdf")
def download_certificate(repo_id: int, token: str = None, authorization: str = Header(default=None)):
    from fastapi.responses import Response
    raw_token = token or (authorization.replace("Bearer ", "") if authorization else None)
    if not raw_token:
        raise HTTPException(401, detail="Not authenticated")
    try:
        payload = jwt.decode(raw_token, SECRET, algorithms=["HS256"])
        user_id = int(payload["sub"])
    except Exception:
        raise HTTPException(401, detail="Invalid token")
    repo, _ = get_repo_report(repo_id, user_id)
    if not repo:
        raise HTTPException(404, detail="Repo not found")
    cert_hash = repo.get('ipfs_hash', '')

    # Regenerate PDF on-the-fly — no DB blob column needed
    pdf = FPDF()
    # Embed cert ID in PDF metadata — always stored as plain text in raw bytes
    pdf.set_subject(f"CERT_ID:{cert_hash}")
    pdf.set_keywords(cert_hash)
    pdf.set_author("RepodoGG Automated AST Scanner")
    pdf.add_page()
    pdf.set_font("Helvetica", style="B", size=24)
    pdf.set_text_color(40, 40, 40)
    pdf.cell(200, 30, txt="REPODOGG SECURITY CERTIFICATE", ln=True, align='C')
    pdf.set_font("Helvetica", style="I", size=14)
    pdf.set_text_color(100, 100, 100)
    pdf.cell(200, 15, txt="This document certifies that the following repository", ln=True, align='C')
    pdf.set_font("Helvetica", style="B", size=20)
    pdf.set_text_color(79, 70, 229)
    pdf.cell(200, 20, txt=f"{repo.get('owner')}/{repo.get('repo_name')}", ln=True, align='C')
    pdf.set_font("Helvetica", size=14)
    pdf.set_text_color(40, 40, 40)
    pdf.cell(200, 15, txt="passed all vulnerability scans with ZERO detected threats.", ln=True, align='C')
    pdf.ln(10)
    pdf.set_font("Helvetica", size=12)
    timestamp = repo.get('scanned_at') or datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    pdf.cell(200, 10, txt=f"Certified Date: {timestamp}", ln=True, align='C')
    pdf.cell(200, 10, txt=f"Analyzed by: RepodoGG Automated AST Scanner", ln=True, align='C')
    pdf.ln(10)
    pdf.set_font("Helvetica", style="B", size=10)
    pdf.set_text_color(79, 70, 229)
    pdf.cell(200, 8, txt=f"Certificate ID:", ln=True, align='C')
    pdf.set_font("Helvetica", size=9)
    pdf.cell(200, 8, txt=cert_hash, ln=True, align='C')
    pdf.ln(5)
    pdf.set_font("Helvetica", style="I", size=9)
    pdf.set_text_color(150, 150, 150)
    pdf.cell(200, 8, txt="This certificate ID is an immutable cryptographic proof of security compliance.", ln=True, align='C')

    pdf_bytes = bytes(pdf.output())
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=RepodoGG_Cert_{repo.get('repo_name')}.pdf"}
    )


# ── public certificate verification ──────────────────────────────────────────

@app.get("/verify")
def verify_cert(cert_id: str):
    """Public endpoint — no auth required. Verifies a certificate ID against the database."""
    if not cert_id or len(cert_id) < 8:
        raise HTTPException(400, detail="Invalid certificate ID.")
    repo = verify_certificate(cert_id)
    if not repo:
        return {"valid": False, "message": "Certificate not found. This certificate may be invalid or was not issued by RepodoGG."}
    return {
        "valid": True,
        "owner": repo["owner"],
        "repo_name": repo["repo_name"],
        "repo_url": repo.get("url", f"https://github.com/{repo['owner']}/{repo['repo_name']}"),
        "certified_at": repo.get("scanned_at"),
        "cert_id": repo["ipfs_hash"],
        "message": f"✅ Verified! {repo['owner']}/{repo['repo_name']} passed zero-vulnerability audit."
    }

@app.post("/verify-pdf")
async def verify_pdf_upload(file: UploadFile):
    """Public endpoint — accepts a PDF upload, extracts Certificate ID from metadata, and verifies it."""
    import re
    raw = await file.read()
    text = raw.decode("latin-1", errors="ignore")
    
    # Try metadata fields first (most reliable — always plain text in PDF header)
    cert_id = None
    meta_match = re.search(r"CERT_ID:([A-Za-z0-9_\-]{10,})", text)
    if meta_match:
        cert_id = meta_match.group(1).strip()
    
    if not cert_id:
        # Try /Keywords field in PDF metadata
        kw_match = re.search(r"/Keywords\s*\(([A-Za-z0-9_\-]{10,})\)", text)
        if kw_match:
            cert_id = kw_match.group(1).strip()

    if not cert_id:
        # Fallback: scan all readable tokens of sufficient length
        tokens = re.findall(r"[A-Za-z0-9]{40,}", text)
        for t in tokens:
            if t.startswith("bafkrei") or t.startswith("hx"):
                cert_id = t
                break

    print(f"[verify-pdf] Extracted cert_id: {cert_id}")

    if not cert_id:
        return {"valid": False, "message": "Could not extract a Certificate ID from this PDF. Make sure it was issued by RepodoGG, or paste the ID manually."}
    
    repo = verify_certificate(cert_id)
    if not repo:
        return {"valid": False, "extracted_id": cert_id, "message": "Certificate ID found but not recognised. This certificate may be tampered or was not issued by RepodoGG."}
    return {
        "valid": True,
        "extracted_id": cert_id,
        "owner": repo["owner"],
        "repo_name": repo["repo_name"],
        "repo_url": repo.get("url", f"https://github.com/{repo['owner']}/{repo['repo_name']}"),
        "certified_at": repo.get("scanned_at"),
        "cert_id": repo["ipfs_hash"],
        "message": f"✅ Verified! {repo['owner']}/{repo['repo_name']} passed zero-vulnerability audit."
    }


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
