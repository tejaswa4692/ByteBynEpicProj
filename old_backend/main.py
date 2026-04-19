import os
import jwt
import bcrypt
from datetime import datetime, timedelta, timezone
from fastapi import FastAPI, HTTPException, Header, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from dotenv import load_dotenv
from db import (create_user, get_user, upsert_repo, get_repos,
                get_repo_report, save_scan_results, upsert_cves, get_all_cves)
from scanner import scan_repo, fetch_github_advisories
from report_generator import generate_pdf_bytes
from mailer import send_report_email

load_dotenv()
SECRET = os.getenv("JWT_SECRET", "supersecret")

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

class AuthBody(BaseModel):
    username: str
    password: str


@app.post("/auth/register")
def register(body: AuthBody):
    if get_user(body.username):
        raise HTTPException(400, detail="Username already taken")
    hashed = bcrypt.hashpw(body.password.encode(), bcrypt.gensalt()).decode()
    uid = create_user(body.username, hashed)
    return {"token": make_token(uid, body.username), "username": body.username}


@app.post("/auth/login")
def login(body: AuthBody):
    user = get_user(body.username)
    if not user or not bcrypt.checkpw(body.password.encode(), user["password_hash"].encode()):
        raise HTTPException(401, detail="Invalid username or password")
    return {"token": make_token(user["id"], body.username), "username": body.username}


# ── scan ───────────────────────────────────────────────────────────────────────

class ScanRequest(BaseModel):
    repo_url: str


@app.post("/scan")
def scan(body: ScanRequest, user: dict = Depends(get_current_user)):
    try:
        results, owner, repo_name, dep_count = scan_repo(body.repo_url)
    except ValueError as e:
        raise HTTPException(400, detail=str(e))

    repo_id = upsert_repo(int(user["sub"]), body.repo_url, owner, repo_name)
    save_scan_results(repo_id, results)
    return {
        "repo_id": repo_id,
        "repo_url": body.repo_url,
        "dependencies_scanned": dep_count,
        "vulnerabilities_found": len(results),
        "results": results,
    }


# ── repos ──────────────────────────────────────────────────────────────────────

@app.get("/repos")
def list_repos(user: dict = Depends(get_current_user)):
    return get_repos(int(user["sub"]))


@app.get("/repos/{repo_id}/report")
def repo_report(repo_id: int, user: dict = Depends(get_current_user)):
    repo, results = get_repo_report(repo_id, int(user["sub"]))
    if not repo:
        raise HTTPException(404, detail="Repo not found")
    return {"repo": repo, "total_vulns": len(results), "vulnerabilities": results}


class EmailRequest(BaseModel):
    recipient_email: str

@app.post("/repos/{repo_id}/email")
def email_report(repo_id: int, body: EmailRequest, user: dict = Depends(get_current_user)):
    repo, results = get_repo_report(repo_id, int(user["sub"]))
    if not repo:
        raise HTTPException(404, detail="Repo not found")
    
    try:
        pdf_bytes = generate_pdf_bytes(repo["repo_name"], results)
        send_report_email(body.recipient_email, repo["repo_name"], pdf_bytes)
        return {"success": True, "message": f"Report securely sent to {body.recipient_email}"}
    except ValueError as e:
        raise HTTPException(400, detail=str(e))
    except Exception as e:
        raise HTTPException(500, detail=str(e))


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
