"""Local-only, read-only security scanner API."""
import os
from pathlib import Path
from fastapi import FastAPI, HTTPException, Header
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from .scanner import scan_directory
from .github_scanner import scan_github
from .advisor import ExplainRequest, explain
from .agents import AgentRequest, run_agents
from .llm import AIRequest, ai_enabled, review_with_model

app = FastAPI(title="NEXUS AI LAB", version="0.3.0")
STATIC = Path(__file__).parent / "static"

class ScanRequest(BaseModel):
    project: str = Field(min_length=1, max_length=120, pattern=r"^[a-zA-Z0-9][a-zA-Z0-9._-]*$")

class GitHubScanRequest(BaseModel):
    repository: str = Field(min_length=3, max_length=250)

@app.post("/api/scan/github")
def scan_public_github(request: GitHubScanRequest):
    return scan_github(request.repository)

@app.post("/api/explain")
def explain_finding(request: ExplainRequest):
    return explain(request.rule)

@app.post("/api/agents/review")
def agent_review(request: AgentRequest):
    return run_agents(request)

@app.get("/api/agents/status")
def agent_status():
    return {"agents": ["Triage Agent", "Remediation Agent", "Quality Agent"],
            "mode": "deterministic", "generative_ai_enabled": ai_enabled()}

@app.post("/api/agents/ai-review")
def generative_review(request: AIRequest, x_nexus_admin_token: str | None = Header(default=None)):
    return review_with_model(request, x_nexus_admin_token)

@app.get("/")
def home():
    return FileResponse(STATIC / "index.html")

@app.get("/health")
def health():
    return {"status": "ok", "version": "0.3.0"}

@app.get("/api/projects")
def projects():
    base = Path(os.environ.get("NEXUS_PROJECTS_DIR", "/projects")).resolve()
    if not base.is_dir():
        return {"projects": []}
    return {"projects": sorted(p.name for p in base.iterdir() if p.is_dir() and not p.is_symlink() and p.resolve().parent == base)}

@app.post("/api/scan")
def scan(request: ScanRequest):
    base = Path(os.environ.get("NEXUS_PROJECTS_DIR", "/projects")).resolve()
    target = (base / request.project).resolve()
    if target.parent != base or not target.is_dir() or (base / request.project).is_symlink():
        raise HTTPException(status_code=404, detail="Project not found")
    return scan_directory(target)
