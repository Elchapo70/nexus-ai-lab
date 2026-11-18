"""Local-only, read-only security scanner API."""
import os
from pathlib import Path
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from .scanner import scan_directory

app = FastAPI(title="NEXUS AI LAB", version="0.1.0")
STATIC = Path(__file__).parent / "static"

class ScanRequest(BaseModel):
    project: str = Field(min_length=1, max_length=120, pattern=r"^[a-zA-Z0-9][a-zA-Z0-9._-]*$")

@app.get("/")
def home():
    return FileResponse(STATIC / "index.html")

@app.get("/health")
def health():
    return {"status": "ok", "version": "0.1.0"}

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
