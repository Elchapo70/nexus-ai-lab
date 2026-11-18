from pathlib import Path
from fastapi.testclient import TestClient
from app.main import app
from app.scanner import scan_directory

def test_detects_debug(tmp_path: Path):
    (tmp_path / "sample.py").write_text("DEBUG = True\n")
    report = scan_directory(tmp_path)
    assert any(f["rule"] == "DEBUG_TRUE" for f in report["findings"])

def test_ignores_symlinks(tmp_path: Path):
    outside = tmp_path.parent / "outside.py"
    outside.write_text("DEBUG = True")
    (tmp_path / "linked.py").symlink_to(outside)
    assert scan_directory(tmp_path)["findings_count"] == 0

def test_health():
    assert TestClient(app).get("/health").json()["status"] == "ok"

def test_missing_project(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("NEXUS_PROJECTS_DIR", str(tmp_path))
    assert TestClient(app).post("/api/scan", json={"project":"missing"}).status_code == 404
