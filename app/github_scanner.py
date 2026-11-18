"""Read-only scan of small public GitHub repositories via official API."""
import base64
import json
import re
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError
from fastapi import HTTPException
from .scanner import RULES, EXTENSIONS

REPO_RE = re.compile(r"^(?:https://github\.com/)?([A-Za-z0-9-]{1,39})/([A-Za-z0-9_.-]{1,100})(?:\.git)?/?$")
MAX_FILES = 30
MAX_BYTES = 120_000

def github_json(path):
    req = Request("https://api.github.com/" + path, headers={"Accept": "application/vnd.github+json", "User-Agent": "NexusAILab/0.2"})
    try:
        with urlopen(req, timeout=12) as response:
            return json.load(response)
    except HTTPError as error:
        if error.code == 404:
            raise HTTPException(404, "Repositorio público no encontrado") from error
        if error.code in (403, 429):
            raise HTTPException(429, "Límite de GitHub alcanzado; intenta más tarde") from error
        raise HTTPException(502, "Error de la API de GitHub") from error
    except (URLError, TimeoutError, ValueError) as error:
        raise HTTPException(502, "GitHub no está disponible") from error

def scan_github(repo):
    match = REPO_RE.fullmatch(repo.strip())
    if not match:
        raise HTTPException(422, "Usa owner/repo o https://github.com/owner/repo")
    owner, name = match.groups()
    metadata = github_json(f"repos/{owner}/{name}")
    if metadata.get("private"):
        raise HTTPException(403, "Solo se permiten repositorios públicos")
    branch = metadata.get("default_branch", "main")
    tree = github_json(f"repos/{owner}/{name}/git/trees/{branch}?recursive=1")
    candidates = [entry for entry in tree.get("tree", []) if entry.get("type") == "blob" and entry.get("size", MAX_BYTES + 1) <= MAX_BYTES and "." + entry["path"].rsplit(".", 1)[-1].lower() in EXTENSIONS]
    findings = []
    inspected = 0
    for entry in candidates[:MAX_FILES]:
        blob = github_json(f"repos/{owner}/{name}/git/blobs/{entry['sha']}")
        if blob.get("encoding") != "base64":
            continue
        try:
            content = base64.b64decode(blob["content"]).decode("utf-8")
        except (ValueError, UnicodeError, KeyError):
            continue
        inspected += 1
        for line_no, line in enumerate(content.splitlines(), 1):
            for code, severity, pattern, recommendation in RULES:
                if pattern.search(line):
                    findings.append({"rule": code, "severity": severity, "file": entry["path"], "line": line_no, "recommendation": recommendation})
    return {"project": f"{owner}/{name}", "files_scanned": inspected, "findings": findings, "findings_count": len(findings), "partial": bool(tree.get("truncated")) or len(candidates) > MAX_FILES, "source": "github-public"}
