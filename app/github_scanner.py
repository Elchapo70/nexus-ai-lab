"""Read-only scan of small public GitHub repositories via official API."""
import base64
import json
import os
import re
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError
from fastapi import HTTPException
from .scanner import RULES, EXTENSIONS
import ast

REPO_RE = re.compile(r"^(?:https://github\.com/)?([A-Za-z0-9-]{1,39})/([A-Za-z0-9_.-]{1,100})(?:\.git)?/?$")
MAX_FILES = 15
MAX_BYTES = 120_000
SKIP_DIRS = {"tests", "test", "examples", "docs", "fixtures", "node_modules", "vendor", ".github", "__pycache__"}
SKIP_PREFIXES = ("test_", "mock_", "fixture_")

def production_candidate(path):
    parts = path.lower().split("/")
    return not any(part in SKIP_DIRS for part in parts[:-1]) and not parts[-1].startswith(SKIP_PREFIXES)

def python_findings(content, path):
    """Use AST to avoid matching rule names in strings, comments and documentation."""
    try:
        tree = ast.parse(content)
    except SyntaxError:
        return []
    results = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "eval":
            results.append({"rule": "EVAL", "severity": "medium", "file": path, "line": node.lineno, "recommendation": "Avoid eval on untrusted input."})
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if any(isinstance(t, ast.Name) and t.id == "DEBUG" for t in targets) and isinstance(node.value, ast.Constant) and node.value.value is True:
                results.append({"rule": "DEBUG_TRUE", "severity": "medium", "file": path, "line": node.lineno, "recommendation": "Disable debug mode in production."})
    return results


def github_json(path):
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "NexusAILab/0.3"}
    token = os.getenv("GITHUB_TOKEN", "").strip()
    if token:
        headers["Authorization"] = "Bearer " + token
    req = Request("https://api.github.com/" + path, headers=headers)
    try:
        with urlopen(req, timeout=12) as response:
            return json.load(response)
    except HTTPError as error:
        if error.code == 404:
            raise HTTPException(404, "Repositorio público no encontrado") from error
        if error.code in (403, 429):
            remaining = error.headers.get("X-RateLimit-Remaining")
            if error.code == 429 or remaining == "0":
                raise HTTPException(429, "Se agotó el límite de GitHub. Configura GITHUB_TOKEN en Render o espera al reinicio del límite.") from error
            raise HTTPException(403, "GitHub rechazó el acceso. Comprueba los permisos y el token del servidor.") from error
        if error.code == 401:
            raise HTTPException(502, "El token de GitHub del servidor no es válido.") from error
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
    candidates = [entry for entry in tree.get("tree", []) if entry.get("type") == "blob" and entry.get("size", MAX_BYTES + 1) <= MAX_BYTES and "." + entry["path"].rsplit(".", 1)[-1].lower() in EXTENSIONS and production_candidate(entry["path"])]
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
        if entry["path"].lower().endswith(".py"):
            findings.extend(python_findings(content, entry["path"]))
            continue
        for line_no, line in enumerate(content.splitlines(), 1):
            for code, severity, pattern, recommendation in RULES:
                if code in {"EVAL", "DEBUG_TRUE"}:
                    continue
                if pattern.search(line):
                    findings.append({"rule": code, "severity": severity, "file": entry["path"], "line": line_no, "recommendation": recommendation})
    return {"project": f"{owner}/{name}", "files_scanned": inspected, "findings": findings, "findings_count": len(findings), "partial": bool(tree.get("truncated")) or len(candidates) > MAX_FILES, "source": "github-public", "scope": "production-files", "excluded": "tests/examples/docs/fixtures", "scan_limit": MAX_FILES}
