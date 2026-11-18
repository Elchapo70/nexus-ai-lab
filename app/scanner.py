"""Read-only, bounded heuristic scanner."""
from pathlib import Path
import re

RULES = [
    ("PRIVATE_KEY", "critical", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"), "Remove private keys and rotate credentials."),
    ("AWS_KEY", "high", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"), "Revoke exposed key and use secret storage."),
    ("HARDCODED_SECRET", "high", re.compile(r"(?i)\b(?:password|api_key|secret_key|token)\s*=\s*['\"][^'\"]{8,}['\"]"), "Use environment variables or a secret manager."),
    ("DEBUG_TRUE", "medium", re.compile(r"\bDEBUG\s*=\s*True\b"), "Disable debug mode in production."),
    ("EVAL", "medium", re.compile(r"\beval\s*\("), "Avoid eval on untrusted input."),
]
EXTENSIONS = {".py", ".js", ".ts", ".jsx", ".tsx", ".json", ".yaml", ".yml", ".env", ".txt", ".toml"}
MAX_FILES = 1500
MAX_SIZE = 512_000

def scan_directory(root: Path):
    findings = []
    inspected = 0
    for path in sorted(root.rglob("*")):
        if inspected >= MAX_FILES:
            break
        if path.is_symlink() or not path.is_file() or path.suffix.lower() not in EXTENSIONS:
            continue
        try:
            if path.stat().st_size > MAX_SIZE:
                continue
            content = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            continue
        inspected += 1
        for number, line in enumerate(content.splitlines(), 1):
            for code, severity, pattern, recommendation in RULES:
                if pattern.search(line):
                    findings.append({"rule": code, "severity": severity, "file": str(path.relative_to(root)), "line": number, "recommendation": recommendation})
    return {"project": root.name, "files_scanned": inspected, "findings": findings, "findings_count": len(findings)}
