"""Bounded, read-only multi-agent security review.

No external model calls, shell execution, repository modification, or billing.
"""
from collections import Counter
from pydantic import BaseModel, Field
from .advisor import ADVICE

MAX_FINDINGS = 100

class AgentRequest(BaseModel):
    project: str = Field(min_length=1, max_length=200)
    files_scanned: int = Field(ge=0, le=1500)
    findings: list[dict] = Field(max_length=MAX_FINDINGS)
    partial: bool = False

def run_agents(request: AgentRequest):
    findings = []
    for item in request.findings:
        if not isinstance(item, dict):
            continue
        rule = item.get("rule")
        if rule not in ADVICE:
            continue
        severity = str(item.get("severity", "medium"))
        if severity not in ("critical", "high", "medium", "low"):
            severity = "medium"
        findings.append({"rule": rule, "severity": severity,
                         "file": str(item.get("file", ""))[:200],
                         "line": item.get("line") if isinstance(item.get("line"), int) else None})
    # Agent 1: evidence triage
    counts = Counter(f["severity"] for f in findings)
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    ranked = sorted(findings, key=lambda f: order[f["severity"]])
    triage = {"agent": "Triage Agent", "status": "complete",
              "severity_counts": {s: counts[s] for s in order},
              "priority": ranked[:10]}
    # Agent 2: remediation planning (non-executing)
    seen = set()
    tasks = []
    for f in ranked:
        if f["rule"] in seen:
            continue
        seen.add(f["rule"])
        title, reason, fix = ADVICE[f["rule"]]
        tasks.append({"rule": f["rule"], "title": title,
                      "why": reason, "recommended_action": fix,
                      "requires_human_review": True})
    remediation = {"agent": "Remediation Agent", "status": "complete", "tasks": tasks}
    # Agent 3: quality and scope guard
    quality = {"agent": "Quality Agent", "status": "complete",
               "notes": ["Detección heurística; no confirma explotación.",
                         "No se ejecutó ni modificó código.",
                         "El análisis puede omitir vulnerabilidades."] +
                        (["Análisis parcial: no se revisaron todos los archivos."] if request.partial else [])}
    return {"project": request.project, "mode": "deterministic-multi-agent",
            "llm_enabled": False, "agents": [triage, remediation, quality],
            "summary": {"files_scanned": request.files_scanned, "findings_reviewed": len(findings)},
            "disclaimer": "Agentes basados en reglas; no utilizan todavía un modelo de IA generativa."}
