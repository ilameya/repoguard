from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Any

@dataclass
class Finding:
    severity: str             
    category: str              
    title: str
    evidence: str
    file: str | None = None
    line: int | None = None
    recommendation: str | None = None
    points: int = 0

def severity_rank(sev: str) -> int:
    order = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
    return order.get(sev.upper(), 0)

def score_findings(findings: list[Finding]) -> dict[str, Any]:
    score = 0
    for f in findings:
        score += int(f.points or 0)
    score = max(0, min(100, score))

    if score >= 80:
        level = "CRITICAL"
    elif score >= 50:
        level = "HIGH"
    elif score >= 20:
        level = "MEDIUM"
    else:
        level = "LOW"

    return {"score": score, "level": level}

def to_json(meta: dict[str, Any], findings: list[Finding]) -> dict[str, Any]:
    s = score_findings(findings)
    return {
        "meta": meta,
        "summary": s,
        "findings": [asdict(f) for f in sorted(findings, key=lambda x: (-severity_rank(x.severity), -x.points))],
    }
