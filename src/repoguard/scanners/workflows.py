from __future__ import annotations
import re
from pathlib import Path
import yaml
from repoguard.report import Finding
from repoguard.utils import safe_read_text

def scan_workflows(root: Path, max_bytes: int) -> list[Finding]:
    findings: list[Finding] = []
    wf_dir = root / ".github" / "workflows"
    if not wf_dir.exists():
        return findings

    for wf in wf_dir.glob("*.yml"):
        findings.extend(_scan_workflow_file(root, wf, max_bytes))
    for wf in wf_dir.glob("*.yaml"):
        findings.extend(_scan_workflow_file(root, wf, max_bytes))

    return findings

def _scan_workflow_file(root: Path, wf: Path, max_bytes: int) -> list[Finding]:
    rel = str(wf.relative_to(root))
    findings: list[Finding] = []

    raw = safe_read_text(wf, max_bytes=max_bytes)
    if raw is None:
        return findings

    if "pull_request_target" in raw:
        findings.append(Finding(
            severity="HIGH",
            category="workflows",
            title="Workflow uses pull_request_target",
            evidence=f"{rel} contains 'pull_request_target'",
            file=rel,
            recommendation="Be careful: pull_request_target runs in the context of the base repo and can expose secrets if misused.",
            points=20,
        ))

    if re.search(r"curl.+\|\s*(bash|sh)", raw):
        findings.append(Finding(
            severity="HIGH",
            category="workflows",
            title="Potential curl|bash in workflow",
            evidence=f"{rel} appears to pipe downloaded script into a shell",
            file=rel,
            recommendation="Avoid executing remote scripts directly. Pin checksums or vendor scripts.",
            points=20,
        ))

    try:
        doc = yaml.safe_load(raw) or {}
    except Exception:
        findings.append(Finding(
            severity="MEDIUM",
            category="workflows",
            title="Workflow YAML could not be parsed",
            evidence=f"Failed to parse {rel}",
            file=rel,
            recommendation="Invalid YAML reduces auditability and can hide risky behavior.",
            points=10,
        ))
        return findings

    perms = doc.get("permissions")
    if isinstance(perms, str) and perms.lower() == "write-all":
        findings.append(Finding(
            severity="HIGH",
            category="workflows",
            title="Workflow permissions: write-all",
            evidence=f"{rel} sets permissions: write-all",
            file=rel,
            recommendation="Use least privilege: explicitly set minimal permissions needed.",
            points=20,
        ))

    jobs = doc.get("jobs", {})
    if isinstance(jobs, dict):
        for job_name, job in jobs.items():
            steps = (job or {}).get("steps", [])
            if not isinstance(steps, list):
                continue
            for step in steps:
                if not isinstance(step, dict):
                    continue
                uses = step.get("uses")
                if isinstance(uses, str):
                    # unpinned if not @<40-hex-sha>
                    if "@" in uses:
                        ref = uses.split("@", 1)[1]
                        if not re.fullmatch(r"[0-9a-fA-F]{40}", ref):
                            findings.append(Finding(
                                severity="MEDIUM",
                                category="workflows",
                                title="Action not pinned to a commit SHA",
                                evidence=f"{rel} job '{job_name}' uses '{uses}'",
                                file=rel,
                                recommendation="Pin actions to a full commit SHA to reduce supply-chain risk.",
                                points=10,
                            ))
                    else:
                        findings.append(Finding(
                            severity="MEDIUM",
                            category="workflows",
                            title="Action reference missing @ref",
                            evidence=f"{rel} job '{job_name}' uses '{uses}' without explicit ref",
                            file=rel,
                            recommendation="Use @<sha> or at least a version tag. SHA pinning is best.",
                            points=10,
                        ))

    return findings
