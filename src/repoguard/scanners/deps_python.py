from __future__ import annotations
import json
import shutil
import subprocess
from pathlib import Path
from repoguard.report import Finding

def scan_python_deps(root: Path) -> list[Finding]:
    req = root / "requirements.txt"
    if not req.exists() or req.stat().st_size == 0:
        return []

    if shutil.which("pip-audit") is None:
        return [Finding(
            severity="LOW",
            category="deps",
            title="pip-audit not installed (dependency CVE scan skipped)",
            evidence="requirements.txt detected but pip-audit not found in PATH",
            recommendation="Install pip-audit (pip install pip-audit) to enable vulnerability scanning.",
            points=5,
        )]

    cmd = ["pip-audit", "-f", "json", "-r", str(req)]

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)

        if proc.returncode != 0:
            return [Finding(
                severity="LOW",
                category="deps",
                title="pip-audit failed to analyze requirements.txt",
                evidence=(proc.stderr or proc.stdout or "pip-audit exited non-zero").strip(),
                recommendation="Run pip-audit manually on requirements.txt to debug.",
                points=5,
            )]

        raw = (proc.stdout or "").strip()
        if not raw:
            return []

        data = json.loads(raw)
        entries = data if isinstance(data, list) else data.get("dependencies", [])
        if not isinstance(entries, list):
            return []

        findings: list[Finding] = []
        for e in entries:
            if not isinstance(e, dict):
                continue
            vulns = e.get("vulns") or e.get("vulnerabilities") or []
            if not vulns:
                continue

            pkg = e.get("name") or e.get("package") or "unknown"
            ver = e.get("version") or e.get("installed_version") or "?"

            for v in vulns:
                if not isinstance(v, dict):
                    continue
                vid = v.get("id") or v.get("cve") or v.get("advisory") or "ADVISORY"
                fix = v.get("fix_versions") or v.get("fixed_in") or []
                fix_str = ", ".join(fix) if isinstance(fix, list) else str(fix)

                findings.append(Finding(
                    severity="HIGH",
                    category="deps",
                    title=f"Vulnerable dependency: {pkg}=={ver}",
                    evidence=f"{vid} (fixed: {fix_str or 'unknown'})",
                    recommendation="Upgrade to a fixed version and regenerate lockfiles.",
                    points=20,
                ))

        return findings

    except subprocess.TimeoutExpired:
        return [Finding(
            severity="LOW",
            category="deps",
            title="pip-audit timed out",
            evidence="pip-audit exceeded 60 seconds",
            recommendation="Try auditing a smaller dependency set or run pip-audit manually.",
            points=5,
        )]

    except Exception as ex:
        return [Finding(
            severity="LOW",
            category="deps",
            title="pip-audit exception",
            evidence=str(ex),
            recommendation="Run pip-audit manually to debug.",
            points=5,
        )]
