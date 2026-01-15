from __future__ import annotations
import argparse
import json
import tempfile
from pathlib import Path
from rich.console import Console
from rich.table import Table
from repoguard.github import fetch_repo_meta, download_repo_zip
from repoguard.report import Finding, score_findings, to_json
from repoguard.scanners.secrets import scan_secrets
from repoguard.scanners.workflows import scan_workflows
from repoguard.scanners.deps_python import scan_python_deps
from repoguard.utils import normalize_repo_ref

console = Console()

def _print_report(meta: dict, findings: list[Finding]) -> None:
    summary = score_findings(findings)

    console.print(f"[bold]Repo:[/bold] {meta['repo']}  [bold]Branch:[/bold] {meta['branch']}")
    console.print(f"[bold]Score:[/bold] {summary['score']}  [bold]Level:[/bold] {summary['level']}\n")

    if not findings:
        console.print("[green]No findings.[/green]")
        return

    t = Table(title="Findings")
    t.add_column("Severity", style="bold")
    t.add_column("Category")
    t.add_column("Title")
    t.add_column("File")
    t.add_column("Evidence")
    t.add_column("Points", justify="right")
 

    for f in sorted(findings, key=lambda x: (x.severity, x.points), reverse=True):
        t.add_row(
         f.severity,
         f.category,
         f.title,
         f.file or "-",
         (f.evidence[:120] + "…") if f.evidence and len(f.evidence) > 120 else (f.evidence or "-"),
         str(f.points),
        )

    console.print(t)

def scan(repo_ref: str, json_path: str | None, max_files: int, max_bytes: int) -> int:
    owner_repo = normalize_repo_ref(repo_ref)
    owner, repo = owner_repo.split("/", 1)

    meta = fetch_repo_meta(owner, repo)
    branch = meta.default_branch

    with tempfile.TemporaryDirectory(prefix="repoguard_") as td:
        tmp = Path(td)
        root = download_repo_zip(owner, repo, branch, tmp)

        findings: list[Finding] = []
        findings += scan_secrets(root, max_files=max_files, max_bytes=max_bytes)
        findings += scan_workflows(root, max_bytes=max_bytes)
        findings += scan_python_deps(root)

        meta_dict = {
            "repo": owner_repo,
            "url": meta.html_url,
            "branch": branch,
            "updated_at": meta.updated_at,
        }

        _print_report(meta_dict, findings)

        if json_path:
            out = to_json(meta_dict, findings)
            Path(json_path).write_text(json.dumps(out, indent=2), encoding="utf-8")
            console.print(f"\n[bold]JSON saved:[/bold] {json_path}")

        summary = score_findings(findings)
        return 2 if summary["level"] in {"HIGH", "CRITICAL"} else 0

def main() -> None:
    p = argparse.ArgumentParser(prog="repoguard", description="GitHub repo risk scanner")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="Scan a public GitHub repo")
    s.add_argument("repo", help="owner/repo or https://github.com/owner/repo")
    s.add_argument("--json", dest="json_path", default=None, help="Write report JSON to a file")
    s.add_argument("--max-files", type=int, default=2500, help="Max files to scan (default: 2500)")
    s.add_argument("--max-bytes", type=int, default=750_000, help="Max bytes per file (default: 750000)")

    args = p.parse_args()

    if args.cmd == "scan":
        code = scan(args.repo, args.json_path, args.max_files, args.max_bytes)
        raise SystemExit(code)
