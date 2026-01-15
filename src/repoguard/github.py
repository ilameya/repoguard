from __future__ import annotations
import io
import zipfile
from dataclasses import dataclass
from pathlib import Path
import requests

GITHUB_API = "https://api.github.com"

@dataclass
class RepoMeta:
    owner: str
    repo: str
    default_branch: str
    html_url: str
    updated_at: str | None

def _get(url: str, timeout: int = 30) -> requests.Response:
    r = requests.get(url, timeout=timeout, headers={"Accept": "application/vnd.github+json"})
    r.raise_for_status()
    return r

def fetch_repo_meta(owner: str, repo: str) -> RepoMeta:
    data = _get(f"{GITHUB_API}/repos/{owner}/{repo}").json()
    return RepoMeta(
        owner=owner,
        repo=repo,
        default_branch=data.get("default_branch", "main"),
        html_url=data.get("html_url", f"https://github.com/{owner}/{repo}"),
        updated_at=data.get("updated_at"),
    )

def download_repo_zip(owner: str, repo: str, branch: str, dest_dir: Path) -> Path:
    """
    Downloads the repo zipball and extracts it into dest_dir.
    Returns the extracted root folder.
    """
    url = f"{GITHUB_API}/repos/{owner}/{repo}/zipball/{branch}"
    resp = _get(url)
    z = zipfile.ZipFile(io.BytesIO(resp.content))
    z.extractall(dest_dir)
    top_levels = [p for p in dest_dir.iterdir() if p.is_dir()]
    if not top_levels:
        raise RuntimeError("Zip extraction failed (no root folder found).")
    top_levels.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    return top_levels[0]
