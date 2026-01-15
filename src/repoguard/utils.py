from __future__ import annotations
import os
import re
from pathlib import Path
from typing import Iterable

TEXT_EXT_ALLOW = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".go", ".java", ".kt", ".rb", ".php",
    ".rs", ".c", ".cc", ".cpp", ".h", ".hpp",
    ".yml", ".yaml", ".json", ".toml", ".ini", ".cfg",
    ".md", ".txt", ".env", ".dockerfile", ".sh", ".bash", ".zsh",
    ".gradle", ".properties", ".xml",
    "Dockerfile",
}

BINARY_EXT_DENY = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".pdf",
    ".zip", ".tar", ".gz", ".7z", ".rar",
    ".exe", ".dll", ".so", ".dylib",
    ".bin", ".dat",
}

IGNORE_DIRS = {
    ".git", ".venv", "venv", "env",
    "__pycache__", ".pytest_cache",
    "node_modules", ".mypy_cache",
    "dist", "build", ".tox",
}


def is_probably_text_file(path: Path) -> bool:
    name = path.name
    ext = path.suffix.lower()
    if ext in BINARY_EXT_DENY:
        return False
    if name == "Dockerfile":
        return True
    return (ext in TEXT_EXT_ALLOW) or (ext == "")

def iter_files(root: Path, max_files: int) -> Iterable[Path]:
    count = 0
    for p in root.rglob("*"):
        parts = set(p.parts)
        if parts & IGNORE_DIRS:
            continue
        if p.is_file():
            count += 1
            if count > max_files:
                return
            yield p


def safe_read_text(path: Path, max_bytes: int) -> str | None:
    try:
        if path.stat().st_size > max_bytes:
            return None
        data = path.read_bytes()
        if b"\x00" in data[:1024]:
            return None
        return data.decode("utf-8", errors="replace")
    except Exception:
        return None

def normalize_repo_ref(repo_ref: str) -> str:
    repo_ref = repo_ref.strip()
    m = re.match(r"^https?://github\.com/([^/]+)/([^/]+)", repo_ref)
    if m:
        owner, repo = m.group(1), m.group(2)
        repo = repo.replace(".git", "")
        return f"{owner}/{repo}"
    if repo_ref.count("/") == 1:
        return repo_ref
    raise ValueError("Repo must be like owner/repo or https://github.com/owner/repo")
