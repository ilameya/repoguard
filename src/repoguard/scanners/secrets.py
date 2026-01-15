from __future__ import annotations
import math
import re
from pathlib import Path
from repoguard.report import Finding
from repoguard.utils import is_probably_text_file, safe_read_text, iter_files

SECRET_PATTERNS = [
    ("AWS Access Key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("GitHub Token", re.compile(r"\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b")),
    ("GitHub PAT", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b")),
    ("Slack Token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("Private Key Block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |)PRIVATE KEY-----")),
]

RISKY_FILENAMES = {
    ".env", ".env.local", ".env.prod", ".env.production",
    "id_rsa", "id_ed25519",
    "credentials", "credentials.json",
    "secret", "secrets", "secrets.json",
    ".npmrc",
}

LOW_VALUE_PATH_MARKERS = (
    "data/",
    "datasets/",
    "generated_tests/",
    "generated_test",
    "tests/",
    "testdata/",
    "benchmarks/",
)


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    ent = 0.0
    n = len(s)
    for c in freq.values():
        p = c / n
        ent -= p * math.log2(p)
    return ent


def _looks_like_non_secret(token: str, window: str) -> bool:
    w = window.lower()

    if any(x in token for x in ("/", "\\", "mnt", "home", "Users", "site-packages")):
        return True

    if token.startswith("1FAIpQL"):
        return True

    if token.startswith(("http://", "https://", "www.")):
        return True

    if any(k in w for k in ("sha256", "sha1", "md5", "checksum", "digest", "commit", "hash=")):
        return True

    if token.startswith("sha256:"):
        return True

    if "abcdefghijklmnopqrstuvwxyz" in token.lower():
        return True
    if "ABCDEFGHIJKLMNOPQRSTUVWXYZ" in token:
        return True
    
    if "github.com" in w or "gitlab.com" in w:
        return True

    return False


def scan_secrets(root: Path, max_files: int, max_bytes: int) -> list[Finding]:
    findings: list[Finding] = []

    for p in iter_files(root, max_files=max_files):
        if p.name in RISKY_FILENAMES:
            findings.append(Finding(
                severity="MEDIUM",
                category="secrets",
                title=f"Risky file committed: {p.name}",
                evidence=f"Found file named {p.name}",
                file=str(p.relative_to(root)),
                recommendation="Do not commit secrets/config with credentials. Use environment variables or secret managers.",
                points=10,
            ))

    entropy_hits = 0
    max_entropy_hits = 5

    scanned = 0
    for p in iter_files(root, max_files=max_files):
        scanned += 1
        if scanned > max_files:
            break

        if not is_probably_text_file(p):
            continue

        text = safe_read_text(p, max_bytes=max_bytes)
        if text is None:
            continue

        rel = str(p.relative_to(root))
        rel_l = rel.lower()

        for name, rx in SECRET_PATTERNS:
            m = rx.search(text)
            if not m:
                continue
            findings.append(Finding(
                severity="CRITICAL" if "Private Key" in name else "HIGH",
                category="secrets",
                title=f"Possible secret detected: {name}",
                evidence=f"Matched pattern in {rel}: {m.group(0)[:60]}",
                file=rel,
                recommendation="Rotate/revoke the credential immediately. Remove from git history (BFG/git filter-repo).",
                points=40 if "Private Key" in name else 20,
            ))

        if any(marker in rel_l for marker in LOW_VALUE_PATH_MARKERS):
            continue

        if entropy_hits >= max_entropy_hits:
            continue

        for m in re.finditer(r"\b[A-Za-z0-9+_=\-]{32,}\b", text):
            if entropy_hits >= max_entropy_hits:
                break

            token = m.group(0)

            if not (re.search(r"[A-Za-z]", token) and re.search(r"\d", token)):
                continue

            start = max(0, m.start() - 40)
            end = min(len(text), m.end() + 40)
            window = text[start:end]

            if _looks_like_non_secret(token, window):
                continue

            ent = _entropy(token)
            if ent < 4.8:
                continue

            findings.append(Finding(
                severity="MEDIUM",
                category="secrets",
                title="High-entropy token-like string",
                evidence=f"String with entropy {ent:.2f} in {rel}: {token[:40]}…",
                file=rel,
                recommendation="Verify this is not a credential/token. If it is, rotate and remove it.",
                points=10,
            ))
            entropy_hits += 1
            break  

    return findings
