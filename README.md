# RepoGuard

RepoGuard is a lightweight static analysis tool that scans GitHub repositories for **common security risks** such as leaked secrets, unsafe configuration files, and vulnerable dependencies.

It is designed to be:
- **Fast** (runs in seconds)
- **Low-noise** (aggressively avoids false positives)
- **Practical** (focused on issues that actually matter in real repositories)

RepoGuard focuses on early warning signals, not exhaustive security certification.

---

## What RepoGuard Checks

### 1. Secret Leakage
Detects high-risk credentials using **high-signal patterns**, including:
- AWS access keys
- GitHub tokens and PATs
- Slack tokens
- Private key blocks (RSA, EC, OpenSSH)

Additionally, RepoGuard uses a **guardrailed entropy heuristic** to flag suspicious token-like strings while avoiding:
- Filesystem paths
- Hashes and checksums
- Generated datasets
- Benchmarks and test corpora
- Dependency artifacts and virtual environments

### 2. Risky Files
Flags files that commonly contain secrets, such as:
- `.env`, `.env.production`
- SSH private keys (`id_rsa`, `id_ed25519`)
- Credential JSON files
- `.npmrc`

### 3. Dependency Vulnerabilities (Python)
If a `requirements.txt` file is present, RepoGuard runs `pip-audit` to identify known CVEs.

Dependency scanning is **best-effort**:
- Resolution or metadata errors are treated as *non-fatal*
- Tooling issues do not inflate the risk score
- Only actionable vulnerability findings affect scoring

---

## Scoring Model

RepoGuard assigns points per finding and aggregates them into a final score:

| Score Range | Risk Level |
|------------|-----------|
| 0–9        | LOW       |
| 10–29      | MEDIUM    |
| 30–59      | HIGH      |
| 60–100     | CRITICAL  |

Key design principles:
- Scores are **capped** to prevent saturation from noisy findings
- Entropy-based findings are **limited per repo**
- High-signal findings (e.g., private keys) dominate the score

---

## Installation

Clone the repository and install in editable mode:

```bash
git clone https://github.com/ilameya/RepoGuard.git
cd repoguard
python -m venv .venv
source .venv/bin/activate
pip install -e .
```

Optional:

```bash
pip install pip-audit
```

## Usage

Scan a public GitHub repository:

For CLI output:
```bash
repoguard scan https://github.com/user/repo
```

For saved JSON output:
```bash
repoguard scan https://github.com/user/repo --json repoguard_report.json
```

## Limitations
- Entropy-based detection is heuristic by nature
- Dependency scanning depends on external tooling (pip-audit)
- Only Python dependencies are supported currently

## On-going Improvements
- Configuration of ignore rules
- Additional dependency ecosystems
- Structured JSON output for pipelines

