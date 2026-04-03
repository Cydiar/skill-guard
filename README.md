<p align="center">
  <h1 align="center">SkillGuard</h1>
  <p align="center"><strong>Security Audit Platform for AI Agent Skills</strong></p>
  <p align="center">
    10 Dimensions · 109 Rules · A–F Risk Grading · Token Cost Estimation
  </p>
  <p align="center">
    <a href="#quick-start">Quick Start</a> ·
    <a href="#features">Features</a> ·
    <a href="#security-dimensions">Dimensions</a> ·
    <a href="#architecture">Architecture</a> ·
    <a href="#deep-scan">Deep Scan</a> ·
    <a href="#claude-code-skill">Skill Integration</a>
  </p>
</p>

---

## What is SkillGuard?

SkillGuard performs comprehensive security audits on **Claude Code Skills** and other AI Agent plugins. Paste a GitHub or [ClawHub](https://clawhub.ai) URL — get a full security report in seconds.

Audit methodology is based on **OWASP LLM Top 10**, **SLSA**, and **Google SAIF**.

## Quick Start

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Start Redis
redis-server --daemonize yes

# 3. Start Celery worker
celery -A app.workers worker --loglevel=info --concurrency=2 &

# 4. Start API server
python -m uvicorn app.main:app --host 0.0.0.0 --port 8011
```

Open **http://localhost:8011** → paste a Skill URL → scan.

## Features

| Feature | Description |
|---------|-------------|
| **Static Analysis** | Pattern-based scanning across 10 security dimensions with 109 rules (67 built-in + 42 configurable) |
| **Deep Scan** | LLM-driven dynamic analysis with multi-turn execution trace and evidence collection |
| **A–F Risk Grading** | Clear letter-grade assessment with per-dimension breakdown |
| **Token Cost Estimation** | 4-level token analysis (L1–L3) with multi-model cost projections |
| **Multi-Skill Detection** | Automatic monorepo detection — scans all skills in a single repo |
| **Bilingual Reports** | Full CN/EN language toggle across all report pages |
| **Configurable Rules** | YAML-based rule engine — add, disable, or whitelist rules per project |

## Security Dimensions

| # | Dimension | Coverage |
|---|-----------|----------|
| 1 | Prompt Injection | Direct/indirect injection patterns, zero-width chars, hidden instructions |
| 2 | Permission Escalation | Missing `allowed-tools`, shell access, dangerous tool combinations |
| 3 | Data Exfiltration | Credential theft, env leaks, outbound HTTP, webhook tunneling |
| 4 | Resource Abuse | Infinite loops, excessive fetching, unbounded retries |
| 5 | Supply Chain | Pipe-to-shell, unpinned dependencies, unverified Docker images |
| 6 | License Compliance | Proprietary restrictions, non-commercial clauses, commercial platform locks |
| 7 | Code Execution | Arbitrary code eval, dynamic imports, subprocess spawning |
| 8 | Filesystem Access | Path traversal, sensitive file reads, recursive deletion |
| 9 | Network Access | Unrestricted outbound, DNS exfiltration, proxy abuse |
| 10 | Obfuscation | Base64 payloads, encoded strings, anti-analysis techniques |

## Architecture

```
                    ┌──────────────┐
                    │   Browser    │
                    └──────┬───────┘
                           │
                    ┌──────▼───────┐
                    │   FastAPI    │  :8011
                    │   Uvicorn    │
                    └──────┬───────┘
                           │
              ┌────────────┼────────────┐
              │            │            │
       ┌──────▼──────┐ ┌──▼───┐ ┌──────▼──────┐
       │ Static Scan │ │Redis │ │  Deep Scan  │
       │   Engine    │ │      │ │  (Celery)   │
       └─────────────┘ └──────┘ └─────────────┘
                                       │
                                ┌──────▼──────┐
                                │  LLM API    │
                                │ (User BYOK) │
                                └─────────────┘
```

- **FastAPI** — Web UI + REST API
- **Celery + Redis** — Async task queue for scan jobs
- **SQLite** — Scan results and report storage
- **LLM Client** — BYOK (Bring Your Own Key) for Deep Scan

## Deep Scan

Deep Scan uses LLM-driven dynamic analysis to go beyond static pattern matching. It executes the skill in a sandboxed environment, traces tool calls, and collects risk evidence.

**Configuration** — provide your own API credentials at runtime:

| Field | Description |
|-------|-------------|
| Base URL | API endpoint (e.g. `https://api.anthropic.com`) |
| API Key | Your API key |
| Model | Sonnet 4.6 Sonnet / Sonnet 4.6 Opus |

No API keys are stored on the server.

## Claude Code Skill

SkillGuard is also available as a **Claude Code Skill** for in-terminal auditing.

```bash
# Audit a skill directly from Claude Code
python3 skill/audit.py https://github.com/user/my-skill
python3 skill/audit.py https://clawhub.ai/author/skill-name
```

Output includes risk grade (A–F), dimension breakdown, severity findings, and remediation guidance.

## Tech Stack

| Layer | Technology |
|-------|-----------|
| API | FastAPI 0.115 · Uvicorn · Pydantic 2 |
| Task Queue | Celery 5.4 · Redis 5.2 |
| Database | SQLite · aiosqlite |
| LLM Client | httpx (direct Anthropic Messages API) |
| Frontend | Jinja2 · Alpine.js · Tailwind CSS |
| Rules Engine | PyYAML · Configurable YAML rules |

## License

MIT
