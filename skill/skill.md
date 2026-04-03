# SkillGuard Security Audit

Audit AI Agent Skills for security vulnerabilities, prompt injection risks, and cost estimation.

## Description

SkillGuard performs comprehensive security audits on Claude Code Skills and other AI Agent plugins. It analyzes 10 security dimensions with 109 detection rules, providing detailed reports with risk scores and remediation guidance.

## Usage

When a user wants to audit a skill, ask for the GitHub or ClawHub URL, then run the audit script.

Example:
- "Audit this skill: https://github.com/user/my-skill"
- "Check security of https://clawhub.ai/author/skill-name"

## Commands

```bash
python3 skill/audit.py <github_or_clawhub_url>
```

The script will:
1. Submit the URL to SkillGuard API
2. Monitor scan progress
3. Display the security report in terminal

## Output

The audit provides:
- Overall security grade (A-F)
- Risk breakdown by dimension
- Detailed findings with severity levels
- Token cost estimates
- Remediation recommendations
