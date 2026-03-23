"""Wrapper around the standalone SkillAuditor for web-app use."""

import sys
from dataclasses import asdict
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

# Make scripts/ importable
_scripts_dir = str(Path(__file__).resolve().parent.parent.parent / "scripts")
if _scripts_dir not in sys.path:
    sys.path.insert(0, _scripts_dir)

from audit_skill import SkillAuditor, AuditReport  # noqa: E402


def run_audit(skill_dir: Path) -> dict:
    """Run the full audit on a skill directory and return a JSON-serialisable dict."""
    auditor = SkillAuditor()
    report: AuditReport = auditor.audit_skill(skill_dir)
    return _report_to_dict(report)


def _report_to_dict(report: AuditReport) -> dict:
    """Convert an AuditReport dataclass to a plain dict."""
    return {
        "skill_name": report.skill_name,
        "skill_path": report.skill_path,
        "risk_score": report.risk_score,
        "risk_level": report.risk_level,
        "file_inventory": report.file_inventory,
        "dimension_summary": report.dimension_summary,
        "token_estimate": {
            "l1_skill_md": report.token_estimate.l1_skill_md,
            "l2_eager": report.token_estimate.l2_eager,
            "l2_lazy": report.token_estimate.l2_lazy,
            "l3_total": report.token_estimate.l3_total,
            "l1_chars": report.token_estimate.l1_chars,
            "l2_eager_chars": report.token_estimate.l2_eager_chars,
            "l2_lazy_chars": report.token_estimate.l2_lazy_chars,
            "l3_chars": report.token_estimate.l3_chars,
            "eager_files": report.token_estimate.eager_files,
            "lazy_files": report.token_estimate.lazy_files,
        },
        "cost_estimates": [
            {
                "model": c.model_name,
                "input_per_m": c.input_per_m,
                "output_per_m": c.output_per_m,
                "cache_input_per_m": c.cache_input_per_m,
                "light_cost": round(c.light_cost, 6),
                "typical_cost": round(c.typical_cost, 6),
                "heavy_cost": round(c.heavy_cost, 6),
            }
            for c in report.cost_estimates
        ],
        "findings": [
            {
                "dimension": f.dimension,
                "severity": f.severity,
                "file_path": f.file_path,
                "line_number": f.line_number,
                "pattern": f.pattern,
                "description": f.description,
                "reference": f.reference,
                "remediation_zh": f.remediation_zh,
                "remediation_en": f.remediation_en,
            }
            for f in report.findings
        ],
    }


def parse_github_url(url: str) -> tuple[str, str, Optional[str]]:
    """Parse a GitHub URL into (owner, repo, subpath).

    Supported formats:
      - https://github.com/owner/repo
      - https://github.com/owner/repo/tree/branch/subdir
    """
    parsed = urlparse(url.strip())
    parts = parsed.path.strip("/").split("/")
    if len(parts) < 2:
        raise ValueError(f"Invalid GitHub URL: {url}")
    owner = parts[0]
    repo = parts[1].removesuffix(".git")
    subpath = None
    if len(parts) > 4 and parts[2] == "tree":
        # /owner/repo/tree/branch/subdir/...
        subpath = "/".join(parts[4:])
    return owner, repo, subpath


def detect_skills(clone_dir: Path) -> list[Path]:
    """Walk clone_dir up to depth 3, find all dirs containing SKILL.md.

    Returns:
        Empty list if single-skill (0 or 1 SKILL.md at root only).
        List of skill dir paths if 2+ SKILL.md files found in subdirs.
    """
    skill_dirs = []
    root = clone_dir.resolve()
    for depth in range(4):  # depth 0..3
        if depth == 0:
            if (root / "SKILL.md").is_file():
                skill_dirs.append(root)
        else:
            pattern = "/".join(["*"] * depth) + "/SKILL.md"
            for skill_md in root.glob(pattern):
                skill_dirs.append(skill_md.parent)

    # If 0 or 1 found at root only → single-skill
    if len(skill_dirs) <= 1:
        return []

    # Filter out root-level SKILL.md — we want subdirectory skills
    sub_skills = [d for d in skill_dirs if d != root]
    if len(sub_skills) < 2:
        return []

    return sorted(sub_skills)


def compute_summary(child_reports: list[dict]) -> dict:
    """Aggregate child scan results into a multi-skill summary.

    Args:
        child_reports: list of dicts, each with keys:
            scan_id, skill_name, risk_score, risk_level, finding_count,
            report_json (parsed dict with token_estimate, findings, etc.)

    Returns:
        Summary dict with aggregate stats and children list.
    """
    total_skills = len(child_reports)
    by_level = {"A": 0, "B": 0, "C": 0, "D": 0, "F": 0}
    max_risk_score = 0
    max_risk_level = "A"
    total_l3 = 0
    total_findings = 0

    level_order = {"A": 0, "B": 1, "C": 2, "D": 3, "F": 4}

    children = []
    for report in child_reports:
        level = report.get("risk_level", "A")
        score = report.get("risk_score", 0)
        fcount = report.get("finding_count", 0)

        by_level[level] = by_level.get(level, 0) + 1
        total_findings += fcount

        if score > max_risk_score:
            max_risk_score = score
        if level_order.get(level, 0) > level_order.get(max_risk_level, 0):
            max_risk_level = level

        # Extract L3 total from report_json if available
        rj = report.get("report_json", {})
        if isinstance(rj, dict):
            te = rj.get("token_estimate", {})
            total_l3 += te.get("l3_total", 0)

        children.append({
            "scan_id": report["scan_id"],
            "skill_name": report.get("skill_name", ""),
            "risk_score": score,
            "risk_level": level,
            "finding_count": fcount,
        })

    return {
        "total_skills": total_skills,
        "by_level": by_level,
        "max_risk_score": max_risk_score,
        "max_risk_level": max_risk_level,
        "total_l3_tokens": total_l3,
        "total_findings": total_findings,
        "children": children,
    }
