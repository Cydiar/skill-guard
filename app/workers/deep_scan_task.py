"""Celery task for Deep Scan (Layer 2): LLM-driven skill execution with trace."""

import json
import logging
import shutil
import tempfile
from pathlib import Path

from app.workers import celery_app
from app.workers._progress import publish_progress
from app.db import (
    get_scan, get_scan_findings, get_deep_scan,
    update_deep_scan, insert_trace_step,
)
from app.engine.llm_client import create_llm_client
from app.engine.skill_driver import SkillDriver, Evidence

logger = logging.getLogger(__name__)


def _publish(deep_scan_id: str, phase: str, progress: int, **extra):
    """Publish deep scan progress via Redis pub/sub."""
    publish_progress(
        scan_id=deep_scan_id,
        phase=phase,
        progress=progress,
    )


def _re_clone(scan: dict, report_json: dict) -> tuple[Path, str]:
    """Re-clone the repo when the original temp dir has been cleaned up.

    Returns (skill_dir, clone_dir_path) — caller must clean up clone_dir.
    """
    from app.workers.clone import _download_tarball, _download_clawhub_zip
    from app.engine.scanner import parse_github_url, parse_clawhub_url, is_clawhub_url
    import subprocess, os
    from app.config import CLONE_TIMEOUT

    github_url = scan.get("github_url", "")
    if not github_url:
        raise ValueError("No github_url in scan record")

    clone_dir = Path(tempfile.mkdtemp(prefix="sg_deepscan_"))

    if is_clawhub_url(github_url):
        # ── ClawHub path ──
        slug = parse_clawhub_url(github_url)
        target = _download_clawhub_zip(slug, clone_dir, timeout=CLONE_TIMEOUT)
        if target is None:
            raise RuntimeError(f"Failed to re-download ClawHub skill: {slug}")
        return target, str(clone_dir)

    # ── GitHub path ──
    owner, repo, subpath = parse_github_url(github_url)
    clone_dir = Path(tempfile.mkdtemp(prefix="sg_deepscan_"))

    # Try tarball first, fall back to git clone
    target = _download_tarball(owner, repo, clone_dir, timeout=CLONE_TIMEOUT)
    if target is None:
        target = clone_dir / repo
        clone_url = f"https://github.com/{owner}/{repo}.git"
        env = os.environ.copy()
        env["GIT_CONFIG_NOSYSTEM"] = "1"
        env["GIT_TERMINAL_PROMPT"] = "0"
        subprocess.run(
            ["git", "clone", "--depth", "1", "--single-branch", "--no-tags", clone_url, str(target)],
            env=env, timeout=CLONE_TIMEOUT, capture_output=True, check=True,
        )

    # Navigate to the correct skill subdirectory
    skill_name = scan.get("skill_name", "")
    original_path = report_json.get("skill_path", "")

    if skill_name and original_path:
        # Try to reconstruct relative path from the original skill_path
        # e.g. /tmp/sg_clone_xxx/superpowers/skills/writing-skills -> skills/writing-skills
        # The repo root is `target`, find the skill subdir by matching skill_name
        for skill_md in target.rglob("SKILL.md"):
            if skill_md.parent.name == skill_name or skill_name in str(skill_md.parent):
                return skill_md.parent, str(clone_dir)

    # If subpath was in the URL
    if subpath:
        skill_path = target / subpath
        if skill_path.is_dir():
            return skill_path, str(clone_dir)

    # Fallback: use repo root
    return target, str(clone_dir)


@celery_app.task(bind=True, name="run_deep_scan", time_limit=600, soft_time_limit=540)
def run_deep_scan(self, deep_scan_id: str, scan_id: str, model: str,
                  base_url: str = "", api_key: str = ""):
    """Execute Deep Scan: LLM-driven skill analysis with full trace.

    Uses user-provided API credentials.

    Phases:
        1. preparing  (0-15%)  — Load static results, create LLM client
        2. running    (15-70%) — Multi-turn LLM conversation + tool execution
        3. annotating (70-85%) — Risk annotation of evidence
        4. generating (85-100%) — Build report JSON
    """
    clone_dir = None  # Track for cleanup
    try:
        # ── Phase 1: Preparing ──────────────────────────────────────
        update_deep_scan(deep_scan_id, status="preparing")
        _publish(deep_scan_id, "preparing", 5)

        # Get static scan data
        scan = get_scan(scan_id)
        if not scan:
            raise ValueError(f"Static scan not found: {scan_id}")

        report_json = json.loads(scan.get("report_json", "{}")) if scan.get("report_json") else {}
        clone_path = report_json.get("skill_path", "")

        if clone_path and Path(clone_path).is_dir():
            skill_dir = Path(clone_path)
        else:
            # Temp dir was cleaned up — re-clone the repo
            _publish(deep_scan_id, "preparing", 8)
            skill_dir, clone_dir = _re_clone(scan, report_json)

        static_findings = get_scan_findings(scan_id)

        # Create LLM client with user-provided credentials
        llm_client = create_llm_client(model, api_key=api_key, base_url=base_url)
        _publish(deep_scan_id, "preparing", 15)

        # ── Phase 2: Running ────────────────────────────────────────
        update_deep_scan(deep_scan_id, status="running")

        step_counter = [0]

        def on_step(step_number, role, content_preview):
            """Callback for each trace step — publish progress."""
            step_counter[0] = step_number
            # Map step progress: 15% to 70%
            max_steps = 100  # rough estimate
            prog = 15 + int(55 * min(step_number / max_steps, 1.0))
            _publish(deep_scan_id, "running", prog)

        driver = SkillDriver(
            llm_client=llm_client,
            skill_dir=skill_dir,
            static_findings=static_findings,
            on_step=on_step,
        )

        result = driver.run()
        _publish(deep_scan_id, "running", 70)

        # ── Phase 3: Annotating ─────────────────────────────────────
        update_deep_scan(deep_scan_id, status="annotating")
        _publish(deep_scan_id, "annotating", 75)

        # Store trace steps in DB
        for step in result.trace:
            insert_trace_step(
                deep_scan_id=deep_scan_id,
                step_number=step.step_number,
                role=step.role,
                content=step.content,
                risk_level=step.risk_level,
                related_finding=step.related_finding,
            )

        _publish(deep_scan_id, "annotating", 85)

        # ── Phase 4: Generating report ──────────────────────────────
        update_deep_scan(deep_scan_id, status="generating")
        _publish(deep_scan_id, "generating", 90)

        # Build evidence list for report
        evidence_list = []
        for ev in result.evidences:
            evidence_list.append({
                "evidence_type": ev.evidence_type,
                "risk_level": ev.risk_level,
                "description": ev.description,
                "tool_name": ev.tool_name,
                "tool_input": ev.tool_input,
                "tool_output": ev.tool_output[:2000],
                "related_finding_id": ev.related_finding_id,
                "related_finding_desc": ev.related_finding_desc,
            })

        # Get LLM usage
        usage = llm_client.get_usage()

        # Build report
        report = {
            "deep_scan_id": deep_scan_id,
            "scan_id": scan_id,
            "model": model,
            "provider": "anthropic",
            "skill_name": scan.get("skill_name", ""),
            "github_url": scan.get("github_url", ""),
            "static_risk_score": scan.get("risk_score", 0),
            "static_risk_level": scan.get("risk_level", ""),
            "dynamic_risk_score": result.risk_score,
            "total_turns": result.total_turns,
            "total_tool_calls": result.total_tool_calls,
            "total_tokens_in": usage["input_tokens"],
            "total_tokens_out": usage["output_tokens"],
            "evidences": evidence_list,
            "evidence_summary": _build_evidence_summary(evidence_list),
            "trace_step_count": len(result.trace),
        }

        # Estimate cost (Anthropic pricing)
        actual_cost = _estimate_cost(model, usage["input_tokens"], usage["output_tokens"])

        # Update DB with final results
        update_deep_scan(
            deep_scan_id,
            status="done",
            risk_score=result.risk_score,
            total_turns=result.total_turns,
            total_tool_calls=result.total_tool_calls,
            total_tokens_in=usage["input_tokens"],
            total_tokens_out=usage["output_tokens"],
            actual_cost=actual_cost,
            report_json=json.dumps(report, ensure_ascii=False),
        )

        _publish(deep_scan_id, "done", 100)
        return {"deep_scan_id": deep_scan_id, "status": "done"}

    except Exception as e:
        logger.exception(f"Deep scan failed: {deep_scan_id}")
        error_msg = str(e)[:500]
        update_deep_scan(deep_scan_id, status="error", error_message=error_msg)
        _publish(deep_scan_id, "error", 0)
        return {"deep_scan_id": deep_scan_id, "status": "error", "error": error_msg}
    finally:
        # Clean up re-cloned temp dir if we created one
        if clone_dir and Path(clone_dir).exists():
            shutil.rmtree(clone_dir, ignore_errors=True)


def _build_evidence_summary(evidences: list[dict]) -> dict:
    """Build a summary of evidence by risk level."""
    summary = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "total": len(evidences)}
    for ev in evidences:
        level = ev.get("risk_level", "")
        if level in summary:
            summary[level] += 1
    return summary


def _estimate_cost(model: str, input_tokens: int, output_tokens: int) -> float:
    """Estimate cost based on model pricing."""
    from app.config import DEEP_SCAN_MODELS
    model_info = DEEP_SCAN_MODELS.get(model)
    if model_info:
        rates = {"input": model_info["input_per_m"], "output": model_info["output_per_m"]}
    else:
        rates = {"input": 3.0, "output": 15.0}  # default to sonnet pricing

    cost = (input_tokens / 1_000_000 * rates["input"]) + (output_tokens / 1_000_000 * rates["output"])
    return round(cost, 6)
