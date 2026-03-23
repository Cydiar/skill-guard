"""Static audit Celery task — runs the engine and stores results."""

import json
import shutil
from pathlib import Path

from celery import group

from app.db import (
    update_scan_status,
    insert_findings,
    create_child_scan,
    count_child_status,
    get_scan,
    get_child_scans,
    get_scan_findings,
)
from app.engine.scanner import run_audit, detect_skills, compute_summary
from app.workers import celery_app
from app.workers._progress import publish_progress

# Risk levels that auto-trigger Deep Scan
_AUTO_DEEP_SCAN_LEVELS = {"C", "D", "F"}


def _find_clone_root(skill_dir: Path) -> Path | None:
    """Walk up from skill_dir to find the sg_clone_ temp directory root."""
    p = skill_dir
    while p.parent != p:
        if p.name.startswith("sg_clone_") or str(p).startswith("/tmp/sg_clone_"):
            return p
        p = p.parent
    return None


@celery_app.task(bind=True, name="run_static_audit")
def run_static_audit(self, clone_path: str, scan_id: str) -> dict:
    """Run the 10-dimension static audit on a cloned skill directory.

    Args:
        clone_path: Path returned by clone_repo task or skill subdir path.
        scan_id: The scan UUID.

    Returns:
        The audit result dict.
    """
    update_scan_status(scan_id, "scanning")
    publish_progress(scan_id, "scanning", 50)

    skill_dir = Path(clone_path)

    try:
        result = run_audit(skill_dir)
    except Exception as exc:
        update_scan_status(scan_id, "error", error_message=f"Audit failed: {str(exc)[:500]}")
        publish_progress(scan_id, "error", 0)
        # If child scan, check if all siblings are done and trigger finalize
        scan = get_scan(scan_id)
        if scan and scan.get("parent_scan_id"):
            _maybe_finalize(scan["parent_scan_id"])
        raise

    publish_progress(scan_id, "saving", 80)

    # Store results
    update_scan_status(
        scan_id,
        "done",
        skill_name=result.get("skill_name", ""),
        risk_score=result.get("risk_score", 0),
        risk_level=result.get("risk_level", ""),
        report_json=json.dumps(result, ensure_ascii=False),
    )

    # Insert individual findings into DB
    if result.get("findings"):
        insert_findings(scan_id, result["findings"])

    publish_progress(scan_id, "done", 100)

    # If child scan, check if all siblings are done and trigger finalize
    scan = get_scan(scan_id)
    if scan and scan.get("parent_scan_id"):
        _maybe_finalize(scan["parent_scan_id"])

    return {
        "scan_id": scan_id,
        "risk_score": result.get("risk_score", 0),
        "risk_level": result.get("risk_level", ""),
    }


def _maybe_finalize(parent_scan_id: str):
    """Check if all children are done/error and trigger finalize if so."""
    counts = count_child_status(parent_scan_id)
    total = counts["total"]
    done = (counts["done"] or 0) + (counts["error"] or 0)
    if total > 0 and done >= total:
        finalize_multi_scan.delay(parent_scan_id)


def _auto_deep_scan(scan_id: str, result: dict):
    """Auto-trigger Deep Scan for high-risk skills (C/D/F)."""
    import uuid
    from app.config import DEEP_SCAN_DEFAULT_MODEL
    from app.db import create_deep_scan, get_deep_scans_for_scan

    # Skip if there's already a deep scan for this scan
    existing = get_deep_scans_for_scan(scan_id)
    if existing:
        return

    deep_scan_id = str(uuid.uuid4())
    create_deep_scan(deep_scan_id, scan_id, DEEP_SCAN_DEFAULT_MODEL, "anthropic")

    from app.workers.deep_scan_task import run_deep_scan
    run_deep_scan.apply_async(
        args=[deep_scan_id, scan_id, DEEP_SCAN_DEFAULT_MODEL],
        task_id=deep_scan_id,
    )


@celery_app.task(bind=True, name="detect_and_dispatch")
def detect_and_dispatch(self, clone_path: str, scan_id: str) -> dict:
    """Detect whether the repo contains multiple skills and dispatch accordingly.

    Args:
        clone_path: Path returned by clone_repo task.
        scan_id: The parent scan UUID.

    Returns:
        dict with scan_id and multi_skill indicator.
    """
    skill_dirs = detect_skills(Path(clone_path))

    if not skill_dirs:
        # Single-skill: run audit directly
        return run_static_audit(clone_path, scan_id)

    # Multi-skill detected
    scan = get_scan(scan_id)
    github_url = scan["github_url"] if scan else ""

    update_scan_status(scan_id, "scanning", is_multi_skill=1)
    publish_progress(scan_id, "scanning", 35)

    # Publish skill count for the frontend
    from app.workers._progress import _get_redis
    try:
        r = _get_redis()
        r.publish(
            f"scan:{scan_id}",
            json.dumps({
                "scan_id": scan_id,
                "phase": "scanning",
                "progress": 35,
                "is_multi_skill": True,
                "total_skills": len(skill_dirs),
            }),
        )
    except Exception:
        pass

    # Create child scan rows and dispatch as a group
    child_tasks = []
    for skill_dir in skill_dirs:
        skill_name = skill_dir.name
        child_id = create_child_scan(scan_id, github_url, skill_name)
        child_tasks.append(run_static_audit.s(str(skill_dir), child_id))

    # Dispatch all child audits — each child checks if it's the last one
    # and triggers finalize_multi_scan automatically
    group(child_tasks).apply_async()

    return {"scan_id": scan_id, "is_multi_skill": True, "total_skills": len(skill_dirs)}


@celery_app.task(bind=True, name="finalize_multi_scan")
def finalize_multi_scan(self, parent_scan_id: str) -> dict:
    """Aggregate child scan results and update the parent scan.

    Args:
        parent_scan_id: The parent scan UUID.

    Returns:
        Summary dict.
    """
    # Guard: skip if parent is already done (idempotent)
    parent = get_scan(parent_scan_id)
    if parent and parent["status"] == "done":
        return {"scan_id": parent_scan_id, "already_done": True}

    child_scans = get_child_scans(parent_scan_id)

    child_reports = []
    for child in child_scans:
        report_json = {}
        if child.get("report_json"):
            try:
                report_json = json.loads(child["report_json"])
            except (json.JSONDecodeError, TypeError):
                pass

        findings = get_scan_findings(child["id"])

        child_reports.append({
            "scan_id": child["id"],
            "skill_name": child.get("skill_name", ""),
            "risk_score": child.get("risk_score", 0),
            "risk_level": child.get("risk_level", ""),
            "finding_count": len(findings),
            "report_json": report_json,
        })

    summary = compute_summary(child_reports)

    # Update parent scan
    update_scan_status(
        parent_scan_id,
        "done",
        risk_score=summary["max_risk_score"],
        risk_level=summary["max_risk_level"],
        report_json=json.dumps(summary, ensure_ascii=False),
    )
    publish_progress(parent_scan_id, "done", 100)

    # Keep cloned repo for potential Deep Scan use

    return {"scan_id": parent_scan_id, "summary": summary}
