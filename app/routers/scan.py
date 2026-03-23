"""Scan API endpoints — trigger scans, check status, WebSocket progress."""

import asyncio
import json

import redis
from celery import chain
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, HTTPException

from app.config import REDIS_URL
from app.db import create_scan, get_scan, count_child_status
from app.models import ScanRequest, ScanResponse, ScanStatus
from app.workers.clone import clone_repo
from app.workers.audit_task import detect_and_dispatch

router = APIRouter(prefix="/api/scan", tags=["scan"])


@router.post("", response_model=ScanResponse)
async def start_scan(req: ScanRequest):
    """Create a new scan and dispatch the clone → detect → audit pipeline."""
    scan_id = create_scan(req.github_url)

    # Celery chain: clone → detect_and_dispatch (handles single or multi-skill)
    pipeline = chain(
        clone_repo.s(scan_id, req.github_url),
        detect_and_dispatch.s(scan_id=scan_id),
    )
    pipeline.apply_async()

    return ScanResponse(scan_id=scan_id, status="pending")


@router.get("/{scan_id}/status", response_model=ScanStatus)
async def scan_status(scan_id: str):
    """Return current scan status."""
    scan = get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    # Map statuses to progress percentages
    progress_map = {
        "pending": 0,
        "cloning": 10,
        "cloned": 30,
        "scanning": 50,
        "saving": 80,
        "done": 100,
        "error": 0,
    }

    is_multi = bool(scan.get("is_multi_skill"))
    total_skills = 0
    done_skills = 0

    if is_multi and scan["status"] not in ("done", "error"):
        counts = count_child_status(scan_id)
        total_skills = counts["total"]
        done_count = counts["done"] or 0
        error_count = counts["error"] or 0
        done_skills = done_count + error_count
        # Calculate progress based on child completion
        if total_skills > 0:
            progress = 35 + int(60 * done_skills / total_skills)
        else:
            progress = progress_map.get(scan["status"], 0)
    else:
        progress = progress_map.get(scan["status"], 0)

    return ScanStatus(
        scan_id=scan_id,
        status=scan["status"],
        phase=scan["status"],
        progress=progress,
        skill_name=scan.get("skill_name", ""),
        error_message=scan.get("error_message", ""),
        is_multi_skill=is_multi,
        total_skills=total_skills,
        done_skills=done_skills,
    )


@router.delete("/clear")
async def clear_scans():
    """Delete all scan records (scans, findings, deep_scans, trace_steps)."""
    from app.db import get_db
    conn = get_db()
    try:
        conn.execute("DELETE FROM trace_steps")
        conn.execute("DELETE FROM deep_scans")
        conn.execute("DELETE FROM findings")
        conn.execute("DELETE FROM scans")
        conn.commit()
    finally:
        conn.close()
    return {"status": "ok"}


@router.websocket("/{scan_id}/ws")
async def scan_ws(websocket: WebSocket, scan_id: str):
    """WebSocket endpoint for real-time scan progress updates.

    Subscribes to Redis pub/sub channel `scan:{scan_id}` and forwards
    messages to the client. Also polls DB status as fallback.
    """
    await websocket.accept()

    # Check scan exists
    scan = get_scan(scan_id)
    if not scan:
        await websocket.send_json({"error": "Scan not found"})
        await websocket.close()
        return

    # If already done, send final status and close
    if scan["status"] in ("done", "error"):
        await websocket.send_json({
            "scan_id": scan_id,
            "phase": scan["status"],
            "progress": 100 if scan["status"] == "done" else 0,
        })
        await websocket.close()
        return

    r = redis.Redis.from_url(REDIS_URL)
    pubsub = r.pubsub()
    pubsub.subscribe(f"scan:{scan_id}")

    try:
        while True:
            # Check for pub/sub messages
            message = pubsub.get_message(ignore_subscribe_messages=True, timeout=1.0)
            if message and message["type"] == "message":
                data = json.loads(message["data"])
                await websocket.send_json(data)
                if data.get("phase") in ("done", "error"):
                    break
            else:
                # Fallback: poll DB every second
                scan = get_scan(scan_id)
                if scan and scan["status"] in ("done", "error"):
                    progress = 100 if scan["status"] == "done" else 0
                    await websocket.send_json({
                        "scan_id": scan_id,
                        "phase": scan["status"],
                        "progress": progress,
                    })
                    break

            await asyncio.sleep(0.5)
    except WebSocketDisconnect:
        pass
    finally:
        pubsub.unsubscribe()
        pubsub.close()
        r.close()
