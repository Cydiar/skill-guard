"""Deep Scan API endpoints — trigger, status, WebSocket progress, report."""

import asyncio
import json
import uuid

import redis
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, HTTPException
from pydantic import BaseModel

from app.config import REDIS_URL, DEEP_SCAN_MODELS, DEEP_SCAN_DEFAULT_MODEL
from app.db import (
    get_scan, get_deep_scan, get_deep_scans_for_scan,
    create_deep_scan, get_trace_steps, get_child_scans,
)
from app.workers.deep_scan_task import run_deep_scan

router = APIRouter(prefix="/api/deep-scan", tags=["deep-scan"])


# ── Request / Response schemas ──────────────────────────────────────


class DeepScanRequest(BaseModel):
    scan_id: str
    model: str = DEEP_SCAN_DEFAULT_MODEL


class DeepScanResponse(BaseModel):
    deep_scan_id: str
    status: str


class DeepScanStatusResponse(BaseModel):
    deep_scan_id: str
    status: str
    phase: str = ""
    progress: int = 0
    error_message: str = ""
    total_turns: int = 0
    total_tool_calls: int = 0


# ── Endpoints ───────────────────────────────────────────────────────


class MultiDeepScanResponse(BaseModel):
    deep_scan_ids: list[str]
    status: str
    count: int = 1


@router.post("")
async def start_deep_scan(req: DeepScanRequest):
    """Launch a Deep Scan for a completed static scan.

    Uses built-in LLM credentials. If the scan is multi-skill,
    dispatches a deep scan for each child skill.
    """
    # Validate model
    if req.model not in DEEP_SCAN_MODELS:
        raise HTTPException(status_code=400, detail=f"Unsupported model: {req.model}. Available: {list(DEEP_SCAN_MODELS.keys())}")

    scan = get_scan(req.scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Static scan not found")
    if scan["status"] != "done":
        raise HTTPException(status_code=400, detail="Static scan is not complete")

    # Determine target scans (single or multi-skill children)
    # Multi-skill: only deep scan C/D/F risk level skills
    _DEEP_SCAN_LEVELS = {"C", "D", "F"}
    if scan.get("is_multi_skill"):
        children = get_child_scans(req.scan_id)
        target_scans = [c for c in children if c["status"] == "done" and c.get("risk_level", "A") in _DEEP_SCAN_LEVELS]
        if not target_scans:
            raise HTTPException(status_code=400, detail="No child skills with risk level C/D/F")
    else:
        target_scans = [scan]

    deep_scan_ids = []
    for target in target_scans:
        target_id = target["id"]

        # Check no active deep scan for this target
        existing = get_deep_scans_for_scan(target_id)
        has_active = any(ds["status"] not in ("done", "error") for ds in existing)
        if has_active:
            continue  # Skip already-running children

        deep_scan_id = str(uuid.uuid4())
        create_deep_scan(deep_scan_id, target_id, req.model, "anthropic")

        # Dispatch Celery task (uses built-in API key from config)
        run_deep_scan.apply_async(
            args=[deep_scan_id, target_id, req.model],
            task_id=deep_scan_id,
        )
        deep_scan_ids.append(deep_scan_id)

    if not deep_scan_ids:
        raise HTTPException(status_code=409, detail="All scans already have active deep scans")

    # For single scan, return the single deep_scan_id for redirect
    if len(deep_scan_ids) == 1:
        return {"deep_scan_id": deep_scan_ids[0], "status": "pending", "count": 1}

    # For multi-skill, return first ID for redirect (progress page will track all)
    return {"deep_scan_id": deep_scan_ids[0], "deep_scan_ids": deep_scan_ids, "status": "pending", "count": len(deep_scan_ids)}


@router.get("/{deep_scan_id}/status", response_model=DeepScanStatusResponse)
async def deep_scan_status(deep_scan_id: str):
    """Return current deep scan status."""
    ds = get_deep_scan(deep_scan_id)
    if not ds:
        raise HTTPException(status_code=404, detail="Deep scan not found")

    # Return minimum progress for each phase — real-time progress comes via WebSocket
    # This avoids polling overwriting higher WebSocket values (causing progress bar bounce)
    progress_map = {
        "pending": 0,
        "preparing": 5,
        "running": 15,
        "annotating": 70,
        "generating": 85,
        "done": 100,
        "error": 0,
    }

    return DeepScanStatusResponse(
        deep_scan_id=deep_scan_id,
        status=ds["status"],
        phase=ds["status"],
        progress=progress_map.get(ds["status"], 0),
        error_message=ds.get("error_message") or "",
        total_turns=ds.get("total_turns") or 0,
        total_tool_calls=ds.get("total_tool_calls") or 0,
    )


@router.websocket("/{deep_scan_id}/ws")
async def deep_scan_ws(websocket: WebSocket, deep_scan_id: str):
    """WebSocket for real-time deep scan progress.

    Subscribes to Redis channel `scan:{deep_scan_id}` (reuses the publish_progress
    mechanism with deep_scan_id as the scan_id parameter).
    """
    await websocket.accept()

    ds = get_deep_scan(deep_scan_id)
    if not ds:
        await websocket.send_json({"error": "Deep scan not found"})
        await websocket.close()
        return

    if ds["status"] in ("done", "error"):
        await websocket.send_json({
            "deep_scan_id": deep_scan_id,
            "phase": ds["status"],
            "progress": 100 if ds["status"] == "done" else 0,
        })
        await websocket.close()
        return

    r = redis.Redis.from_url(REDIS_URL)
    pubsub = r.pubsub()
    pubsub.subscribe(f"scan:{deep_scan_id}")

    try:
        while True:
            message = pubsub.get_message(ignore_subscribe_messages=True, timeout=1.0)
            if message and message["type"] == "message":
                data = json.loads(message["data"])
                # Rename scan_id to deep_scan_id for clarity
                data["deep_scan_id"] = data.pop("scan_id", deep_scan_id)
                await websocket.send_json(data)
                if data.get("phase") in ("done", "error"):
                    break
            else:
                # Fallback: poll DB
                ds = get_deep_scan(deep_scan_id)
                if ds and ds["status"] in ("done", "error"):
                    await websocket.send_json({
                        "deep_scan_id": deep_scan_id,
                        "phase": ds["status"],
                        "progress": 100 if ds["status"] == "done" else 0,
                    })
                    break

            await asyncio.sleep(0.5)
    except WebSocketDisconnect:
        pass
    finally:
        pubsub.unsubscribe()
        pubsub.close()
        r.close()


@router.get("/{deep_scan_id}/report")
async def deep_scan_report(deep_scan_id: str):
    """Return the full Deep Scan trace report JSON."""
    ds = get_deep_scan(deep_scan_id)
    if not ds:
        raise HTTPException(status_code=404, detail="Deep scan not found")
    if ds["status"] != "done":
        raise HTTPException(status_code=400, detail="Deep scan is not complete")

    report = json.loads(ds["report_json"]) if ds.get("report_json") else {}

    # Attach trace steps
    trace_steps = get_trace_steps(deep_scan_id)
    report["trace_steps"] = trace_steps

    return report


@router.get("/by-scan/{scan_id}")
async def list_deep_scans(scan_id: str):
    """List all deep scans for a static scan."""
    scans = get_deep_scans_for_scan(scan_id)
    return [
        {
            "deep_scan_id": ds["id"],
            "status": ds["status"],
            "model": ds["model"],
            "risk_score": ds.get("risk_score"),
            "actual_cost": ds.get("actual_cost"),
            "created_at": ds.get("created_at"),
        }
        for ds in scans
    ]
