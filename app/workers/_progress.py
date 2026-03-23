"""Redis pub/sub helper for progress updates."""

import json

import redis

from app.config import REDIS_URL


def _get_redis():
    return redis.Redis.from_url(REDIS_URL)


def publish_progress(scan_id: str, phase: str, progress: int):
    """Publish a progress update for a scan via Redis pub/sub."""
    try:
        r = _get_redis()
        r.publish(
            f"scan:{scan_id}",
            json.dumps({"scan_id": scan_id, "phase": phase, "progress": progress}),
        )
    except Exception:
        pass  # Non-critical — progress is best-effort
