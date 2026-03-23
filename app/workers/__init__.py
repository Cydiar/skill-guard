"""Celery app instance and configuration."""

from celery import Celery

from app.config import REDIS_URL

celery_app = Celery(
    "skillguard",
    broker=REDIS_URL,
    backend=REDIS_URL,
    include=[
        "app.workers.clone",
        "app.workers.audit_task",
        "app.workers.deep_scan_task",
    ],
)

celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    task_track_started=True,
    task_time_limit=300,
    task_soft_time_limit=240,
)
