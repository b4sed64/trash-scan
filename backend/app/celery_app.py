"""Celery application: execution queue and scheduler tick (PRD §19)."""
from __future__ import annotations

from celery import Celery

from .config import get_settings

settings = get_settings()

celery_app = Celery(
    "trashscan",
    broker=settings.redis_url,
    backend=settings.redis_url,
    include=["app.worker.tasks"],
)

celery_app.conf.update(
    task_always_eager=settings.celery_task_always_eager,
    task_eager_propagates=True,
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    worker_prefetch_multiplier=1,
    task_track_started=True,
    broker_connection_retry_on_startup=True,
    result_expires=3600,
    timezone="UTC",
    beat_schedule={
        "scheduler-tick": {
            "task": "app.worker.tasks.scheduler_tick",
            "schedule": 30.0,
        },
        "lifecycle-sweep": {
            "task": "app.worker.tasks.lifecycle_sweep",
            "schedule": 30.0,
        },
        "retention-sweep": {
            "task": "app.worker.tasks.retention_sweep",
            "schedule": 3600.0,
        },
    },
)
