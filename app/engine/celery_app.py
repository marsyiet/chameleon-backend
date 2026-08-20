from celery import Celery
from celery.schedules import crontab
from app.config.config import config

def create_celery_app() -> Celery:
    redis_url = config.REDIS_URL
    if redis_url.startswith("rediss://"):
        redis_url += "?ssl_cert_reqs=CERT_NONE"

    app = Celery(
        "scanner",
        broker=redis_url,
        backend=redis_url,
        include=[
            "app.engine.tasks.orchestrator",
            "app.engine.tasks.masscan_task",
            "app.engine.tasks.nmap_task",
            "app.engine.tasks.zgrab_task",
            "app.engine.tasks.enrichment",
            "app.engine.tasks.rescan_task",
        ]
    )

    app.conf.update(
        task_serializer="json",
        result_serializer="json",
        accept_content=["json"],
        timezone="UTC",
        enable_utc=True,
        task_acks_late=True,
        worker_prefetch_multiplier=1,
        task_track_started=True,
        result_expires=86400,
        worker_concurrency=4,
    )

    # Vérifie toutes les heures s'il existe des planifications de scan
    # arrivées à échéance. Nécessite un processus Celery Beat séparé :
    #   celery -A app.engine.celery_app beat --loglevel=info
    app.conf.beat_schedule = {
        "check-due-rescans": {
            "task": "engine.tasks.rescan_task.check_due_rescans",
            "schedule": crontab(minute=0),
        },
    }

    return app


celery_app = create_celery_app()