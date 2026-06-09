from celery import Celery
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

    return app


celery_app = create_celery_app()