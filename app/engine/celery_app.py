from celery import Celery
from config import config
 
def create_celery_app() -> Celery:
    app = Celery(
        "scanner",
        broker=config.REDIS_URL,
        backend=config.REDIS_URL.replace("/0", "/1"),  # base Redis séparée
        include=[
            "engine.tasks.orchestrator",
            "engine.tasks.masscan_task",
            "engine.tasks.nmap_task",
            "engine.tasks.zgrab_task",
            "engine.tasks.enrichment",
        ]
    )
 
    app.conf.update(
        task_serializer="json",
        result_serializer="json",
        accept_content=["json"],
        timezone="UTC",
        enable_utc=True,
        task_acks_late=True,         # évite perte de tâches si crash worker
        worker_prefetch_multiplier=1, # 1 tâche à la fois par worker
        task_track_started=True,      # statut "STARTED" visible dans Redis
        result_expires=86400,         # résultats gardés 24h dans Redis
        worker_concurrency=4,         # threads par worker
    )
 
    return app
 
 
celery_app = create_celery_app()
