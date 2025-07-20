# celery_config.py
from celery import Celery
import os

# Redis as broker
broker_url = os.getenv('REDIS_URL', 'redis://localhost:6379/0')
result_backend = os.getenv('REDIS_URL', 'redis://localhost:6379/0')

# Create Celery app
app = Celery('aisec_scanner', broker=broker_url, backend=result_backend)

# Simple configuration
app.conf.update(
    task_serializer='json',
    accept_content=['json'],
    result_serializer='json',
    timezone='UTC',
    enable_utc=True,
    worker_prefetch_multiplier=1,
    worker_max_tasks_per_child=100,
    result_expires=3600,
)

# Auto-discover tasks
app.autodiscover_tasks(['src.distributed'])