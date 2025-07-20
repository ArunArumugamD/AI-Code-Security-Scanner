# run_worker.py
"""Start a Celery worker for distributed scanning"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from celery_config import app

if __name__ == '__main__':
    # Windows-compatible worker
    app.worker_main([
        'worker',
        '--loglevel=info',
        '--concurrency=2',
        '--pool=solo'
    ])