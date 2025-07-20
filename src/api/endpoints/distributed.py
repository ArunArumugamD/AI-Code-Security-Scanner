# src/api/endpoints/distributed.py
"""API endpoints for distributed scanning"""
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session
from pydantic import BaseModel
from src.database.models.base import get_db
from src.distributed.tasks import (
    scan_file_task, scan_directory_task, 
    distributed_project_scan, analyze_vulnerability_task
)
from celery.result import AsyncResult

router = APIRouter(prefix="/api/distributed", tags=["Distributed Scanning"])

# Request models
class FileScanRequest(BaseModel):
    file_path: str
    project_id: Optional[int] = None

class DirectoryScanRequest(BaseModel):
    directory: str
    extensions: Optional[List[str]] = None

@router.post("/scan/file")
async def distributed_file_scan(request: FileScanRequest):
    """Queue file for distributed scanning"""
    task = scan_file_task.delay(request.file_path, request.project_id)
    return {
        "task_id": task.id,
        "status": "queued",
        "file": request.file_path
    }

@router.post("/scan/directory")
async def distributed_directory_scan(request: DirectoryScanRequest):
    """Scan directory using multiple workers"""
    task = scan_directory_task.delay(request.directory, request.extensions)
    return {
        "task_id": task.id,
        "status": "distributed_scan_started",
        "directory": request.directory
    }

@router.post("/scan/project/{project_id}")
async def scan_project_distributed(
    project_id: int,
    parallel_workers: int = 4,
    db: Session = Depends(get_db)
):
    """Full distributed project scan"""
    task = distributed_project_scan.delay(project_id, parallel_workers)
    return {
        "task_id": task.id,
        "project_id": project_id,
        "workers": parallel_workers,
        "status": "distributed_scan_initiated"
    }

@router.get("/task/{task_id}")
async def get_task_status(task_id: str):
    """Get distributed task status"""
    result = AsyncResult(task_id)
    
    if result.ready():
        return {
            "task_id": task_id,
            "status": result.status,
            "result": result.result
        }
    else:
        return {
            "task_id": task_id,
            "status": result.status,
            "info": result.info
        }

@router.get("/workers/status")
async def get_worker_status():
    """Get active workers status"""
    from celery_config import app
    
    # Get active workers
    active = app.control.inspect().active()
    stats = app.control.inspect().stats()
    
    return {
        "active_workers": list(active.keys()) if active else [],
        "worker_stats": stats or {},
        "total_workers": len(active) if active else 0
    }

# Update main.py to include distributed routes
def register_distributed_routes(app):
    app.include_router(router)