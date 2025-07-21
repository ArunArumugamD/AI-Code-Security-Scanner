# src/api/main.py
from fastapi import FastAPI, HTTPException, Depends, BackgroundTasks, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from contextlib import asynccontextmanager
from sqlalchemy.orm import Session 
import time
import asyncio
from typing import List, Optional, Dict, Any
from datetime import datetime

from src.api.models import *
from src.database.models.base import get_db, SessionLocal
from src.database.models.vulnerability import Project, VulnerabilityPattern, VulnerabilityDetection, Scan
from src.database.operations import VulnerabilityDB
from src.core.scanner_engine import EnhancedScannerEngine, quick_scan
from src.core.config import settings
from src.api.endpoints import learning
from src.api.websocket.routes import router as websocket_router
from src.api.endpoints import distributed
from src.api.endpoints import analytics
from src.ml.zero_day_detector import router as zero_day_router
import os

# Lifespan context manager for startup/shutdown
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    print("?? Starting AISec Scanner API...")
    
    # Initialize database
    from src.database.models.base import init_db
    init_db()
    
    # Load patterns count
    db = SessionLocal()
    pattern_count = db.query(VulnerabilityPattern).count()
    db.close()
    
    app.state.pattern_count = pattern_count
    print(f"? Loaded {pattern_count} vulnerability patterns")
    
    yield
    
    # Shutdown
    print("?? Shutting down AISec Scanner API...")

# Create FastAPI app
app = FastAPI(
    title="AISec Scanner API",
    description="Advanced AI-powered code security scanner with multi-language support",
    version="1.0.0",
    lifespan=lifespan
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(learning.router)
app.include_router(websocket_router)
app.include_router(distributed.router)
app.include_router(analytics.router)
app.include_router(zero_day_router)

# Exception handler
@app.exception_handler(HTTPException)
async def http_exception_handler(request, exc):
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail, "error_code": f"HTTP_{exc.status_code}"}
    )

# Health check endpoint
@app.get("/health", response_model=HealthResponse, tags=["System"])
async def health_check(db: Session = Depends(get_db)):
    """Check API health and system status"""
    try:
        # Test database connection
        db.execute("SELECT 1")
        db_status = True
    except:
        db_status = False
    
    return HealthResponse(
        status="healthy" if db_status else "degraded",
        version="1.0.0",
        database=db_status,
        analyzers=2,  # Pattern + AST analyzers
        patterns_loaded=app.state.pattern_count
    )

# Root endpoint
@app.get("/", tags=["System"])
async def root():
    """API root endpoint with basic info"""
    return {
        "message": "AISec Scanner API",
        "version": "1.0.0",
        "docs": "/docs",
        "health": "/health",
        "websocket": "/ws", 
        "websocket_demo": "Open websocket_demo.html in browser" 
    }

# Project endpoints
@app.post("/api/projects", response_model=ProjectResponse, status_code=status.HTTP_201_CREATED, tags=["Projects"])
async def create_project(project: ProjectCreate, db: Session = Depends(get_db)):
    """Create a new project"""
    try:
        db_project = VulnerabilityDB.create_project(
            db,
            name=project.name,
            description=project.description,
            repository_url=project.repository_url,
            languages=project.languages
        )
        return ProjectResponse.model_validate(db_project)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/api/projects", response_model=List[ProjectResponse], tags=["Projects"])
async def list_projects(
    skip: int = 0,
    limit: int = 100,
    active_only: bool = True,
    db: Session = Depends(get_db)
):
    """List all projects"""
    query = db.query(Project)
    if active_only:
        query = query.filter(Project.active == True)
    
    projects = query.offset(skip).limit(limit).all()
    return [ProjectResponse.model_validate(p) for p in projects]

@app.get("/api/projects/{project_id}", response_model=ProjectResponse, tags=["Projects"])
async def get_project(project_id: int, db: Session = Depends(get_db)):
    """Get project details"""
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    return ProjectResponse.model_validate(project)

@app.put("/api/projects/{project_id}", response_model=ProjectResponse, tags=["Projects"])
async def update_project(
    project_id: int,
    project_update: ProjectUpdate,
    db: Session = Depends(get_db)
):
    """Update project details"""
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    
    update_data = project_update.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(project, field, value)
    
    db.commit()
    db.refresh(project)
    return ProjectResponse.model_validate(project)

# Scanning endpoints
@app.post("/api/scan/quick", response_model=QuickScanResponse, tags=["Scanning"])
async def quick_code_scan(request: CodeScanRequest):
    """Quick scan code without saving to database"""
    start_time = time.time()
    
    try:
        # Run quick scan
        vulnerabilities = await quick_scan(request.code, request.language)
        
        # Convert to response format
        vuln_list = []
        summary = {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0}
        
        for vuln in vulnerabilities:
            vuln_dict = {
                "line": vuln.line_start,
                "severity": vuln.severity.value,
                "name": vuln.name,
                "description": vuln.description,
                "confidence": vuln.confidence,
                "code_snippet": vuln.code_snippet,
                "fix_suggestion": vuln.fix_suggestion
            }
            vuln_list.append(vuln_dict)
            
            summary["total"] += 1
            summary[vuln.severity.value] += 1
        
        scan_time = time.time() - start_time
        
        return QuickScanResponse(
            vulnerabilities=vuln_list,
            summary=summary,
            scan_time=scan_time
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")

@app.post("/api/scan/start", response_model=ScanResponse, tags=["Scanning"])
async def start_scan(
    request: ScanRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    """Start a full project scan"""
    # Verify project exists
    project = db.query(Project).filter(Project.id == request.project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    
    # Create scan record
    scan = VulnerabilityDB.create_scan(db, request.project_id, request.scan_type.value)
    
    # Start background scan
    background_tasks.add_task(
        run_background_scan,
        scan_id=scan.id,
        project_id=request.project_id,
        target_path=request.target_path,
        file_extensions=request.file_extensions
    )
    
    return ScanResponse.model_validate(scan)

async def run_background_scan(scan_id: int, project_id: int, target_path: str, file_extensions: List[str]):
    """Run scan in background"""
    db = SessionLocal()
    try:
        scanner = EnhancedScannerEngine(project_id=project_id)
        scanner.scan_id = scan_id
        
        if target_path and os.path.exists(target_path):
            if os.path.isfile(target_path):
                await scanner.scan_file(target_path)
            else:
                await scanner.scan_directory(target_path, file_extensions)
        
        # Update scan completion
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if scan:
            scan.end_time = datetime.utcnow()
            scan.duration_seconds = int((scan.end_time - scan.start_time).total_seconds())
            
            # Update counts
            stats = VulnerabilityDB.get_vulnerability_stats(db, project_id)
            scan.total_vulnerabilities = stats['total']
            scan.critical_count = stats['critical']
            scan.high_count = stats['high']
            scan.medium_count = stats['medium']
            scan.low_count = stats['low']
            
            db.commit()
            
    except Exception as e:
        print(f"Background scan error: {e}")
    finally:
        db.close()

# Vulnerability endpoints
@app.get("/api/vulnerabilities", response_model=List[VulnerabilityResponse], tags=["Vulnerabilities"])
async def list_vulnerabilities(
    project_id: Optional[int] = None,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db)
):
    """List vulnerabilities with filters"""
    query = db.query(VulnerabilityDetection)
    
    if project_id:
        query = query.filter(VulnerabilityDetection.project_id == project_id)
    if severity:
        query = query.filter(VulnerabilityDetection.severity == severity)
    if status:
        query = query.filter(VulnerabilityDetection.status == status)
    
    vulns = query.offset(skip).limit(limit).all()
    
    # Enrich with pattern info
    result = []
    for vuln in vulns:
        vuln_dict = VulnerabilityResponse.model_validate(vuln)
        if vuln.pattern:
            vuln_dict.name = vuln.pattern.name
            vuln_dict.description = vuln.pattern.description
            vuln_dict.cwe_id = vuln.pattern.cwe_id
            vuln_dict.fix_suggestion = vuln.pattern.fix_guidance
        result.append(vuln_dict)
    
    return result

@app.patch("/api/vulnerabilities/{detection_id}", response_model=VulnerabilityResponse, tags=["Vulnerabilities"])
async def update_vulnerability(
    detection_id: str,
    update: VulnerabilityUpdate,
    db: Session = Depends(get_db)
):
    """Update vulnerability status"""
    vuln = VulnerabilityDB.update_detection_status(
        db,
        detection_id,
        update.status,
        update.suppression_reason
    )
    
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability not found")
    
    return VulnerabilityResponse.model_validate(vuln)

# Statistics endpoint
@app.get("/api/projects/{project_id}/stats", tags=["Statistics"])
async def get_project_stats(project_id: int, db: Session = Depends(get_db)):
    """Get project vulnerability statistics"""
    stats = VulnerabilityDB.get_vulnerability_stats(db, project_id)
    
    # Add trend data
    recent_scans = db.query(Scan).filter(
        Scan.project_id == project_id
    ).order_by(Scan.start_time.desc()).limit(10).all()
    
    trend = [
        {
            "date": scan.start_time.isoformat(),
            "total": scan.total_vulnerabilities,
            "critical": scan.critical_count
        }
        for scan in recent_scans
    ]
    
    return {
        "current": stats,
        "trend": trend
    }

# Run the API
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host=settings.API_HOST, port=settings.API_PORT)

