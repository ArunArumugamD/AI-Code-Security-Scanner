# src/distributed/tasks.py
"""
Distributed scanning tasks using Celery
Shows enterprise-scale architecture for security scanning
"""
from celery import Task, group, chain
from celery_config import app
from typing import List, Dict, Any
import asyncio
import time
import json
from pathlib import Path

# Import existing scanner
from src.core.scanner_engine_no_groq import BasicScannerEngine
from src.core.scanner_engine import quick_scan
from src.database.models.base import SessionLocal
from src.database.models.vulnerability import Project

class ScanTask(Task):
    """Base task with database connection management"""
    _scanner = None
    
    @property
    def scanner(self):
        if self._scanner is None:
            # Initialize scanner once per worker
            db = SessionLocal()
            project = db.query(Project).first()
            if project:
                self._scanner = BasicScannerEngine(project.id)
            db.close()
        return self._scanner

@app.task
def scan_file_task(file_path: str, project_id: int = None) -> Dict[str, Any]:
    """
    Distributed file scanning task
    Can be executed on any worker node
    """
    start_time = time.time()
    
    try:
        # Create event loop for async scanner
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        # Use existing scanner
        scanner = BasicScannerEngine(project_id) if project_id else BasicScannerEngine()
        vulnerabilities = loop.run_until_complete(scanner.scan_file(file_path))
        
        # Convert to serializable format
        results = {
            'file_path': file_path,
            'scan_time': time.time() - start_time,
            'vulnerabilities': [
                {
                    'id': v.id,
                    'name': v.name,
                    'severity': v.severity.value,
                    'confidence': v.confidence,
                    'line_start': v.line_start,
                    'line_end': v.line_end,
                    'description': v.description
                }
                for v in vulnerabilities
            ],
            'vulnerability_count': len(vulnerabilities),
            'worker': 'worker-1'
        }
        
        return results
        
    except Exception as e:
        # Log error and return failure
        return {
            'error': str(e),
            'file_path': file_path,
            'status': 'failed'
        }

@app.task(bind=True)
def scan_directory_task(self, directory: str, extensions: List[str] = None) -> Dict[str, Any]:
    """
    Distributed directory scanning
    Breaks down into parallel file scan tasks
    """
    from pathlib import Path
    
    if extensions is None:
        extensions = ['.py', '.js', '.java', '.php', '.c', '.cpp']
    
    # Find all files
    files_to_scan = []
    for ext in extensions:
        files_to_scan.extend(Path(directory).rglob(f'*{ext}'))
    
    total_files = len(files_to_scan)
    
    # Update progress
    self.update_state(
        state='PROGRESS',
        meta={'current': 0, 'total': total_files, 'status': 'Starting distributed scan'}
    )
    
    # Create parallel tasks using group
    scan_tasks = group(
        scan_file_task.s(str(file_path)) 
        for file_path in files_to_scan
    )
    
    # Execute all tasks in parallel
    job = scan_tasks.apply_async()
    
    # Wait for results with timeout
    results = job.get(timeout=300)  # 5 minute timeout
    
    # Aggregate results
    summary = {
        'directory': directory,
        'total_files': total_files,
        'files_scanned': len(results),
        'total_vulnerabilities': sum(r['vulnerability_count'] for r in results),
        'scan_results': results,
        'workers_used': list(set(r['worker'] for r in results))
    }
    
    return summary

@app.task(bind=True, name='tasks.analyze_vulnerability')
def analyze_vulnerability_task(self, code_snippet: str, language: str, 
                             vuln_type: str = None) -> Dict[str, Any]:
    """
    Distributed AI analysis task
    Heavy AI computation distributed across workers
    """
    try:
        # Import AI models
        from src.ml.codebert_model import CodeBERTManager
        from src.ml.groq_analyzer import GroqCloudAnalyzer
        
        # Initialize AI models (cached per worker)
        if not hasattr(self, '_codebert'):
            self._codebert = CodeBERTManager()
        if not hasattr(self, '_groq'):
            self._groq = GroqCloudAnalyzer()
        
        # Generate embedding
        embedding = self._codebert.get_embedding(code_snippet, language)
        
        # Get Groq analysis if available
        groq_analysis = None
        if self._groq.enabled and vuln_type:
            vuln_info = {
                'type': vuln_type,
                'severity': 'high',
                'confidence': 0.8
            }
            
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            groq_result = loop.run_until_complete(
                self._groq.analyze_vulnerability(code_snippet, vuln_info, language)
            )
            
            groq_analysis = {
                'explanation': groq_result.detailed_explanation,
                'fix': groq_result.fix_recommendation,
                'severity': groq_result.severity_assessment
            }
        
        return {
            'code_analyzed': len(code_snippet),
            'language': language,
            'embedding_generated': True,
            'embedding_shape': embedding.shape,
            'groq_analysis': groq_analysis,
            'worker': self.request.hostname
        }
        
    except Exception as e:
        return {
            'error': str(e),
            'code_analyzed': len(code_snippet),
            'language': language
        }

@app.task(name='tasks.distributed_project_scan')
def distributed_project_scan(project_id: int, parallel_workers: int = 4) -> Dict[str, Any]:
    """
    Full project scan using distributed workers
    Shows enterprise-scale capability
    """
    from src.database.models.base import SessionLocal
    
    db = SessionLocal()
    project = db.query(Project).filter(Project.id == project_id).first()
    
    if not project:
        return {'error': 'Project not found'}
    
    # Scan workflow using chain and group
    workflow = chain(
        # 1. Scan all Python files in parallel
        group(
            scan_directory_task.s('./src', ['.py']),
            scan_directory_task.s('./tests', ['.py'])
        ),
        
        # 2. Aggregate results
        aggregate_results.s(project_id)
    )
    
    result = workflow.apply_async()
    return {
        'project': project.name,
        'task_id': result.id,
        'status': 'Distributed scan started',
        'workers': parallel_workers
    }

@app.task
def aggregate_results(scan_results: List[Dict], project_id: int) -> Dict[str, Any]:
    """Aggregate results from distributed scanning"""
    total_files = sum(r['total_files'] for r in scan_results)
    total_vulns = sum(r['total_vulnerabilities'] for r in scan_results)
    
    # Get unique workers used
    all_workers = set()
    for result in scan_results:
        all_workers.update(result.get('workers_used', []))
    
    return {
        'project_id': project_id,
        'total_files_scanned': total_files,
        'total_vulnerabilities': total_vulns,
        'distributed_workers': list(all_workers),
        'scan_results': scan_results
    }