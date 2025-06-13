# src/database/operations_fix.py
from typing import List, Optional, Dict, Any
from sqlalchemy.orm import Session
from sqlalchemy import and_, or_, func, Integer  # Add Integer import
from datetime import datetime, timedelta
import json
import uuid
from src.database.models.vulnerability import (
    VulnerabilityPattern, VulnerabilityDetection, 
    Scan, Project, CVEIntelligence
)

class VulnerabilityDB:
    """Database operations for vulnerability management"""
    
    @staticmethod
    def create_project(db: Session, name: str, **kwargs) -> Project:
        """Create a new project"""
        project = Project(
            name=name,
            description=kwargs.get('description', ''),
            repository_url=kwargs.get('repository_url', ''),
            languages=kwargs.get('languages', [])
        )
        db.add(project)
        db.commit()
        db.refresh(project)
        return project
    
    @staticmethod
    def create_scan(db: Session, project_id: int, scan_type: str = 'full') -> Scan:
        """Create a new scan record"""
        scan = Scan(
            scan_id=f"SCAN-{uuid.uuid4().hex[:8]}",
            project_id=project_id,
            scan_type=scan_type,
            start_time=datetime.utcnow()
        )
        db.add(scan)
        db.commit()
        db.refresh(scan)
        return scan
    
    @staticmethod
    def record_detection(db: Session, scan_id: int, detection_data: Dict[str, Any]) -> VulnerabilityDetection:
        """Record a vulnerability detection"""
        detection = VulnerabilityDetection(
            detection_id=f"DET-{uuid.uuid4().hex[:8]}",
            scan_id=scan_id,
            file_path=detection_data['file_path'],
            line_start=detection_data['line_start'],
            line_end=detection_data['line_end'],
            code_snippet=detection_data.get('code_snippet', ''),
            severity=detection_data['severity'],
            confidence_score=detection_data['confidence_score'],
            ai_explanation=detection_data.get('ai_explanation'),
            project_id=detection_data.get('project_id')
        )
        db.add(detection)
        db.commit()
        db.refresh(detection)
        return detection
    
    @staticmethod
    def get_project_vulnerabilities(db: Session, project_id: int, 
                                  status: Optional[str] = None,
                                  severity: Optional[str] = None) -> List[VulnerabilityDetection]:
        """Get vulnerabilities for a project with filters"""
        query = db.query(VulnerabilityDetection).filter(
            VulnerabilityDetection.project_id == project_id
        )
        
        if status:
            query = query.filter(VulnerabilityDetection.status == status)
        if severity:
            query = query.filter(VulnerabilityDetection.severity == severity)
            
        return query.order_by(VulnerabilityDetection.detected_at.desc()).all()
    
    @staticmethod
    def get_vulnerability_stats(db: Session, project_id: int) -> Dict[str, Any]:
        """Get vulnerability statistics for a project"""
        # Fixed version using SQLAlchemy's Integer type
        stats = db.query(
            func.count(VulnerabilityDetection.id).label('total'),
            func.sum(func.cast(VulnerabilityDetection.severity == 'critical', Integer)).label('critical'),
            func.sum(func.cast(VulnerabilityDetection.severity == 'high', Integer)).label('high'),
            func.sum(func.cast(VulnerabilityDetection.severity == 'medium', Integer)).label('medium'),
            func.sum(func.cast(VulnerabilityDetection.severity == 'low', Integer)).label('low'),
            func.avg(VulnerabilityDetection.confidence_score).label('avg_confidence')
        ).filter(
            VulnerabilityDetection.project_id == project_id,
            VulnerabilityDetection.status == 'open'
        ).first()
        
        return {
            'total': stats.total or 0,
            'critical': stats.critical or 0,
            'high': stats.high or 0,
            'medium': stats.medium or 0,
            'low': stats.low or 0,
            'average_confidence': float(stats.avg_confidence or 0)
        }
    
    @staticmethod
    def search_patterns(db: Session, language: str = None, 
                       severity: str = None) -> List[VulnerabilityPattern]:
        """Search vulnerability patterns"""
        query = db.query(VulnerabilityPattern)
        
        if language:
            query = query.filter(
                VulnerabilityPattern.languages.contains([language])
            )
        if severity:
            query = query.filter(VulnerabilityPattern.severity == severity)
            
        return query.all()
    
    @staticmethod
    def update_detection_status(db: Session, detection_id: str, 
                              status: str, reason: str = None) -> VulnerabilityDetection:
        """Update detection status (confirm, false positive, etc)"""
        detection = db.query(VulnerabilityDetection).filter(
            VulnerabilityDetection.detection_id == detection_id
        ).first()
        
        if detection:
            detection.status = status
            detection.verified_by_user = True
            if status == 'false_positive':
                detection.suppressed = True
                detection.suppression_reason = reason
            elif status == 'fixed':
                detection.resolved_at = datetime.utcnow()
                
            db.commit()
            db.refresh(detection)
            
        return detection
