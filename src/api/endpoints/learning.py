# src/api/endpoints/learning.py
"""API endpoints for self-learning feedback system"""
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from typing import List, Dict, Optional, Any
from datetime import datetime
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from src.database.models.base import get_db, SessionLocal
from src.database.models.vulnerability import VulnerabilityDetection
from src.ml.self_learning import SelfLearningEngine, LearningEnabledScanner
from src.core.scanner_engine import EnhancedScannerEngine

router = APIRouter(prefix="/api/learning", tags=["Self-Learning"])

# Initialize learning engine
learning_engine = SelfLearningEngine()

# Request/Response models
class FeedbackRequest(BaseModel):
    detection_id: str
    was_correct: bool
    notes: Optional[str] = ""
    
class FeedbackResponse(BaseModel):
    success: bool
    message: str
    accuracy_before: float
    accuracy_after: float
    patterns_learned: int

class LearningMetricsResponse(BaseModel):
    total_feedback: int
    true_positives: int
    false_positives: int
    accuracy: float
    accuracy_improvement: float
    patterns_learned: int
    confidence_adjustments: Dict[str, float]
    
class PatternSuggestion(BaseModel):
    type: str
    pattern: str
    confidence: float
    confirmations: int
    description: str

class BatchFeedbackRequest(BaseModel):
    feedbacks: List[FeedbackRequest]

@router.post("/feedback", response_model=FeedbackResponse)
async def submit_feedback(
    request: FeedbackRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    """Submit feedback on a vulnerability detection"""
    # Get detection from database
    detection = db.query(VulnerabilityDetection).filter(
        VulnerabilityDetection.detection_id == request.detection_id
    ).first()
    
    if not detection:
        raise HTTPException(status_code=404, detail="Detection not found")
    
    # Calculate accuracy before feedback
    metrics_before = learning_engine.export_learning_report()
    accuracy_before = (
        metrics_before.true_positives / metrics_before.total_feedback 
        if metrics_before.total_feedback > 0 else 0.0
    )
    
    # Create vulnerability object for learning
    from src.core.base_scanner import Vulnerability, Severity
    vuln = Vulnerability(
        id=detection.detection_id,
        name=detection.pattern.name if detection.pattern else "Unknown",
        description=detection.pattern.description if detection.pattern else "",
        severity=Severity(detection.severity),
        confidence=detection.confidence_score,
        file_path=detection.file_path,
        line_start=detection.line_start,
        line_end=detection.line_end,
        code_snippet=detection.code_snippet or ""
    )
    
    # Record feedback
    record = learning_engine.record_feedback(
        vuln,
        request.was_correct,
        request.notes,
        "pattern"  # TODO: Get actual detection method
    )
    
    # Update database
    detection.verified_by_user = True
    detection.status = 'confirmed' if request.was_correct else 'false_positive'
    if not request.was_correct:
        detection.suppressed = True
        detection.suppression_reason = f"User feedback: {request.notes}"
    db.commit()
    
    # Calculate accuracy after feedback
    metrics_after = learning_engine.export_learning_report()
    accuracy_after = (
        metrics_after.true_positives / metrics_after.total_feedback
        if metrics_after.total_feedback > 0 else 0.0
    )
    
    # Background task to retrain if needed
    if metrics_after.total_feedback % 50 == 0:
        background_tasks.add_task(retrain_models)
    
    return FeedbackResponse(
        success=True,
        message=f"Feedback recorded. The detection was marked as {'correct' if request.was_correct else 'false positive'}.",
        accuracy_before=accuracy_before,
        accuracy_after=accuracy_after,
        patterns_learned=metrics_after.patterns_learned
    )

@router.post("/feedback/batch", response_model=Dict[str, Any])
async def submit_batch_feedback(
    request: BatchFeedbackRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    """Submit feedback for multiple detections at once"""
    results = []
    successful = 0
    failed = 0
    
    for feedback in request.feedbacks:
        try:
            # Process each feedback
            result = await submit_feedback(
                feedback,
                background_tasks,
                db
            )
            results.append({
                "detection_id": feedback.detection_id,
                "success": True
            })
            successful += 1
        except Exception as e:
            results.append({
                "detection_id": feedback.detection_id,
                "success": False,
                "error": str(e)
            })
            failed += 1
    
    return {
        "total": len(request.feedbacks),
        "successful": successful,
        "failed": failed,
        "results": results
    }

@router.get("/metrics", response_model=LearningMetricsResponse)
async def get_learning_metrics():
    """Get current learning system metrics"""
    metrics = learning_engine.export_learning_report()
    
    accuracy = (
        metrics.true_positives / metrics.total_feedback
        if metrics.total_feedback > 0 else 0.0
    )
    
    return LearningMetricsResponse(
        total_feedback=metrics.total_feedback,
        true_positives=metrics.true_positives,
        false_positives=metrics.false_positives,
        accuracy=accuracy,
        accuracy_improvement=metrics.accuracy_improvement,
        patterns_learned=metrics.patterns_learned,
        confidence_adjustments=metrics.confidence_adjustments
    )

@router.get("/patterns/suggestions", response_model=List[PatternSuggestion])
async def get_pattern_suggestions():
    """Get suggested new patterns based on learning"""
    suggestions = learning_engine.suggest_new_patterns()
    
    return [
        PatternSuggestion(
            type=s['type'],
            pattern=s['pattern'],
            confidence=s['confidence'],
            confirmations=s['confirmations'],
            description=s['description']
        )
        for s in suggestions
    ]

@router.post("/patterns/approve/{pattern_index}")
async def approve_pattern_suggestion(
    pattern_index: int,
    db: Session = Depends(get_db)
):
    """Approve a suggested pattern and add it to the database"""
    suggestions = learning_engine.suggest_new_patterns()
    
    if pattern_index >= len(suggestions):
        raise HTTPException(status_code=404, detail="Pattern suggestion not found")
    
    suggestion = suggestions[pattern_index]
    
    # Create new vulnerability pattern
    from src.database.models.vulnerability import VulnerabilityPattern
    import uuid
    
    new_pattern = VulnerabilityPattern(
        pattern_id=f"LEARNED-{uuid.uuid4().hex[:8]}",
        name=f"Learned {suggestion['type']} Pattern",
        description=f"Pattern learned from {suggestion['confirmations']} confirmed detections",
        severity="high",  # Default, should be customized
        languages=["python", "javascript"],  # Should detect from examples
        detection_patterns={
            "python": [suggestion['pattern']],
            "javascript": [suggestion['pattern']]
        },
        confidence_threshold=0.7 + suggestion['confidence'],
        fix_guidance="Review and fix this vulnerability pattern",
        created_at=datetime.utcnow()
    )
    
    db.add(new_pattern)
    db.commit()
    
    return {
        "success": True,
        "pattern_id": new_pattern.pattern_id,
        "message": "Pattern approved and added to knowledge base"
    }

@router.get("/confidence/adjustments")
async def get_confidence_adjustments():
    """Get current confidence adjustment factors"""
    return {
        "adjustments": learning_engine.confidence_adjustments,
        "explanation": "Values > 1.0 boost confidence, < 1.0 reduce confidence"
    }

@router.post("/retrain")
async def trigger_retrain(background_tasks: BackgroundTasks):
    """Manually trigger model retraining"""
    background_tasks.add_task(retrain_models)
    
    return {
        "success": True,
        "message": "Retraining initiated in background"
    }

# Background tasks
async def retrain_models():
    """Background task to retrain models"""
    print("🔄 Starting model retraining...")
    
    # This would trigger retraining of:
    # 1. Pattern classifier
    # 2. Confidence adjustment models
    # 3. Update CodeBERT embeddings cache
    
    # For now, just retrain pattern classifier
    learning_engine._retrain_pattern_classifier()
    
    print("✓ Model retraining completed")


# Update main.py to include learning endpoints
def register_learning_routes(app):
    """Register learning routes with the main app"""
    app.include_router(router)