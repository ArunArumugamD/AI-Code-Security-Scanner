# src/api/models.py
from pydantic import BaseModel, Field, ConfigDict
from typing import List, Optional, Dict, Any
from datetime import datetime
from enum import Enum

class SeverityEnum(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"

class ScanTypeEnum(str, Enum):
    full = "full"
    incremental = "incremental"
    realtime = "realtime"

# Request Models
class ProjectCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    description: Optional[str] = None
    repository_url: Optional[str] = None
    languages: List[str] = []

class ProjectUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=200)
    description: Optional[str] = None
    repository_url: Optional[str] = None
    languages: Optional[List[str]] = None
    active: Optional[bool] = None

class ScanRequest(BaseModel):
    project_id: int
    scan_type: ScanTypeEnum = ScanTypeEnum.full
    target_path: Optional[str] = None
    file_extensions: List[str] = ['.py', '.js', '.java', '.php', '.c', '.cpp']

class CodeScanRequest(BaseModel):
    code: str = Field(..., min_length=1)
    language: str = Field(..., min_length=1, max_length=20)
    filename: Optional[str] = "api_scan.tmp"

class VulnerabilityUpdate(BaseModel):
    status: str = Field(..., pattern="^(open|confirmed|false_positive|fixed)$")
    suppression_reason: Optional[str] = None

# Response Models
class ProjectResponse(BaseModel):
    id: int
    name: str
    description: Optional[str]
    repository_url: Optional[str]
    languages: List[str]
    security_score: Optional[float]
    last_scan_date: Optional[datetime]
    created_at: datetime
    active: bool
    
    model_config = ConfigDict(from_attributes=True)

class VulnerabilityResponse(BaseModel):
    id: int
    detection_id: str
    file_path: str
    line_start: int
    line_end: int
    severity: str
    confidence_score: float
    pattern_id: Optional[int]
    name: Optional[str]
    description: Optional[str]
    code_snippet: Optional[str]
    ai_explanation: Optional[str]
    cwe_id: Optional[str]
    fix_suggestion: Optional[str]
    status: str
    detected_at: datetime
    
    model_config = ConfigDict(from_attributes=True)

class ScanResponse(BaseModel):
    id: int
    scan_id: str
    project_id: int
    scan_type: str
    start_time: datetime
    end_time: Optional[datetime]
    files_scanned: int
    lines_scanned: int
    total_vulnerabilities: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    
    model_config = ConfigDict(from_attributes=True)

class ScanResultResponse(BaseModel):
    scan: ScanResponse
    vulnerabilities: List[VulnerabilityResponse]
    summary: Dict[str, int]

class QuickScanResponse(BaseModel):
    vulnerabilities: List[Dict[str, Any]]
    summary: Dict[str, int]
    scan_time: float

class HealthResponse(BaseModel):
    status: str
    version: str
    database: bool
    analyzers: int
    patterns_loaded: int

class ErrorResponse(BaseModel):
    detail: str
    error_code: Optional[str] = None
