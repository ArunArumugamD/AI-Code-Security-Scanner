# src/core/base_scanner.py
from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from enum import Enum
import asyncio
from datetime import datetime

class Severity(Enum):
    """Vulnerability severity levels matching CVE standards"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

@dataclass
class Vulnerability:
    """Core vulnerability data structure"""
    id: str
    name: str
    description: str
    severity: Severity
    confidence: float  # 0.0 to 1.0
    file_path: str
    line_start: int
    line_end: int
    code_snippet: str
    cwe_id: Optional[str] = None
    cve_id: Optional[str] = None
    fix_suggestion: Optional[str] = None
    ai_explanation: Optional[str] = None
    detected_at: datetime = None
    
    def __post_init__(self):
        if self.detected_at is None:
            self.detected_at = datetime.utcnow()

class BaseAnalyzer(ABC):
    """Abstract base class for all security analyzers"""
    
    def __init__(self, name: str, supported_languages: List[str]):
        self.name = name
        self.supported_languages = supported_languages
        self.is_ai_powered = False
        
    @abstractmethod
    async def analyze(self, code: str, language: str, file_path: str) -> List[Vulnerability]:
        """Analyze code and return vulnerabilities"""
        pass
    
    def supports_language(self, language: str) -> bool:
        """Check if analyzer supports the given language"""
        return language.lower() in self.supported_languages

class ScannerEngine:
    """Main orchestrator for all analyzers"""
    
    def __init__(self):
        self.analyzers: List[BaseAnalyzer] = []
        self.real_time_callbacks = []
        
    def register_analyzer(self, analyzer: BaseAnalyzer):
        """Register a new analyzer"""
        self.analyzers.append(analyzer)
        print(f"Registered analyzer: {analyzer.name}")
        
    async def scan_code(self, code: str, language: str, file_path: str) -> List[Vulnerability]:
        """Run all applicable analyzers on code"""
        vulnerabilities = []
        
        # Get applicable analyzers
        applicable_analyzers = [
            a for a in self.analyzers 
            if a.supports_language(language)
        ]
        
        # Run analyzers concurrently
        tasks = [
            analyzer.analyze(code, language, file_path)
            for analyzer in applicable_analyzers
        ]
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if isinstance(result, list):
                vulnerabilities.extend(result)
            elif isinstance(result, Exception):
                print(f"Analyzer error: {result}")
                
        # Deduplicate vulnerabilities
        seen = set()
        unique_vulns = []
        for vuln in vulnerabilities:
            key = (vuln.file_path, vuln.line_start, vuln.name)
            if key not in seen:
                seen.add(key)
                unique_vulns.append(vuln)
                
        return unique_vulns
