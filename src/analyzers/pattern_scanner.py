# src/analyzers/pattern_scanner.py
import re
import asyncio
from typing import List, Dict, Tuple
from src.core.base_scanner import BaseAnalyzer, Vulnerability, Severity
from src.database.models.base import SessionLocal
from src.database.models.vulnerability import VulnerabilityPattern
from src.core.language_detector import LanguageDetector

class PatternBasedScanner(BaseAnalyzer):
    """Scanner that uses regex patterns from the vulnerability database"""
    
    def __init__(self):
        super().__init__(
            name="Pattern-Based Vulnerability Scanner",
            supported_languages=['python', 'javascript', 'java', 'php', 'c', 'cpp']
        )
        self._load_patterns()
    
    def _load_patterns(self):
        """Load vulnerability patterns from database"""
        db = SessionLocal()
        try:
            self.patterns = db.query(VulnerabilityPattern).all()
            print(f"✓ Loaded {len(self.patterns)} vulnerability patterns from database")
        finally:
            db.close()
    
    async def analyze(self, code: str, language: str, file_path: str) -> List[Vulnerability]:
        """Analyze code using regex patterns"""
        vulnerabilities = []
        
        # Get patterns for this language
        relevant_patterns = [
            p for p in self.patterns 
            if language in p.languages
        ]
        
        # Split code into lines for line number tracking
        lines = code.split('\n')
        
        for pattern in relevant_patterns:
            # Get regex patterns for this language
            regex_patterns = pattern.detection_patterns.get(language, [])
            
            for regex_pattern in regex_patterns:
                try:
                    # Compile regex with case-insensitive flag
                    regex = re.compile(regex_pattern, re.IGNORECASE | re.MULTILINE)
                    
                    # Search through code
                    for line_num, line in enumerate(lines, 1):
                        if regex.search(line):
                            # Calculate confidence based on pattern match strength
                            confidence = self._calculate_confidence(
                                line, regex_pattern, pattern
                            )
                            
                            if confidence >= pattern.confidence_threshold:
                                vuln = Vulnerability(
                                    id=f"{pattern.pattern_id}-{file_path}-{line_num}",
                                    name=pattern.name,
                                    description=pattern.description,
                                    severity=self._map_severity(pattern.severity),
                                    confidence=confidence,
                                    file_path=file_path,
                                    line_start=line_num,
                                    line_end=line_num,
                                    code_snippet=line.strip(),
                                    cwe_id=pattern.cwe_id,
                                    fix_suggestion=self._get_fix_suggestion(pattern, language)
                                )
                                vulnerabilities.append(vuln)
                                
                except re.error as e:
                    print(f"Invalid regex pattern: {regex_pattern} - {e}")
        
        return vulnerabilities
    
    def _calculate_confidence(self, line: str, pattern: str, vuln_pattern: VulnerabilityPattern) -> float:
        """Calculate confidence score for a match"""
        base_confidence = 0.7
        
        # Increase confidence for exact pattern matches
        if pattern in line:
            base_confidence += 0.2
        
        # Increase confidence for critical vulnerabilities
        if vuln_pattern.severity == 'critical':
            base_confidence += 0.1
        
        # Decrease confidence for comments
        if any(line.strip().startswith(comment) for comment in ['//', '#', '/*', '*']):
            base_confidence -= 0.3
        
        return min(base_confidence, 1.0)
    
    def _map_severity(self, severity_str: str) -> Severity:
        """Map string severity to enum"""
        mapping = {
            'critical': Severity.CRITICAL,
            'high': Severity.HIGH,
            'medium': Severity.MEDIUM,
            'low': Severity.LOW,
            'info': Severity.INFO
        }
        return mapping.get(severity_str.lower(), Severity.MEDIUM)
    
    def _get_fix_suggestion(self, pattern: VulnerabilityPattern, language: str) -> str:
        """Get fix suggestion for the vulnerability"""
        if pattern.secure_alternatives and language in pattern.secure_alternatives:
            return f"{pattern.fix_guidance}\n\nExample: {pattern.secure_alternatives[language]}"
        return pattern.fix_guidance
