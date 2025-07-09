# src/analyzers/pattern_scanner.py - FIXED VERSION
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
            
            # Debug: Print loaded patterns
            for p in self.patterns:
                if p.pattern_id == "SQL-001":
                    print(f"  SQL Pattern loaded: {p.detection_patterns}")
                    
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
        
        print(f"  Checking {len(relevant_patterns)} patterns for {language}")
        
        # Split code into lines for line number tracking
        lines = code.split('\n')
        
        for pattern in relevant_patterns:
            # Get regex patterns for this language
            regex_patterns = pattern.detection_patterns.get(language, [])
            
            # Debug SQL pattern
            if pattern.pattern_id == "SQL-001":
                print(f"  SQL regex patterns for {language}: {regex_patterns}")
            
            for regex_pattern in regex_patterns:
                try:
                    # Fix regex pattern - ensure it's properly escaped
                    # Don't use raw strings, use proper escaping
                    if '\\(' in regex_pattern and not '\\\\(' in regex_pattern:
                        regex_pattern = regex_pattern.replace('\\(', '\\\\(')
                        regex_pattern = regex_pattern.replace('\\)', '\\\\)')
                    
                    # Compile regex
                    regex = re.compile(regex_pattern, re.IGNORECASE)
                    
                    # Search through code line by line
                    for line_num, line in enumerate(lines, 1):
                        if regex.search(line):
                            # Debug match
                            if pattern.pattern_id == "SQL-001":
                                print(f"  SQL pattern matched on line {line_num}: {line.strip()}")
                            
                            # Calculate confidence
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
                                print(f"  Added vulnerability: {vuln.name} at line {line_num}")
                                
                except re.error as e:
                    print(f"Invalid regex pattern: {regex_pattern} - {e}")
        
        print(f"  Pattern scanner found {len(vulnerabilities)} vulnerabilities")
        return vulnerabilities
    
    def _calculate_confidence(self, line: str, pattern: str, vuln_pattern: VulnerabilityPattern) -> float:
        """Calculate confidence score for a match"""
        base_confidence = 0.8  # Increased base confidence
        
        # Increase confidence for exact pattern matches
        if "+" in line and ("WHERE" in line.upper() or "SELECT" in line.upper()):
            base_confidence += 0.15
        
        # Increase confidence for critical vulnerabilities
        if vuln_pattern.severity == 'critical':
            base_confidence += 0.05
        
        # Decrease confidence for comments
        if any(line.strip().startswith(comment) for comment in ['//', '#', '/*', '*']):
            base_confidence -= 0.4
        
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