# src/analyzers/pattern_scanner.py - COMPLETE FIXED VERSION
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
    
    def _fix_regex_pattern(self, pattern: str) -> str:
        """Fix common regex pattern issues"""
        # Remove double backslashes before parentheses
        pattern = pattern.replace('\\\\(', r'\(').replace('\\\\)', r'\)')
        pattern = pattern.replace('\\(', r'\(').replace('\\)', r'\)')
        
        # Fix specific problematic patterns
        if pattern == r"os\.system\s*\\(":
            return r"os\.system\s*\("
        elif pattern == r"\beval\s*\\(":
            return r"\beval\s*\("
        elif pattern == r"\bexec\s*\\(":
            return r"\bexec\s*\("
        elif pattern == r"os\.popen\s*\\(":
            return r"os\.popen\s*\("
            
        # Fix subprocess patterns
        if "subprocess" in pattern and "\\(" in pattern:
            pattern = pattern.replace("\\(", r"\(")
            
        return pattern
    
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
                    # Fix the regex pattern
                    fixed_pattern = self._fix_regex_pattern(regex_pattern)
                    
                    # Compile regex
                    regex = re.compile(fixed_pattern, re.IGNORECASE | re.MULTILINE)
                    
                    # Search through code line by line
                    for line_num, line in enumerate(lines, 1):
                        # Skip empty lines and comments
                        stripped_line = line.strip()
                        if not stripped_line:
                            continue
                            
                        # Skip comment lines
                        if language == 'python' and stripped_line.startswith('#'):
                            continue
                        if language in ['javascript', 'java', 'c', 'cpp'] and stripped_line.startswith('//'):
                            continue
                            
                        # Search for pattern
                        if regex.search(line):
                            # Debug match
                            if pattern.pattern_id in ["SQL-001", "CMD-001", "EVAL-001", "EXEC-001"]:
                                print(f"  {pattern.pattern_id} matched on line {line_num}: {line.strip()}")
                            
                            # Calculate confidence
                            confidence = self._calculate_confidence(
                                line, fixed_pattern, pattern
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
                                # Don't break - continue checking other lines
                                
                except re.error as e:
                    print(f"Regex error for pattern '{regex_pattern}': {e}")
                    # Try a simpler pattern
                    try:
                        # For os.system, eval, exec - just look for the function name
                        if "os.system" in regex_pattern:
                            simple_regex = re.compile(r"os\.system\s*\(", re.IGNORECASE)
                            for line_num, line in enumerate(lines, 1):
                                if simple_regex.search(line):
                                    vuln = Vulnerability(
                                        id=f"OSYS-001-{file_path}-{line_num}",
                                        name="Unsafe os.system usage",
                                        description="os.system is unsafe for executing system commands",
                                        severity=Severity.HIGH,
                                        confidence=0.9,
                                        file_path=file_path,
                                        line_start=line_num,
                                        line_end=line_num,
                                        code_snippet=line.strip(),
                                        cwe_id="CWE-78",
                                        fix_suggestion="Use subprocess.run with shell=False instead"
                                    )
                                    vulnerabilities.append(vuln)
                                    print(f"  Added os.system vulnerability at line {line_num}")
                                    
                        elif "eval" in regex_pattern and "\\b" in regex_pattern:
                            simple_regex = re.compile(r"\beval\s*\(", re.IGNORECASE)
                            for line_num, line in enumerate(lines, 1):
                                if simple_regex.search(line):
                                    vuln = Vulnerability(
                                        id=f"EVAL-001-{file_path}-{line_num}",
                                        name="Unsafe eval usage",
                                        description="eval() can execute arbitrary code",
                                        severity=Severity.HIGH,
                                        confidence=0.9,
                                        file_path=file_path,
                                        line_start=line_num,
                                        line_end=line_num,
                                        code_snippet=line.strip(),
                                        cwe_id="CWE-94",
                                        fix_suggestion="Use ast.literal_eval() or JSON.parse() instead"
                                    )
                                    vulnerabilities.append(vuln)
                                    print(f"  Added eval vulnerability at line {line_num}")
                                    
                        elif "exec" in regex_pattern and "\\b" in regex_pattern:
                            simple_regex = re.compile(r"\bexec\s*\(", re.IGNORECASE)
                            for line_num, line in enumerate(lines, 1):
                                if simple_regex.search(line):
                                    vuln = Vulnerability(
                                        id=f"EXEC-001-{file_path}-{line_num}",
                                        name="Unsafe exec usage",
                                        description="exec() can execute arbitrary Python code",
                                        severity=Severity.HIGH,
                                        confidence=0.9,
                                        file_path=file_path,
                                        line_start=line_num,
                                        line_end=line_num,
                                        code_snippet=line.strip(),
                                        cwe_id="CWE-94",
                                        fix_suggestion="Avoid exec() or strictly validate input"
                                    )
                                    vulnerabilities.append(vuln)
                                    print(f"  Added exec vulnerability at line {line_num}")
                    except:
                        pass
        
        print(f"  Pattern scanner found {len(vulnerabilities)} vulnerabilities")
        return vulnerabilities
    
    def _calculate_confidence(self, line: str, pattern: str, vuln_pattern: VulnerabilityPattern) -> float:
        """Calculate confidence score for a match"""
        base_confidence = 0.8
        
        # Increase confidence for exact pattern matches
        if "+" in line and ("WHERE" in line.upper() or "SELECT" in line.upper()):
            base_confidence += 0.15
        
        # Increase confidence for f-strings with SQL
        if "f\"" in line or "f'" in line:
            if any(sql in line.upper() for sql in ["SELECT", "INSERT", "UPDATE", "DELETE"]):
                base_confidence += 0.1
        
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