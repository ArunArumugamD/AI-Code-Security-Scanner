# src/analyzers/parser_analyzer.py - FIXED VERSION
from typing import List
import asyncio
from src.core.base_scanner import BaseAnalyzer, Vulnerability, Severity
from src.core.code_parser import UniversalCodeParser
from src.core.language_detector import LanguageDetector

class ParserBasedAnalyzer(BaseAnalyzer):
    """Security analyzer using AST parsing to find vulnerabilities"""
    
    def __init__(self):
        super().__init__(
            name="AST Parser Analyzer",
            supported_languages=['python', 'javascript', 'java', 'php', 'c', 'cpp']
        )
        self.parser = UniversalCodeParser()
        
    async def analyze(self, code: str, language: str, file_path: str) -> List[Vulnerability]:
        """Analyze code using AST parsing"""
        vulnerabilities = []
        
        # Find security patterns
        patterns = await asyncio.to_thread(
            self.parser.find_security_patterns, code, language
        )
        
        # Debug: show what patterns were found
        print(f"  AST Parser found {len(patterns)} security patterns")
        
        # Filter out false positives
        filtered_patterns = []
        for pattern in patterns:
            # Check if the pattern actually exists in the code
            if pattern['pattern'] in pattern['code']:
                filtered_patterns.append(pattern)
                print(f"    Valid pattern: {pattern['pattern']} at line {pattern['line']}")
            else:
                print(f"    Filtered false positive: {pattern['pattern']} not in code")
        
        for pattern in filtered_patterns:
            vuln = Vulnerability(
                id=f"PARSE-{language.upper()}-{pattern['line']:04d}",
                name=f"{pattern['pattern']} vulnerability",
                description=pattern['risk'],
                severity=Severity.HIGH if pattern['severity'] == 'high' else Severity.MEDIUM,
                confidence=0.85,  # Reduced confidence slightly
                file_path=file_path,
                line_start=pattern['line'],
                line_end=pattern['line'],
                code_snippet=pattern['code'],
                fix_suggestion=self._get_fix_suggestion(pattern['pattern'], language),
                cwe_id=self._get_cwe_for_pattern(pattern['pattern'])
            )
            vulnerabilities.append(vuln)
        
        # Extract functions and check complexity
        functions = await asyncio.to_thread(
            self.parser.extract_functions, code, language
        )
        
        for func in functions:
            if func.complexity > 10:  # High complexity threshold
                vuln = Vulnerability(
                    id=f"COMPLEX-{func.name}-{func.start_line}",
                    name=f"High complexity in {func.name}",
                    description=f"Function has cyclomatic complexity of {func.complexity}",
                    severity=Severity.LOW,
                    confidence=0.95,
                    file_path=file_path,
                    line_start=func.start_line,
                    line_end=func.end_line,
                    code_snippet=func.body[:200] + "..." if len(func.body) > 200 else func.body,
                    fix_suggestion="Consider breaking this function into smaller, more focused functions"
                )
                vulnerabilities.append(vuln)
        
        print(f"  AST Parser returning {len(vulnerabilities)} vulnerabilities")
        return vulnerabilities
    
    def _get_fix_suggestion(self, pattern: str, language: str) -> str:
        """Get fix suggestion for common patterns"""
        suggestions = {
            'eval': 'Use ast.literal_eval() for Python or JSON.parse() for JavaScript',
            'exec': 'Avoid dynamic code execution. Use predefined functions instead',
            'innerHTML': 'Use textContent or sanitize input with DOMPurify',
            'strcpy': 'Use strncpy() or snprintf() with bounds checking',
            'gets': 'Use fgets() with buffer size limit',
            'system': 'Use subprocess with shell=False or execve() family functions',
            'execute': 'Use parameterized queries instead of string concatenation',
            'SELECT': 'Use parameterized queries to prevent SQL injection'
        }
        return suggestions.get(pattern, "Review and sanitize all user inputs")
    
    def _get_cwe_for_pattern(self, pattern: str) -> str:
        """Map patterns to CWE IDs"""
        cwe_map = {
            'eval': 'CWE-95',
            'exec': 'CWE-78',
            'innerHTML': 'CWE-79',
            'system': 'CWE-78',
            'execute': 'CWE-89',
            'SELECT': 'CWE-89'
        }
        return cwe_map.get(pattern, 'CWE-Unknown')