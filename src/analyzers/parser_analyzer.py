# src/analyzers/parser_analyzer.py
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
        
        for pattern in patterns:
            vuln = Vulnerability(
                id=f"PARSE-{language.upper()}-{pattern['line']:04d}",
                name=f"Unsafe {pattern['pattern']} usage",
                description=pattern['risk'],
                severity=Severity.HIGH if pattern['severity'] == 'high' else Severity.MEDIUM,
                confidence=0.9,  # High confidence for direct pattern match
                file_path=file_path,
                line_start=pattern['line'],
                line_end=pattern['line'],
                code_snippet=pattern['code'],
                fix_suggestion=self._get_fix_suggestion(pattern['pattern'], language)
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
        
        return vulnerabilities
    
    def _get_fix_suggestion(self, pattern: str, language: str) -> str:
        """Get fix suggestion for common patterns"""
        suggestions = {
            'eval': 'Use ast.literal_eval() for Python or JSON.parse() for JavaScript',
            'exec': 'Avoid dynamic code execution. Use predefined functions instead',
            'innerHTML': 'Use textContent or sanitize input with DOMPurify',
            'strcpy': 'Use strncpy() or snprintf() with bounds checking',
            'gets': 'Use fgets() with buffer size limit',
            'system': 'Use subprocess with shell=False or execve() family functions'
        }
        return suggestions.get(pattern, "Review and sanitize all user inputs")
