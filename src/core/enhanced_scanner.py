# src/core/enhanced_scanner.py
from typing import List, Dict, Optional, Tuple
from src.core.base_scanner import Vulnerability, ScannerEngine
from src.core.confidence_scorer import ConfidenceScorer, ConfidenceScore
from src.core.code_parser import UniversalCodeParser

class EnhancedVulnerabilityScanner:
    """Scanner with advanced confidence scoring integration"""
    
    def __init__(self):
        self.scanner_engine = ScannerEngine()
        self.confidence_scorer = ConfidenceScorer()
        self.code_parser = UniversalCodeParser()
        
        # Track detection methods used
        self.detection_methods = {}
        
    async def scan_with_confidence(self, code: str, language: str, 
                                  file_path: str) -> List[Dict]:
        """Scan code and calculate detailed confidence scores"""
        
        # Run all analyzers
        vulnerabilities = await self.scanner_engine.scan_code(code, language, file_path)
        
        # Parse code for context
        ast = self.code_parser.parse(code, language)
        code_context = self._extract_code_context(code, ast, language)
        
        # Enhance each vulnerability with confidence scoring
        enhanced_results = []
        
        for vuln in vulnerabilities:
            # Collect detection methods for this vulnerability
            detection_methods = self._get_detection_methods(vuln)
            
            # Calculate comprehensive confidence score
            confidence_score = self.confidence_scorer.calculate_confidence(
                vulnerability_type=vuln.name,
                detection_methods=detection_methods,
                code_context=code_context,
                file_path=file_path
            )
            
            # Create enhanced result
            enhanced_vuln = {
                "vulnerability": vuln,
                "confidence_analysis": confidence_score,
                "detection_methods": detection_methods,
                "context": code_context
            }
            
            enhanced_results.append(enhanced_vuln)
        
        # Sort by confidence
        enhanced_results.sort(
            key=lambda x: x["confidence_analysis"].overall_confidence,
            reverse=True
        )
        
        return enhanced_results
    
    def _extract_code_context(self, code: str, ast, language: str) -> Dict:
        """Extract context information from code"""
        lines = code.split('\n')
        
        context = {
            "lines_of_code": len(lines),
            "has_user_input": any(
                term in code.lower() 
                for term in ['request', 'input', 'user', 'param', 'arg']
            ),
            "has_validation": any(
                term in code 
                for term in ['validate', 'sanitize', 'escape', 'filter', 'check']
            ),
            "in_comment": False,  # Would need more sophisticated check
            "cyclomatic_complexity": self._estimate_complexity(ast),
            "has_error_handling": any(
                term in code 
                for term in ['try:', 'except:', 'catch', 'finally:']
            )
        }
        
        return context
    
    def _estimate_complexity(self, ast) -> int:
        """Estimate cyclomatic complexity from AST"""
        if not ast:
            return 1
        
        complexity = 1
        
        def count_decision_points(node):
            nonlocal complexity
            if node.type in ['if_statement', 'while_statement', 'for_statement', 
                           'case', 'catch', 'conditional_expression']:
                complexity += 1
            
            for child in node.children:
                count_decision_points(child)
        
        count_decision_points(ast)
        return complexity
    
    def _get_detection_methods(self, vuln: Vulnerability) -> List[Tuple[str, float]]:
        """Extract detection methods used for this vulnerability"""
        methods = []
        
        # Determine which analyzer found this
        vuln_id = vuln.id
        
        if "PATTERN" in vuln_id or "PARSE" in vuln_id:
            methods.append(("pattern", vuln.confidence))
        
        if "AST" in vuln_id or "PARSE" in vuln_id:
            methods.append(("ast", vuln.confidence))
        
        if "AI-" in vuln_id:
            methods.append(("codebert", vuln.confidence))
        
        if "GNN" in vuln_id:
            methods.append(("gnn", vuln.confidence))
        
        if "HYBRID" in vuln_id:
            methods.append(("hybrid", vuln.confidence))
            # Also extract component scores if available
            if hasattr(vuln, 'ai_metadata'):
                if 'gnn_score' in vuln.ai_metadata:
                    methods.append(("gnn", vuln.ai_metadata['gnn_score']))
                if 'codebert_score' in vuln.ai_metadata:
                    methods.append(("codebert", vuln.ai_metadata['codebert_score']))
        
        # Default if no specific method identified
        if not methods:
            methods.append(("unknown", vuln.confidence))
        
        return methods
    
    def generate_confidence_report(self, results: List[Dict]) -> str:
        """Generate a confidence analysis report"""
        report = "🔍 Vulnerability Confidence Analysis Report\n"
        report += "=" * 50 + "\n\n"
        
        if not results:
            report += "No vulnerabilities detected.\n"
            return report
        
        # Overall statistics
        high_confidence = sum(1 for r in results 
                            if r["confidence_analysis"].overall_confidence > 0.8)
        medium_confidence = sum(1 for r in results 
                              if 0.5 < r["confidence_analysis"].overall_confidence <= 0.8)
        low_confidence = sum(1 for r in results 
                           if r["confidence_analysis"].overall_confidence <= 0.5)
        
        report += f"Total Vulnerabilities: {len(results)}\n"
        report += f"  • High Confidence: {high_confidence}\n"
        report += f"  • Medium Confidence: {medium_confidence}\n"
        report += f"  • Low Confidence: {low_confidence}\n\n"
        
        # Detailed analysis
        report += "Detailed Findings:\n"
        report += "-" * 50 + "\n"
        
        for i, result in enumerate(results, 1):
            vuln = result["vulnerability"]
            conf = result["confidence_analysis"]
            
            report += f"\n{i}. {vuln.name}\n"
            report += f"   Location: {vuln.file_path}:{vuln.line_start}\n"
            report += f"   Severity: {vuln.severity.value}\n"
            report += f"   Overall Confidence: {conf.overall_confidence:.1%} ({conf.reliability_rating})\n"
            
            report += "   Detection Methods:\n"
            for method, score in result["detection_methods"]:
                report += f"     • {method}: {score:.1%}\n"
            
            report += "   Confidence Breakdown:\n"
            for factor, score in conf.factors.items():
                report += f"     • {factor}: {score:.1%}\n"
            
            report += f"   Explanation: {conf.explanation.split('.')[0]}.\n"
        
        return report

