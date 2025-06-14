# src/analyzers/hybrid_analyzer.py
from typing import List, Optional
import asyncio
from src.core.base_scanner import BaseAnalyzer, Vulnerability, Severity
from src.ml.hybrid_model import HybridAnalysisEngine

class HybridAIAnalyzer(BaseAnalyzer):
    """Ultimate analyzer combining GNN and CodeBERT for maximum accuracy"""
    
    def __init__(self):
        super().__init__(
            name="Hybrid AI Analyzer (GNN + CodeBERT)",
            supported_languages=['python', 'javascript', 'java']
        )
        self.is_ai_powered = True
        
        try:
            self.hybrid_engine = HybridAnalysisEngine()
            self.enabled = True
            print("✓ Hybrid AI Analyzer initialized (GNN + CodeBERT)")
        except Exception as e:
            print(f"⚠ Hybrid analyzer disabled: {e}")
            self.enabled = False
            self.hybrid_engine = None
    
    async def analyze(self, code: str, language: str, file_path: str) -> List[Vulnerability]:
        """Analyze code using hybrid AI model"""
        if not self.enabled or not self.hybrid_engine:
            return []
        
        vulnerabilities = []
        
        try:
            # Run hybrid analysis
            prediction = await asyncio.to_thread(
                self.hybrid_engine.analyze, code, language
            )
            
            # Only report if confidence is high enough
            if prediction.vulnerability_score > 0.4 and prediction.confidence > 0.4:
                # Determine severity based on type and scores
                severity = self._calculate_severity(
                    prediction.vulnerability_type,
                    prediction.vulnerability_score,
                    prediction.confidence
                )
                
                # Find specific location (simplified - could be enhanced)
                suspicious_lines = self._identify_vulnerable_lines(
                    code, prediction.vulnerability_type
                )
                
                vuln = Vulnerability(
                    id=f"HYBRID-{file_path}-{prediction.vulnerability_type.replace(' ', '_')}",
                    name=f"Hybrid AI: {prediction.vulnerability_type}",
                    description=f"Advanced AI analysis detected {prediction.vulnerability_type} with high confidence",
                    severity=severity,
                    confidence=prediction.confidence,
                    file_path=file_path,
                    line_start=suspicious_lines[0] if suspicious_lines else 1,
                    line_end=suspicious_lines[-1] if suspicious_lines else len(code.split('\n')),
                    code_snippet=self._extract_snippet(code, suspicious_lines),
                    ai_explanation=prediction.explanation,
                    cwe_id=self._get_cwe_id(prediction.vulnerability_type),
                    fix_suggestion=self._get_fix_suggestion(prediction.vulnerability_type)
                )
                
                # Add additional metadata
                vuln.ai_metadata = {
                    'gnn_score': prediction.gnn_score,
                    'codebert_score': prediction.codebert_score,
                    'combined_score': prediction.vulnerability_score,
                    'features': prediction.combined_features
                }
                
                vulnerabilities.append(vuln)
            
            # Check for high complexity even if no specific vulnerability
            if prediction.combined_features.get('graph_density', 0) > 0.15:
                vuln = Vulnerability(
                    id=f"HYBRID-COMPLEXITY-{file_path}",
                    name="High Code Complexity",
                    description="AI detected unusually complex code structure that may hide vulnerabilities",
                    severity=Severity.LOW,
                    confidence=0.7,
                    file_path=file_path,
                    line_start=1,
                    line_end=len(code.split('\n')),
                    code_snippet="[Full file - complex structure]",
                    ai_explanation=f"Graph density: {prediction.combined_features['graph_density']:.2f}, "
                                  f"Nodes: {prediction.combined_features['graph_nodes']}"
                )
                vulnerabilities.append(vuln)
                
        except Exception as e:
            print(f"Hybrid analysis error: {e}")
        
        return vulnerabilities
    
    def _calculate_severity(self, vuln_type: str, score: float, confidence: float) -> Severity:
        """Calculate severity based on multiple factors"""
        critical_types = ["SQL Injection", "Command Injection", "Insecure Deserialization"]
        high_types = ["XSS", "Path Traversal"]
        
        combined_score = score * confidence
        
        if vuln_type in critical_types and combined_score > 0.7:
            return Severity.CRITICAL
        elif vuln_type in critical_types or (vuln_type in high_types and combined_score > 0.6):
            return Severity.HIGH
        elif combined_score > 0.5:
            return Severity.MEDIUM
        else:
            return Severity.LOW
    
    def _identify_vulnerable_lines(self, code: str, vuln_type: str) -> List[int]:
        """Identify likely vulnerable lines based on type"""
        lines = code.split('\n')
        vulnerable_lines = []
        
        # Pattern keywords for each vulnerability type
        patterns = {
            "SQL Injection": ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'query', 'execute'],
            "XSS": ['innerHTML', 'document.write', 'html(', 'append('],
            "Command Injection": ['system', 'exec', 'subprocess', 'shell'],
            "Path Traversal": ['open(', 'readFile', 'include', 'require'],
            "Insecure Deserialization": ['pickle', 'unserialize', 'loads', 'json.loads']
        }
        
        keywords = patterns.get(vuln_type, [])
        
        for i, line in enumerate(lines, 1):
            if any(keyword in line for keyword in keywords):
                vulnerable_lines.append(i)
        
        return vulnerable_lines or [1]  # Default to first line if nothing found
    
    def _extract_snippet(self, code: str, lines: List[int], context: int = 2) -> str:
        """Extract code snippet around vulnerable lines"""
        if not lines:
            return code[:200] + "..." if len(code) > 200 else code
        
        code_lines = code.split('\n')
        min_line = max(0, min(lines) - context - 1)
        max_line = min(len(code_lines), max(lines) + context)
        
        snippet = '\n'.join(code_lines[min_line:max_line])
        return snippet[:300] + "..." if len(snippet) > 300 else snippet
    
    def _get_cwe_id(self, vuln_type: str) -> str:
        """Map vulnerability type to CWE ID"""
        cwe_mapping = {
            "SQL Injection": "CWE-89",
            "XSS": "CWE-79",
            "Command Injection": "CWE-78",
            "Path Traversal": "CWE-22",
            "Insecure Deserialization": "CWE-502"
        }
        return cwe_mapping.get(vuln_type, "CWE-Unknown")
    
    def _get_fix_suggestion(self, vuln_type: str) -> str:
        """Get fix suggestion for vulnerability type"""
        fixes = {
            "SQL Injection": "Use parameterized queries or prepared statements. Never concatenate user input into SQL.",
            "XSS": "Sanitize all user input before rendering. Use textContent instead of innerHTML.",
            "Command Injection": "Avoid system calls with user input. Use subprocess with shell=False.",
            "Path Traversal": "Validate and sanitize file paths. Use os.path.basename() and check against whitelist.",
            "Insecure Deserialization": "Never deserialize untrusted data. Use JSON instead of pickle/serialize."
        }
        return fixes.get(vuln_type, "Review and sanitize all user inputs.")

