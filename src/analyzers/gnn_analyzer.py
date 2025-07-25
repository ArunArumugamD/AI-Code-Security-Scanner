# src/analyzers/gnn_analyzer.py
from typing import List, Dict, Optional
import asyncio
from pathlib import Path
from src.core.base_scanner import BaseAnalyzer, Vulnerability, Severity
from src.ml.code_graph import CodeGraphBuilder
from src.ml.gnn_model import GNNVulnerabilityDetector
import torch

class GNNStructuralAnalyzer(BaseAnalyzer):
    """Analyzer using Graph Neural Networks for structural vulnerability detection"""
    
    def __init__(self, model_path: Optional[str] = None):
        super().__init__(
            name="GNN Structural Analyzer",
            supported_languages=['python', 'javascript', 'java']
        )
        self.is_ai_powered = True
        
        # Default to trained model if no path specified
        if model_path is None:
            model_path = "data/models/trained_gnn_model.pth"
        
        try:
            self.graph_builder = CodeGraphBuilder()
            
            # Check if trained model exists
            if Path(model_path).exists():
                self.gnn_detector = GNNVulnerabilityDetector(model_path)
                self.enabled = True
                self.using_trained_model = True
                print(f"✓ GNN Structural Analyzer initialized with TRAINED model from {model_path}")
            else:
                # Fall back to untrained model with warning
                self.gnn_detector = GNNVulnerabilityDetector()
                self.enabled = True
                self.using_trained_model = False
                print("⚠️  GNN Structural Analyzer initialized with RANDOM weights (no trained model found)")
                print(f"   To train the model, run: python src/ml/training/train_gnn.py")
                
        except Exception as e:
            print(f"❌ GNN analyzer disabled: {e}")
            self.enabled = False
            self.using_trained_model = False
    
    async def analyze(self, code: str, language: str, file_path: str) -> List[Vulnerability]:
        """Analyze code structure using GNN"""
        if not self.enabled:
            return []
        
        vulnerabilities = []
        
        try:
            # Build code graph
            graph = await asyncio.to_thread(
                self.graph_builder.build_graph, code, language
            )
            
            # Skip if graph is too small
            if len(graph.nodes()) < 3:
                return vulnerabilities
            
            # Convert to PyTorch format
            graph_data = self.graph_builder.to_pytorch_geometric(graph)
            
            # Run GNN analysis
            vuln_prob, vuln_type, type_confidence = await asyncio.to_thread(
                self.gnn_detector.predict, graph_data
            )
            
            # Analyze structure for additional insights
            structure_analysis = await asyncio.to_thread(
                self.gnn_detector.analyze_code_structure, graph_data
            )
            
            # Adjust confidence based on whether model is trained
            if not self.using_trained_model:
                # Reduce confidence significantly for untrained model
                vuln_prob *= 0.3
                type_confidence *= 0.3
            
            # Only report if confidence is high enough
            confidence_threshold = 0.7 if self.using_trained_model else 0.85
            
            if vuln_prob > confidence_threshold:
                # Find the most suspicious part of the code
                suspicious_lines = self._identify_suspicious_sections(
                    graph, structure_analysis
                )
                
                # Calculate severity based on type and probability
                severity = self._calculate_severity(vuln_prob, vuln_type)
                
                # Create vulnerability report
                vuln = Vulnerability(
                    id=f"GNN-{file_path}-{vuln_type.replace(' ', '_')}",
                    name=f"GNN: Structural {vuln_type} Pattern",
                    description=self._generate_description(vuln_type, structure_analysis, self.using_trained_model),
                    severity=severity,
                    confidence=vuln_prob * type_confidence,  # Combined confidence
                    file_path=file_path,
                    line_start=suspicious_lines[0] if suspicious_lines else 1,
                    line_end=suspicious_lines[-1] if suspicious_lines else len(code.split('\n')),
                    code_snippet=self._extract_snippet(code, suspicious_lines),
                    ai_explanation=self._generate_gnn_explanation(
                        vuln_type, vuln_prob, structure_analysis, self.using_trained_model
                    ),
                    cwe_id=self._get_cwe_id(vuln_type),
                    fix_suggestion=self._get_fix_suggestion(vuln_type)
                )
                vulnerabilities.append(vuln)
            
            # Report high complexity regardless of vulnerability
            if structure_analysis['suspicious_ratio'] > 0.3 and self.using_trained_model:
                vuln = Vulnerability(
                    id=f"GNN-COMPLEXITY-{file_path}",
                    name="Complex/Suspicious Code Structure",
                    description="Code structure analysis reveals high complexity and suspicious patterns",
                    severity=Severity.MEDIUM,
                    confidence=0.75 if self.using_trained_model else 0.4,
                    file_path=file_path,
                    line_start=1,
                    line_end=len(code.split('\n')),
                    code_snippet="[Full file analysis]",
                    ai_explanation=f"GNN detected {structure_analysis['suspicious_nodes']} suspicious nodes "
                                  f"out of {structure_analysis['num_nodes']} total nodes. "
                                  f"Graph density: {structure_analysis['graph_density']:.2f}. "
                                  f"{'Trained model analysis.' if self.using_trained_model else 'Note: Using untrained model.'}"
                )
                vulnerabilities.append(vuln)
            
        except Exception as e:
            print(f"GNN analysis error: {e}")
        
        return vulnerabilities
    
    def _identify_suspicious_sections(self, graph, analysis: Dict) -> List[int]:
        """Identify suspicious lines in the code based on graph analysis"""
        suspicious_lines = []
        
        try:
            import networkx as nx
            
            # Get nodes with high centrality (important/connected nodes)
            centrality = nx.betweenness_centrality(graph)
            
            # Sort nodes by centrality
            sorted_nodes = sorted(centrality.items(), key=lambda x: x[1], reverse=True)
            
            # Get lines of top suspicious nodes
            for node_id, centrality_score in sorted_nodes[:5]:
                if node_id in graph.nodes():
                    node_data = graph.nodes[node_id]
                    line = node_data.get('line', 0)
                    
                    # For trained model, use centrality threshold
                    if self.using_trained_model and centrality_score > 0.1:
                        if line > 0:
                            suspicious_lines.append(line)
                    # For untrained model, be more conservative
                    elif not self.using_trained_model and centrality_score > 0.3:
                        if line > 0:
                            suspicious_lines.append(line)
        except Exception as e:
            print(f"Error identifying suspicious sections: {e}")
        
        return sorted(set(suspicious_lines))
    
    def _calculate_severity(self, vuln_prob: float, vuln_type: str) -> Severity:
        """Calculate severity based on probability and type"""
        critical_types = ["SQL Injection", "Command Injection", "Insecure Deserialization"]
        high_types = ["XSS", "Path Traversal"]
        
        # Adjust thresholds based on whether model is trained
        if self.using_trained_model:
            if vuln_type in critical_types and vuln_prob > 0.8:
                return Severity.CRITICAL
            elif vuln_type in critical_types or (vuln_type in high_types and vuln_prob > 0.85):
                return Severity.HIGH
            elif vuln_prob > 0.8:
                return Severity.MEDIUM
            else:
                return Severity.LOW
        else:
            # More conservative for untrained model
            if vuln_type in critical_types and vuln_prob > 0.9:
                return Severity.HIGH
            elif vuln_prob > 0.85:
                return Severity.LOW
            else:
                return Severity.LOW
    
    def _extract_snippet(self, code: str, lines: List[int], context: int = 2) -> str:
        """Extract code snippet around suspicious lines"""
        if not lines:
            return "[No specific location identified]"
        
        code_lines = code.split('\n')
        min_line = max(0, min(lines) - context - 1)
        max_line = min(len(code_lines), max(lines) + context)
        
        snippet_lines = code_lines[min_line:max_line]
        return '\n'.join(snippet_lines)[:300]  # Limit length
    
    def _generate_description(self, vuln_type: str, structure_analysis: Dict, is_trained: bool) -> str:
        """Generate description based on model status"""
        if is_trained:
            return f"Graph Neural Network analysis detected structural patterns consistent with {vuln_type}. " \
                   f"The trained model identified suspicious code structure patterns."
        else:
            return f"Graph analysis detected structural patterns that might indicate {vuln_type}. " \
                   f"Note: This detection uses an untrained model and may be less accurate."
    
    def _generate_gnn_explanation(self, vuln_type: str, probability: float, 
                                 analysis: Dict, is_trained: bool) -> str:
        """Generate explanation from GNN analysis"""
        model_status = "trained GNN model" if is_trained else "untrained GNN model (random weights)"
        
        explanation = f"Graph Neural Network analysis using {model_status} detected patterns consistent with {vuln_type}. "
        explanation += f"Confidence: {probability:.0%}. "
        
        if analysis['graph_density'] > 0.5:
            explanation += "The code has high structural complexity. "
        
        if analysis['suspicious_ratio'] > 0.2:
            explanation += f"{analysis['suspicious_ratio']:.0%} of code nodes show suspicious patterns. "
        
        if is_trained:
            explanation += "The GNN identified structural relationships between code elements that match learned vulnerability patterns."
        else:
            explanation += "Warning: Using untrained model - results may be unreliable. Train the model for accurate detection."
        
        return explanation
    
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
    
    def get_model_status(self) -> Dict[str, any]:
        """Get current model status"""
        return {
            "enabled": self.enabled,
            "using_trained_model": self.using_trained_model,
            "model_path": "data/models/trained_gnn_model.pth",
            "supported_languages": self.supported_languages,
            "vulnerability_types": [
                "SQL Injection",
                "XSS", 
                "Command Injection",
                "Path Traversal",
                "Insecure Deserialization"
            ]
        }