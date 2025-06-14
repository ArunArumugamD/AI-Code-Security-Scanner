# src/analyzers/gnn_analyzer.py
from typing import List, Dict, Optional
import asyncio
from src.core.base_scanner import BaseAnalyzer, Vulnerability, Severity
from src.ml.code_graph import CodeGraphBuilder
from src.ml.gnn_model import GNNVulnerabilityDetector
import torch

class GNNStructuralAnalyzer(BaseAnalyzer):
    """Analyzer using Graph Neural Networks for structural vulnerability detection"""
    
    def __init__(self):
        super().__init__(
            name="GNN Structural Analyzer",
            supported_languages=['python', 'javascript', 'java']
        )
        self.is_ai_powered = True
        
        try:
            self.graph_builder = CodeGraphBuilder()
            self.gnn_detector = GNNVulnerabilityDetector()
            self.enabled = True
            print("✓ GNN Structural Analyzer initialized")
        except Exception as e:
            print(f"⚠ GNN analyzer disabled: {e}")
            self.enabled = False
    
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
            
            if len(graph.nodes()) < 3:  # Too small to analyze
                return vulnerabilities
            
            # Convert to PyTorch format
            graph_data = self.graph_builder.to_pytorch_geometric(graph)
            
            # Run GNN analysis
            vuln_prob, vuln_type, type_confidence = await asyncio.to_thread(
                self.gnn_detector.predict, graph_data
            )
            
            # Analyze structure
            structure_analysis = await asyncio.to_thread(
                self.gnn_detector.analyze_code_structure, graph_data
            )
            
            # If high vulnerability probability
            if vuln_prob > 0.7:
                # Find the most suspicious part of the code
                suspicious_lines = self._identify_suspicious_sections(
                    graph, structure_analysis
                )
                
                vuln = Vulnerability(
                    id=f"GNN-{file_path}-{vuln_type.replace(' ', '_')}",
                    name=f"GNN: Structural {vuln_type} Pattern",
                    description=f"Graph analysis detected structural patterns consistent with {vuln_type}",
                    severity=self._calculate_severity(vuln_prob, vuln_type),
                    confidence=vuln_prob * type_confidence,  # Combined confidence
                    file_path=file_path,
                    line_start=suspicious_lines[0] if suspicious_lines else 1,
                    line_end=suspicious_lines[-1] if suspicious_lines else len(code.split('\n')),
                    code_snippet=self._extract_snippet(code, suspicious_lines),
                    ai_explanation=self._generate_gnn_explanation(
                        vuln_type, vuln_prob, structure_analysis
                    )
                )
                vulnerabilities.append(vuln)
            
            # Additional structural issues
            if structure_analysis['suspicious_ratio'] > 0.3:
                vuln = Vulnerability(
                    id=f"GNN-STRUCT-{file_path}",
                    name="Complex/Suspicious Code Structure",
                    description="Code structure analysis reveals high complexity and suspicious patterns",
                    severity=Severity.MEDIUM,
                    confidence=0.75,
                    file_path=file_path,
                    line_start=1,
                    line_end=len(code.split('\n')),
                    code_snippet="[Full file analysis]",
                    ai_explanation=f"GNN detected {structure_analysis['suspicious_nodes']} suspicious nodes "
                                  f"out of {structure_analysis['num_nodes']} total nodes. "
                                  f"Graph density: {structure_analysis['graph_density']:.2f}"
                )
                vulnerabilities.append(vuln)
            
        except Exception as e:
            print(f"GNN analysis error: {e}")
        
        return vulnerabilities
    
    def _identify_suspicious_sections(self, graph, analysis: Dict) -> List[int]:
        """Identify suspicious lines in the code"""
        suspicious_lines = []
        
        # Get nodes with high centrality (important nodes)
        try:
            import networkx as nx
            centrality = nx.betweenness_centrality(graph)
            
            # Sort nodes by centrality
            sorted_nodes = sorted(centrality.items(), key=lambda x: x[1], reverse=True)
            
            # Get lines of top suspicious nodes
            for node_id, _ in sorted_nodes[:5]:
                if node_id in graph.nodes():
                    line = graph.nodes[node_id].get('line', 0)
                    if line > 0:
                        suspicious_lines.append(line)
        except:
            pass
        
        return sorted(set(suspicious_lines))
    
    def _calculate_severity(self, vuln_prob: float, vuln_type: str) -> Severity:
        """Calculate severity based on probability and type"""
        critical_types = ["SQL Injection", "Command Injection", "Insecure Deserialization"]
        high_types = ["XSS", "Path Traversal"]
        
        if vuln_type in critical_types and vuln_prob > 0.8:
            return Severity.CRITICAL
        elif vuln_type in critical_types or (vuln_type in high_types and vuln_prob > 0.85):
            return Severity.HIGH
        elif vuln_prob > 0.8:
            return Severity.MEDIUM
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
    
    def _generate_gnn_explanation(self, vuln_type: str, probability: float, 
                                 analysis: Dict) -> str:
        """Generate explanation from GNN analysis"""
        explanation = f"Graph Neural Network analysis detected patterns consistent with {vuln_type}. "
        explanation += f"Confidence: {probability:.0%}. "
        
        if analysis['graph_density'] > 0.5:
            explanation += "The code has high structural complexity. "
        
        if analysis['suspicious_ratio'] > 0.2:
            explanation += f"{analysis['suspicious_ratio']:.0%} of code nodes show suspicious patterns. "
        
        explanation += "The GNN identified structural relationships between code elements that match known vulnerability patterns."
        
        return explanation
