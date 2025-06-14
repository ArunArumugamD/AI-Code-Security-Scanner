# src/ml/hybrid_model.py
import torch
import torch.nn as nn
import torch.nn.functional as F
import numpy as np
from typing import Tuple, Dict, List, Optional
from dataclasses import dataclass
from torch_geometric.data import Data

from src.ml.codebert_model import CodeBERTManager
from src.ml.gnn_model import VulnerabilityGNN
from src.ml.code_graph import CodeGraphBuilder

@dataclass
class HybridPrediction:
    """Result from hybrid model analysis"""
    vulnerability_score: float
    vulnerability_type: str
    confidence: float
    gnn_score: float
    codebert_score: float
    combined_features: Dict[str, float]
    explanation: str

class HybridVulnerabilityDetector(nn.Module):
    """Combines GNN structural analysis with CodeBERT semantic understanding"""
    
    def __init__(self, gnn_features: int = 24, codebert_dim: int = 768):
        super().__init__()
        
        # Initialize base models
        self.gnn = VulnerabilityGNN(
            num_node_features=gnn_features,
            num_edge_features=6,
            hidden_dim=128
        )
        
        # Feature fusion layers
        self.fusion_layer = nn.Sequential(
            nn.Linear(64 + codebert_dim, 512),  # GNN output (64) + CodeBERT (768)
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(512, 256),
            nn.ReLU(),
            nn.Dropout(0.3)
        )
        
        # Final classifiers
        self.vulnerability_classifier = nn.Linear(256, 2)  # Binary: vulnerable or not
        self.type_classifier = nn.Linear(256, 5)  # 5 vulnerability types
        self.confidence_estimator = nn.Linear(256, 1)  # Confidence score
        
    def forward(self, graph_data: Data, code_embedding: torch.Tensor):
        """Forward pass combining both models"""
        # Get GNN features
        x = graph_data.x
        edge_index = graph_data.edge_index
        
        # GNN forward pass (get intermediate features)
        x = self.gnn.conv1(x, edge_index)
        x = self.gnn.bn1(x)
        x = F.relu(x)
        x = self.gnn.dropout(x)
        
        x = self.gnn.conv2(x, edge_index)
        x = self.gnn.bn2(x)
        x = F.relu(x)
        x = self.gnn.dropout(x)
        
        x = self.gnn.conv3(x, edge_index)
        x = self.gnn.bn3(x)
        x = F.relu(x)
        
        # Global pooling for graph-level representation
        if hasattr(graph_data, 'batch'):
            from torch_geometric.nn import global_mean_pool
            gnn_features = global_mean_pool(x, graph_data.batch)
        else:
            gnn_features = x.mean(dim=0, keepdim=True)
        
        # Ensure code_embedding is 2D
        if code_embedding.dim() == 1:
            code_embedding = code_embedding.unsqueeze(0)
        
        # Combine GNN and CodeBERT features
        combined = torch.cat([gnn_features, code_embedding], dim=1)
        
        # Fusion layers
        fused = self.fusion_layer(combined)
        
        # Predictions
        vuln_pred = self.vulnerability_classifier(fused)
        type_pred = self.type_classifier(fused)
        conf_pred = torch.sigmoid(self.confidence_estimator(fused))
        
        return vuln_pred, type_pred, conf_pred

class HybridAnalysisEngine:
    """Engine for running hybrid GNN + CodeBERT analysis"""
    
    def __init__(self, model_path: Optional[str] = None):
        self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        
        # Initialize components
        print("🤖 Initializing Hybrid AI Engine...")
        self.codebert = CodeBERTManager()
        self.graph_builder = CodeGraphBuilder()
        self.hybrid_model = HybridVulnerabilityDetector()
        self.hybrid_model.to(self.device)
        self.hybrid_model.eval()
        
        if model_path:
            self.load_model(model_path)
        
        print("✓ Hybrid AI Engine ready (GNN + CodeBERT)")
        
        self.vuln_types = {
            0: "SQL Injection",
            1: "XSS",
            2: "Command Injection", 
            3: "Path Traversal",
            4: "Insecure Deserialization"
        }
    
    def analyze(self, code: str, language: str) -> HybridPrediction:
        """Perform hybrid analysis on code"""
        with torch.no_grad():
            # Step 1: Build code graph
            graph = self.graph_builder.build_graph(code, language)
            graph_data = self.graph_builder.to_pytorch_geometric(graph)
            graph_data = graph_data.to(self.device)
            
            # Step 2: Get CodeBERT embedding
            code_embedding = self.codebert.get_embedding(code, language)
            code_embedding_tensor = torch.tensor(code_embedding, dtype=torch.float32).to(self.device)
            
            # Step 3: Run hybrid model
            vuln_pred, type_pred, conf_pred = self.hybrid_model(graph_data, code_embedding_tensor)
            
            # Step 4: Process predictions
            vuln_probs = F.softmax(vuln_pred, dim=1)
            type_probs = F.softmax(type_pred, dim=1)
            
            vulnerability_score = vuln_probs[0, 1].item()
            type_idx = torch.argmax(type_probs).item()
            vulnerability_type = self.vuln_types[type_idx]
            confidence = conf_pred.item()
            
            # Step 5: Individual model scores for transparency
            # Run GNN alone
            gnn_vuln, _ = self.hybrid_model.gnn(graph_data.x, graph_data.edge_index)
            gnn_score = F.softmax(gnn_vuln, dim=1)[0, 1].item()
            
            # CodeBERT similarity score
            codebert_score = self._calculate_codebert_score(code, vulnerability_type, language)
            
            # Step 6: Extract combined features
            combined_features = self._extract_features(graph, code, vulnerability_score)
            
            # Step 7: Generate explanation
            explanation = self._generate_explanation(
                vulnerability_type, vulnerability_score, gnn_score, 
                codebert_score, confidence, combined_features
            )
            
            return HybridPrediction(
                vulnerability_score=vulnerability_score,
                vulnerability_type=vulnerability_type,
                confidence=confidence,
                gnn_score=gnn_score,
                codebert_score=codebert_score,
                combined_features=combined_features,
                explanation=explanation
            )
    
    def _calculate_codebert_score(self, code: str, vuln_type: str, language: str) -> float:
        """Calculate CodeBERT-based vulnerability score"""
        vuln_examples = {
            "SQL Injection": "query = 'SELECT * FROM users WHERE id = ' + user_input",
            "XSS": "document.getElementById('div').innerHTML = user_data",
            "Command Injection": "os.system('ping ' + ip_address)",
            "Path Traversal": "open('/var/data/' + user_file)",
            "Insecure Deserialization": "pickle.loads(user_data)"
        }
        
        if vuln_type in vuln_examples:
            example_embedding = self.codebert.get_embedding(vuln_examples[vuln_type], language)
            code_embedding = self.codebert.get_embedding(code, language)
            similarity = self.codebert.calculate_similarity(code_embedding, example_embedding)
            return similarity
        return 0.5
    
    def _extract_features(self, graph, code: str, vuln_score: float) -> Dict[str, float]:
        """Extract interpretable features from analysis"""
        lines = code.split('\n')
        
        return {
            "graph_nodes": len(graph.nodes()),
            "graph_edges": len(graph.edges()),
            "graph_density": len(graph.edges()) / (len(graph.nodes()) ** 2) if len(graph.nodes()) > 0 else 0,
            "code_lines": len(lines),
            "vulnerability_score": vuln_score,
            "has_user_input": float(any(term in code.lower() for term in ['input', 'request', 'user', 'param'])),
            "has_dangerous_functions": float(any(func in code for func in ['eval', 'exec', 'system', 'shell'])),
            "has_sql_keywords": float(any(sql in code.upper() for sql in ['SELECT', 'INSERT', 'UPDATE', 'DELETE']))
        }
    
    def _generate_explanation(self, vuln_type: str, vuln_score: float, 
                            gnn_score: float, codebert_score: float, 
                            confidence: float, features: Dict) -> str:
        """Generate detailed explanation of the analysis"""
        explanation = f"Hybrid AI Analysis Results:\n"
        explanation += f"- Detected: {vuln_type} (Overall: {vuln_score:.1%}, Confidence: {confidence:.1%})\n"
        explanation += f"- GNN (Structure): {gnn_score:.1%} - Analyzed {features['graph_nodes']} nodes and {features['graph_edges']} edges\n"
        explanation += f"- CodeBERT (Semantics): {codebert_score:.1%} - Code semantically similar to {vuln_type} patterns\n"
        
        if vuln_score > 0.8:
            explanation += f"\nHIGH RISK: Both structural and semantic analysis indicate {vuln_type}."
        elif vuln_score > 0.6:
            explanation += f"\nMODERATE RISK: Suspicious patterns detected, manual review recommended."
        
        if features['has_dangerous_functions']:
            explanation += f"\n⚠️ Dangerous functions detected in code."
        
        if features['graph_density'] > 0.1:
            explanation += f"\n📊 High code complexity (density: {features['graph_density']:.2f})"
        
        return explanation
    
    def batch_analyze(self, code_samples: List[Tuple[str, str]]) -> List[HybridPrediction]:
        """Analyze multiple code samples efficiently"""
        results = []
        for code, language in code_samples:
            try:
                result = self.analyze(code, language)
                results.append(result)
            except Exception as e:
                print(f"Error analyzing sample: {e}")
        return results
    
    def save_model(self, path: str):
        """Save the hybrid model"""
        torch.save({
            'model_state': self.hybrid_model.state_dict(),
            'vuln_types': self.vuln_types
        }, path)
        print(f"✓ Model saved to {path}")
    
    def load_model(self, path: str):
        """Load a pre-trained hybrid model"""
        checkpoint = torch.load(path, map_location=self.device)
        self.hybrid_model.load_state_dict(checkpoint['model_state'])
        self.vuln_types = checkpoint.get('vuln_types', self.vuln_types)
        print(f"✓ Model loaded from {path}")

