# src/ml/gnn_model.py
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch_geometric.nn import GCNConv, global_mean_pool, global_max_pool
from torch_geometric.data import Data, DataLoader
import numpy as np
from typing import List, Tuple, Optional, Dict, Any
from pathlib import Path

class VulnerabilityGNN(nn.Module):
    """Graph Neural Network for vulnerability detection in code structure"""
    
    def __init__(self, num_node_features: int, num_edge_features: int, 
                 hidden_dim: int = 128, num_classes: int = 2):
        super(VulnerabilityGNN, self).__init__()
        
        # Graph convolution layers
        self.conv1 = GCNConv(num_node_features, hidden_dim)
        self.conv2 = GCNConv(hidden_dim, hidden_dim)
        self.conv3 = GCNConv(hidden_dim, hidden_dim // 2)
        
        # Batch normalization
        self.bn1 = nn.BatchNorm1d(hidden_dim)
        self.bn2 = nn.BatchNorm1d(hidden_dim)
        self.bn3 = nn.BatchNorm1d(hidden_dim // 2)
        
        # Dropout for regularization
        self.dropout = nn.Dropout(0.5)
        
        # Final classifier
        self.classifier = nn.Sequential(
            nn.Linear(hidden_dim // 2, hidden_dim // 4),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(hidden_dim // 4, num_classes)
        )
        
        # For vulnerability type classification
        self.vuln_type_classifier = nn.Sequential(
            nn.Linear(hidden_dim // 2, hidden_dim // 4),
            nn.ReLU(),
            nn.Linear(hidden_dim // 4, 5)  # 5 vulnerability types
        )
    
    def forward(self, x, edge_index, batch=None):
        # First GCN layer
        x = self.conv1(x, edge_index)
        x = self.bn1(x)
        x = F.relu(x)
        x = self.dropout(x)
        
        # Second GCN layer
        x = self.conv2(x, edge_index)
        x = self.bn2(x)
        x = F.relu(x)
        x = self.dropout(x)
        
        # Third GCN layer
        x = self.conv3(x, edge_index)
        x = self.bn3(x)
        x = F.relu(x)
        
        # Global pooling (to get graph-level representation)
        if batch is not None:
            x = global_mean_pool(x, batch)
        else:
            x = global_mean_pool(x, torch.zeros(x.size(0), dtype=torch.long))
        
        # Classification
        vuln_detection = self.classifier(x)
        vuln_type = self.vuln_type_classifier(x)
        
        return vuln_detection, vuln_type

class GNNVulnerabilityDetector:
    """Wrapper for using GNN to detect vulnerabilities"""
    
    def __init__(self, model_path: Optional[str] = None):
        self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        
        # Initialize model
        self.model = VulnerabilityGNN(
            num_node_features=24,  # Based on CodeGraphBuilder features
            num_edge_features=6,   # Based on edge types
            hidden_dim=128
        )
        self.model.to(self.device)
        
        # Load pre-trained weights if available
        if model_path and Path(model_path).exists():
            self.model.load_state_dict(torch.load(model_path, map_location=self.device))
            self.model.eval()
            print(f"✓ Loaded GNN model from {model_path}")
        else:
            print("✓ Initialized new GNN model (no pre-trained weights)")
        
        # Vulnerability type mapping
        self.vuln_types = {
            0: "SQL Injection",
            1: "XSS",
            2: "Command Injection",
            3: "Path Traversal",
            4: "Insecure Deserialization"
        }
    
    def predict(self, graph_data: Data) -> Tuple[float, str, float]:
        """Predict vulnerability probability and type"""
        self.model.eval()
        
        with torch.no_grad():
            # Move data to device
            graph_data = graph_data.to(self.device)
            
            # Forward pass
            vuln_logits, type_logits = self.model(
                graph_data.x, 
                graph_data.edge_index
            )
            
            # Calculate probabilities
            vuln_prob = torch.softmax(vuln_logits, dim=1)[0, 1].item()
            type_probs = torch.softmax(type_logits, dim=1)[0]
            
            # Get most likely vulnerability type
            type_idx = torch.argmax(type_probs).item()
            vuln_type = self.vuln_types.get(type_idx, "Unknown")
            type_confidence = type_probs[type_idx].item()
            
            return vuln_prob, vuln_type, type_confidence
    
    def analyze_code_structure(self, graph_data: Data) -> Dict[str, Any]:
        """Analyze code structure for vulnerability patterns"""
        # Get node embeddings
        self.model.eval()
        
        with torch.no_grad():
            x = graph_data.x.to(self.device)
            edge_index = graph_data.edge_index.to(self.device)
            
            # Get intermediate representations
            x = self.model.conv1(x, edge_index)
            x = F.relu(x)
            node_embeddings = x.cpu().numpy()
        
        # Analyze graph properties
        num_nodes = graph_data.num_nodes
        num_edges = graph_data.edge_index.size(1)
        
        # Calculate graph metrics
        density = num_edges / (num_nodes * (num_nodes - 1)) if num_nodes > 1 else 0
        
        # Find suspicious patterns
        suspicious_nodes = []
        for i, embedding in enumerate(node_embeddings):
            # High activation in certain dimensions indicates suspicious patterns
            if np.max(embedding) > 2.0:  # Threshold
                suspicious_nodes.append(i)
        
        return {
            "num_nodes": num_nodes,
            "num_edges": num_edges,
            "graph_density": density,
            "suspicious_nodes": len(suspicious_nodes),
            "suspicious_ratio": len(suspicious_nodes) / num_nodes if num_nodes > 0 else 0
        }
    
    def train_on_examples(self, training_data: List[Tuple[Data, int, int]]):
        """Train the model on labeled examples"""
        self.model.train()
        optimizer = torch.optim.Adam(self.model.parameters(), lr=0.001)
        criterion_vuln = nn.CrossEntropyLoss()
        criterion_type = nn.CrossEntropyLoss()
        
        for epoch in range(10):  # Simple training loop
            total_loss = 0
            
            for graph_data, has_vuln, vuln_type in training_data:
                graph_data = graph_data.to(self.device)
                
                # Forward pass
                vuln_pred, type_pred = self.model(
                    graph_data.x, 
                    graph_data.edge_index
                )
                
                # Calculate losses
                vuln_target = torch.tensor([has_vuln], device=self.device)
                type_target = torch.tensor([vuln_type], device=self.device)
                
                loss_vuln = criterion_vuln(vuln_pred, vuln_target)
                loss_type = criterion_type(type_pred, type_target)
                
                total_loss = loss_vuln + loss_type
                
                # Backward pass
                optimizer.zero_grad()
                total_loss.backward()
                optimizer.step()
                
                total_loss += total_loss.item()
            
            print(f"Epoch {epoch + 1}, Loss: {total_loss / len(training_data):.4f}")

