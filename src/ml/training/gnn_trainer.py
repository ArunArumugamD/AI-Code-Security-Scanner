#gnn_trainer.py
import json
from pathlib import Path
from typing import List, Tuple
import torch
from src.ml.code_graph import CodeGraphBuilder
from src.ml.gnn_model import GNNVulnerabilityDetector

class GNNTrainingDataGenerator:
    def __init__(self):
        self.graph_builder = CodeGraphBuilder()
        self.training_samples = []
    
    def add_vulnerable_sample(self, code: str, language: str, vuln_type: int):
        """Add a vulnerable code sample"""
        graph = self.graph_builder.build_graph(code, language)
        graph_data = self.graph_builder.to_pytorch_geometric(graph)
        # Label: (has_vulnerability=1, vulnerability_type)
        self.training_samples.append((graph_data, 1, vuln_type))
    
    def add_safe_sample(self, code: str, language: str):
        """Add a safe code sample"""
        graph = self.graph_builder.build_graph(code, language)
        graph_data = self.graph_builder.to_pytorch_geometric(graph)
        # Label: (has_vulnerability=0, no_type=-1)
        self.training_samples.append((graph_data, 0, -1))
    
    def save_dataset(self, path: str):
        """Save the dataset"""
        torch.save(self.training_samples, path)