#!/usr/bin/env python3
"""
Test the trained GNN model
"""
import sys
from pathlib import Path
import torch

# Add project root to path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from src.ml.gnn_model_improved import ImprovedGNNVulnerabilityDetector

def test_trained_model():
    """Test the trained GNN model"""
    print("Testing trained GNN model...")
    
    # Check if model exists
    model_path = "data/models/trained_gnn_model.pth"
    if not Path(model_path).exists():
        print(f"Model not found at {model_path}")
        print("Please run training first: python train_gnn.py")
        return
    
    # Load model
    try:
        detector = ImprovedGNNVulnerabilityDetector(model_path)
        print("Model loaded successfully")
    except Exception as e:
        print(f"Failed to load model: {e}")
        return
    
    # Test vulnerable code
    test_code = """#include <stdio.h>
#include <string.h>

void vulnerable_function(char* user_input) {
    char buffer[64];
    strcpy(buffer, user_input);  // VULNERABLE
    printf("Input: %s\\n", buffer);
}"""
    
    try:
        vuln_prob, vuln_type, confidence, analysis = detector.predict(test_code, "c")
        
        print("\nTest Results:")
        print(f"   Vulnerability Probability: {vuln_prob:.2%}")
        print(f"   Type: {vuln_type}")
        print(f"   Confidence: {confidence:.2%}")
        print(f"   Analysis: {analysis}")
        
        if vuln_prob > 0.7:
            print("\nModel correctly identified vulnerability!")
        else:
            print("\nModel may need more training")
            
    except Exception as e:
        print(f"   Test failed: {e}")

if __name__ == "__main__":
    test_trained_model()
