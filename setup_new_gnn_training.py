#!/usr/bin/env python3
# setup_new_gnn_training.py
"""
Setup script to clean old GNN training and prepare for new high-accuracy training
Windows compatible version
"""
import os
import shutil
import sys
from pathlib import Path
import json

def clean_old_training_data():
    """Remove old training data and models"""
    print("Cleaning old training data...")
    
    paths_to_clean = [
        "data/models/trained_gnn_model.pth",
        "data/models/gnn_training_data.pt", 
        "src/ml/training/train_gnn.py",
        "src/ml/training/train_gnn_improved.py",
        "src/ml/training/train_enhanced.py"
    ]
    
    for path in paths_to_clean:
        if os.path.exists(path):
            if os.path.isfile(path):
                os.remove(path)
                print(f"   Removed {path}")
            elif os.path.isdir(path):
                shutil.rmtree(path)
                print(f"   Removed directory {path}")
    
    # Clean training directories
    training_dirs = [
        "data/gnn_training",
        "data/sard",
        "data/models"
    ]
    
    for dir_path in training_dirs:
        if os.path.exists(dir_path):
            shutil.rmtree(dir_path)
            print(f"   Cleaned {dir_path}")

def setup_directories():
    """Create necessary directories"""
    print("Setting up directories...")
    
    directories = [
        "data/models",
        "data/gnn_training", 
        "data/sard",
        "src/ml/training",
        "logs"
    ]
    
    for directory in directories:
        os.makedirs(directory, exist_ok=True)
        print(f"   Created {directory}")

def create_training_config():
    """Create training configuration file"""
    print("Creating training configuration...")
    
    config = {
        "model": {
            "num_node_features": 62,
            "num_edge_features": 8,
            "hidden_dim": 256,
            "num_classes": 2,
            "num_vuln_types": 10
        },
        "training": {
            "batch_size": 32,
            "learning_rate": 0.001,
            "weight_decay": 1e-5,
            "epochs": 200,
            "patience": 20,
            "validation_split": 0.2
        },
        "dataset": {
            "min_samples": 1000,
            "languages": ["c", "java"],
            "cwe_types": [
                "CWE-120", "CWE-89", "CWE-78", "CWE-134",
                "CWE-476", "CWE-415", "CWE-401", "CWE-190", "CWE-22"
            ]
        }
    }
    
    os.makedirs("data/gnn_training", exist_ok=True)
    with open("data/gnn_training/config.json", "w", encoding='utf-8') as f:
        json.dump(config, f, indent=2)
    
    print("   Created training configuration")

def create_training_script():
    """Create simple training execution script"""
    print("Creating training execution script...")
    
    script_content = '''#!/usr/bin/env python3
"""
Execute GNN Training
"""
import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from src.ml.training.train_gnn_complete import main

if __name__ == "__main__":
    print("Starting Enhanced GNN Training...")
    print("This will take some time depending on your system.")
    print("Expected training time: 30-60 minutes on your AMD Ryzen 5 5625U")
    print()
    
    try:
        main()
    except KeyboardInterrupt:
        print("\\nTraining interrupted by user")
    except Exception as e:
        print(f"\\nTraining failed: {e}")
        import traceback
        traceback.print_exc()
'''
    
    with open("train_gnn.py", "w", encoding='utf-8') as f:
        f.write(script_content)
    
    print("   Created train_gnn.py execution script")

def create_test_script():
    """Create testing script for the trained model"""
    print("Creating model test script...")
    
    test_content = '''#!/usr/bin/env python3
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
    printf("Input: %s\\\\n", buffer);
}"""
    
    try:
        vuln_prob, vuln_type, confidence, analysis = detector.predict(test_code, "c")
        
        print("\\nTest Results:")
        print(f"   Vulnerability Probability: {vuln_prob:.2%}")
        print(f"   Type: {vuln_type}")
        print(f"   Confidence: {confidence:.2%}")
        print(f"   Analysis: {analysis}")
        
        if vuln_prob > 0.7:
            print("\\nModel correctly identified vulnerability!")
        else:
            print("\\nModel may need more training")
            
    except Exception as e:
        print(f"   Test failed: {e}")

if __name__ == "__main__":
    test_trained_model()
'''
    
    with open("test_gnn.py", "w", encoding='utf-8') as f:
        f.write(test_content)
    
    print("   Created test_gnn.py")

def create_requirements_file():
    """Create requirements file for the new training"""
    print("Creating requirements file...")
    
    requirements = """# Additional requirements for GNN training
torch-geometric>=2.4.0
matplotlib>=3.7.0
seaborn>=0.12.0
scikit-learn>=1.3.0
requests>=2.31.0
lxml>=4.9.0
numpy>=1.24.0
"""
    
    with open("requirements_gnn.txt", "w", encoding='utf-8') as f:
        f.write(requirements)
    
    print("   Created requirements_gnn.txt")

def main():
    """Main setup function"""
    print("Setting up Enhanced GNN Training Pipeline")
    print("=" * 60)
    
    # Step 1: Clean old data
    clean_old_training_data()
    
    # Step 2: Setup directories
    setup_directories()
    
    # Step 3: Create configuration
    create_training_config()
    
    # Step 4: Create scripts
    create_training_script()
    create_test_script()
    
    # Step 5: Create requirements
    create_requirements_file()
    
    print("\n" + "=" * 60)
    print("SETUP COMPLETED!")
    print("=" * 60)
    
    print("\nNext Steps:")
    print("1. Install dependencies:")
    print("   pip install torch-geometric matplotlib seaborn scikit-learn requests lxml")
    
    print("\n2. Start training:")
    print("   python train_gnn.py")
    
    print("\n3. Test the trained model:")
    print("   python test_gnn.py")
    
    print("\nExpected Results:")
    print("   • Training time: 30-60 minutes")
    print("   • Target accuracy: 85-95%")
    print("   • Model size: ~50-100MB")

if __name__ == "__main__":
    main()