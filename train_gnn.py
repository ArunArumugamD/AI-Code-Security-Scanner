#!/usr/bin/env python3
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
        print("\nTraining interrupted by user")
    except Exception as e:
        print(f"\nTraining failed: {e}")
        import traceback
        traceback.print_exc()
