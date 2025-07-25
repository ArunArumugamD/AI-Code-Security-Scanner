# src/ml/training/train_gnn.py
import sys
import os
from pathlib import Path

# Add project root to Python path
project_root = Path(__file__).parent.parent.parent.parent
sys.path.insert(0, str(project_root))

import torch
import torch.nn as nn
from typing import List, Tuple
from src.ml.code_graph import CodeGraphBuilder
from src.ml.gnn_model import GNNVulnerabilityDetector
from src.database.models.base import SessionLocal
from src.database.models.vulnerability import VulnerabilityDetection

class GNNTrainingDataGenerator:
    """Generator for creating GNN training data"""
    def __init__(self):
        self.graph_builder = CodeGraphBuilder()
        self.training_samples = []
    
    def add_vulnerable_sample(self, code: str, language: str, vuln_type: int):
        """Add a vulnerable code sample"""
        try:
            graph = self.graph_builder.build_graph(code, language)
            graph_data = self.graph_builder.to_pytorch_geometric(graph)
            # Label: (has_vulnerability=1, vulnerability_type)
            self.training_samples.append((graph_data, 1, vuln_type))
            return True
        except Exception as e:
            print(f"Failed to process vulnerable sample: {e}")
            return False
    
    def add_safe_sample(self, code: str, language: str):
        """Add a safe code sample"""
        try:
            graph = self.graph_builder.build_graph(code, language)
            graph_data = self.graph_builder.to_pytorch_geometric(graph)
            # Label: (has_vulnerability=0, no_type=-1)
            self.training_samples.append((graph_data, 0, -1))
            return True
        except Exception as e:
            print(f"Failed to process safe sample: {e}")
            return False
    
    def save_dataset(self, path: str):
        """Save the dataset"""
        full_path = project_root / path
        full_path.parent.mkdir(parents=True, exist_ok=True)
        torch.save(self.training_samples, str(full_path))
        print(f"Saved {len(self.training_samples)} samples to {full_path}")

def create_training_dataset():
    """Create dataset from your existing database and examples"""
    generator = GNNTrainingDataGenerator()
    db = SessionLocal()
    
    print("📊 Creating training dataset...")
    
    # Get confirmed vulnerabilities from your database
    confirmed_vulns = db.query(VulnerabilityDetection).filter(
        VulnerabilityDetection.verified_by_user == True,
        VulnerabilityDetection.status == 'confirmed'
    ).limit(100).all()  # Limit for initial training
    
    print(f"Found {len(confirmed_vulns)} confirmed vulnerabilities in database")
    
    # Map vulnerability types
    vuln_type_map = {
        'SQL Injection': 0,
        'XSS': 1,
        'Cross-Site Scripting': 1,
        'Command Injection': 2,
        'Path Traversal': 3,
        'Insecure Deserialization': 4
    }
    
    # Add vulnerable samples from database
    db_samples_added = 0
    for vuln in confirmed_vulns:
        if vuln.code_snippet and len(vuln.code_snippet) > 10:
            # Try to get vuln type from pattern name
            vuln_name = vuln.pattern.name if vuln.pattern else "Unknown"
            vuln_type = vuln_type_map.get(vuln_name, 0)
            
            # Detect language from file path
            language = 'python'  # default
            if vuln.file_path.endswith('.js'):
                language = 'javascript'
            elif vuln.file_path.endswith('.java'):
                language = 'java'
            
            if generator.add_vulnerable_sample(vuln.code_snippet, language, vuln_type):
                db_samples_added += 1
    
    print(f"Added {db_samples_added} samples from database")
    
    # Add manual vulnerable examples
    vulnerable_examples = {
        'SQL Injection': [
            ("""
def get_user_data(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    return cursor.fetchall()
""", 'python'),
            ("""
def search_products(name):
    sql = "SELECT * FROM products WHERE name LIKE '%" + name + "%'"
    return db.execute(sql)
""", 'python'),
        ],
        'Command Injection': [
            ("""
import os
def ping_server(host):
    os.system(f"ping -c 4 {host}")
""", 'python'),
            ("""
def process_file(filename):
    os.system("cat " + filename + " | grep error")
""", 'python'),
        ],
        'XSS': [
            ("""
function displayMessage(userInput) {
    document.getElementById('output').innerHTML = userInput;
}
""", 'javascript'),
        ],
    }
    
    # Add manual vulnerable samples
    manual_vuln_added = 0
    for vuln_name, samples in vulnerable_examples.items():
        vuln_type = vuln_type_map.get(vuln_name, 0)
        for code, language in samples:
            if generator.add_vulnerable_sample(code, language, vuln_type):
                manual_vuln_added += 1
    
    print(f"Added {manual_vuln_added} manual vulnerable examples")
    
    # Add safe code examples
    safe_examples = [
        ("""
def get_user_data(user_id):
    query = "SELECT * FROM users WHERE id = ?"
    cursor.execute(query, (user_id,))
    return cursor.fetchall()
""", 'python'),
        ("""
def search_products(name):
    sql = "SELECT * FROM products WHERE name LIKE ?"
    return db.execute(sql, (f"%{name}%",))
""", 'python'),
        ("""
import subprocess
def ping_server(host):
    if validate_hostname(host):
        subprocess.run(['ping', '-c', '4', host], check=True)
""", 'python'),
        ("""
function displayMessage(userInput) {
    document.getElementById('output').textContent = userInput;
}
""", 'javascript'),

    ("""
def validate_email(email):
    # Safe: using regex for validation, no execution
    import re
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None
""", 'python'),

    ]
    
    safe_added = 0
    for safe_code, language in safe_examples:
        if generator.add_safe_sample(safe_code, language):
            safe_added += 1
    
    print(f"Added {safe_added} safe examples")
    
    # Save dataset
    generator.save_dataset('data/models/gnn_training_data.pt')
    db.close()
    
    print(f"\n✅ Total training samples: {len(generator.training_samples)}")
    return generator.training_samples

def train_gnn_model():
    """Train the GNN model"""
    print("🚀 Starting GNN Training...\n")
    
    # Load or create dataset
    dataset_path = project_root / 'data/models/gnn_training_data.pt'
    try:
        dataset = torch.load(str(dataset_path))
        print(f"📊 Loaded existing dataset: {len(dataset)} samples")
    except:
        print("Creating new training dataset...")
        dataset = create_training_dataset()
    
    if len(dataset) < 10:
        print("❌ Not enough training samples! Need at least 10.")
        return
    
    # Split dataset (80/20 train/test)
    train_size = int(0.8 * len(dataset))
    train_data = dataset[:train_size]
    test_data = dataset[train_size:]
    
    print(f"📊 Training samples: {len(train_data)}")
    print(f"📊 Test samples: {len(test_data)}")
    
    # Initialize model
    detector = GNNVulnerabilityDetector()
    model = detector.model
    device = detector.device
    model.to(device)
    
    # Training setup
    optimizer = torch.optim.Adam(model.parameters(), lr=0.001)
    criterion_vuln = nn.CrossEntropyLoss()
    criterion_type = nn.CrossEntropyLoss()
    
    # Training loop
    print("\n🏋️ Training started...")
    model.train()
    
    best_accuracy = 0
    for epoch in range(50):  # 50 epochs for quick training
        total_loss = 0
        correct = 0
        
        for graph_data, has_vuln, vuln_type in train_data:
            try:
                graph_data = graph_data.to(device)
                
                # Forward pass
                vuln_pred, type_pred = model(
                    graph_data.x,
                    graph_data.edge_index
                )
                
                # Calculate loss
                vuln_target = torch.tensor([has_vuln], device=device)
                loss = criterion_vuln(vuln_pred, vuln_target)
                
                if has_vuln == 1 and vuln_type >= 0:
                    type_target = torch.tensor([vuln_type], device=device)
                    loss += criterion_type(type_pred, type_target)
                
                # Backward pass
                optimizer.zero_grad()
                loss.backward()
                optimizer.step()
                
                total_loss += loss.item()
                
                # Track accuracy
                pred_class = torch.argmax(vuln_pred, dim=1).item()
                if pred_class == has_vuln:
                    correct += 1
                    
            except Exception as e:
                print(f"Training error: {e}")
                continue
        
        # Calculate epoch metrics
        accuracy = correct / len(train_data) if len(train_data) > 0 else 0
        avg_loss = total_loss / len(train_data) if len(train_data) > 0 else 0
        
        # Print progress every 10 epochs
        if (epoch + 1) % 10 == 0:
            print(f"Epoch {epoch+1}/50: Loss={avg_loss:.4f}, Accuracy={accuracy:.2%}")
        
        # Save best model
        if accuracy > best_accuracy:
            best_accuracy = accuracy
    
    print(f"\n✅ Training Complete! Best accuracy: {best_accuracy:.2%}")
    
    # Test the model
    print("\n🧪 Testing model...")
    model.eval()
    test_correct = 0
    with torch.no_grad():
        for graph_data, has_vuln, vuln_type in test_data:
            try:
                graph_data = graph_data.to(device)
                vuln_pred, _ = model(graph_data.x, graph_data.edge_index)
                pred_class = torch.argmax(vuln_pred, dim=1).item()
                if pred_class == has_vuln:
                    test_correct += 1
            except:
                continue
    
    test_accuracy = test_correct / len(test_data) if len(test_data) > 0 else 0
    print(f"📊 Test Accuracy: {test_accuracy:.2%}")
    
    # Save trained model
    model_path = project_root / 'data/models/trained_gnn_model.pth'
    model_path.parent.mkdir(parents=True, exist_ok=True)
    torch.save(model.state_dict(), str(model_path))
    print(f"\n💾 Model saved to {model_path}")
    
    print("\n🎉 GNN is now trained and ready to use!")
    print("Update your GNN analyzer to use 'data/models/trained_gnn_model.pth'")

if __name__ == "__main__":
    train_gnn_model()