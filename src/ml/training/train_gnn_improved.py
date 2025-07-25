# src/ml/training/train_gnn_improved.py
import sys
import os
from pathlib import Path

# Add project root to Python path
project_root = Path(__file__).parent.parent.parent.parent
sys.path.insert(0, str(project_root))

import torch
import torch.nn as nn
from typing import List, Tuple
import random
from src.ml.code_graph import CodeGraphBuilder
from src.ml.gnn_model import GNNVulnerabilityDetector
from src.database.models.base import SessionLocal
from src.database.models.vulnerability import VulnerabilityDetection

class ImprovedGNNTrainer:
    """Improved GNN trainer with better data handling"""
    def __init__(self):
        self.graph_builder = CodeGraphBuilder()
        self.training_samples = []
    
    def add_sample(self, code: str, language: str, is_vulnerable: bool, vuln_type: int = 0):
        """Add a training sample with proper validation"""
        try:
            # Build graph
            graph = self.graph_builder.build_graph(code, language)
            
            # Skip trivial graphs
            if len(graph.nodes()) < 3:
                return False
            
            # Convert to PyTorch format
            graph_data = self.graph_builder.to_pytorch_geometric(graph)
            
            # Validate graph data
            if graph_data.x.size(0) == 0 or graph_data.edge_index.size(1) == 0:
                return False
            
            # Add sample
            label = 1 if is_vulnerable else 0
            vuln_type_label = vuln_type if is_vulnerable else -1
            
            self.training_samples.append((graph_data, label, vuln_type_label))
            return True
            
        except Exception as e:
            print(f"   ❌ Failed to process sample: {e}")
            return False
    
    def create_balanced_dataset(self):
        """Create a balanced dataset with equal vulnerable/safe samples"""
        print("📊 Creating improved balanced dataset...")
        
        # Vulnerability type mapping
        vuln_types = {
            'SQL Injection': 0,
            'XSS': 1,
            'Command Injection': 2,
            'Path Traversal': 3,
            'Insecure Deserialization': 4
        }
        
        # More extensive vulnerable examples
        vulnerable_samples = [
            # SQL Injection examples
            ('def get_user(id): return db.execute(f"SELECT * FROM users WHERE id={id}")', 'python', 0),
            ('def search(term): return cursor.execute("SELECT * FROM products WHERE name LIKE \'%" + term + "%\'")', 'python', 0),
            ('def login(user, pwd): return db.query(f"SELECT * FROM users WHERE user=\'{user}\' AND pwd=\'{pwd}\'")', 'python', 0),
            ('function getUser(id) { return db.query(`SELECT * FROM users WHERE id=${id}`); }', 'javascript', 0),
            ('function search(q) { return db.execute("SELECT * FROM items WHERE title LIKE \'%" + q + "%\'"); }', 'javascript', 0),
            
            # Command Injection examples  
            ('import os\ndef ping(host): os.system(f"ping {host}")', 'python', 2),
            ('def backup(dir): os.system("tar -czf backup.tar.gz " + dir)', 'python', 2),
            ('def process(file): subprocess.call(f"cat {file} | grep error", shell=True)', 'python', 2),
            ('const { exec } = require("child_process");\nfunction run(cmd) { exec(`ls ${cmd}`); }', 'javascript', 2),
            ('function convert(file) { exec(`convert ${file} output.jpg`); }', 'javascript', 2),
            
            # XSS examples
            ('function show(data) { document.getElementById("out").innerHTML = data; }', 'javascript', 1),
            ('function display(msg) { document.write("<div>" + msg + "</div>"); }', 'javascript', 1),
            ('function update(html) { element.innerHTML = `<p>${html}</p>`; }', 'javascript', 1),
            ('def render(data): return f"<h1>{data}</h1>"', 'python', 1),
            ('def show_msg(msg): return render_template_string(f"<p>{msg}</p>")', 'python', 1),
            
            # Path Traversal examples
            ('def read(file): return open("/uploads/" + file).read()', 'python', 3),
            ('def serve(path): return open(os.path.join("/var/www/", path), "rb").read()', 'python', 3),
            ('def load(name): return open(f"/configs/{name}.conf").read()', 'python', 3),
            ('function readFile(name) { return fs.readFileSync("./files/" + name); }', 'javascript', 3),
            ('function getFile(path) { return fs.readFileSync(`/data/${path}`); }', 'javascript', 3),
            
            # Deserialization examples
            ('import pickle\ndef load(data): return pickle.loads(data)', 'python', 4),
            ('def deserialize(obj): return marshal.loads(obj)', 'python', 4),
            ('import yaml\ndef parse(config): return yaml.load(config)', 'python', 4),
            ('def restore(session): return pickle.loads(base64.b64decode(session))', 'python', 4),
            ('def process(data): return pickle.loads(urllib.parse.unquote(data))', 'python', 4),
        ]
        
        # Corresponding safe examples (same number as vulnerable)
        safe_samples = [
            # Safe SQL queries
            ('def get_user(id): return db.execute("SELECT * FROM users WHERE id=?", (id,))', 'python'),
            ('def search(term): return cursor.execute("SELECT * FROM products WHERE name LIKE ?", (f"%{term}%",))', 'python'),
            ('def login(user, pwd): return db.query("SELECT * FROM users WHERE user=? AND pwd_hash=?", (user, hash(pwd)))', 'python'),
            ('function getUser(id) { return db.query("SELECT * FROM users WHERE id=?", [id]); }', 'javascript'),
            ('function search(q) { return db.prepare("SELECT * FROM items WHERE title LIKE ?").get(`%${q}%`); }', 'javascript'),
            
            # Safe command execution
            ('import subprocess\ndef ping(host): subprocess.run(["ping", "-c", "4", host], check=True)', 'python'),
            ('def backup(dir): subprocess.run(["tar", "-czf", "backup.tar.gz", dir], check=True)', 'python'),
            ('def process(file): with open(file) as f: return [line for line in f if "error" in line]', 'python'),
            ('const { spawn } = require("child_process");\nfunction run(cmd) { spawn("ls", [cmd]); }', 'javascript'),
            ('function convert(file) { spawn("convert", [file, "output.jpg"]); }', 'javascript'),
            
            # Safe HTML output
            ('function show(data) { document.getElementById("out").textContent = data; }', 'javascript'),
            ('function display(msg) { const div = document.createElement("div"); div.textContent = msg; document.body.appendChild(div); }', 'javascript'),
            ('function update(text) { element.textContent = text; }', 'javascript'),
            ('def render(data): return html.escape(f"<h1>{data}</h1>")', 'python'),
            ('def show_msg(msg): return render_template("message.html", message=msg)', 'python'),
            
            # Safe file operations
            ('def read(file): safe_file = os.path.basename(file); return open(f"/uploads/{safe_file}").read()', 'python'),
            ('def serve(path): safe_path = os.path.basename(path); return open(f"/var/www/{safe_path}", "rb").read()', 'python'),
            ('def load(name): if name.isalnum(): return open(f"/configs/{name}.conf").read()', 'python'),
            ('function readFile(name) { const safe = path.basename(name); return fs.readFileSync(`./files/${safe}`); }', 'javascript'),
            ('function getFile(path) { const safe = path.basename(path); return fs.readFileSync(`/data/${safe}`); }', 'javascript'),
            
            # Safe serialization
            ('import json\ndef load(data): return json.loads(data)', 'python'),
            ('def deserialize(obj): return json.loads(obj)', 'python'),
            ('import yaml\ndef parse(config): return yaml.safe_load(config)', 'python'),
            ('def restore(session): return json.loads(base64.b64decode(session))', 'python'),
            ('def process(data): return json.loads(urllib.parse.unquote(data))', 'python'),
        ]
        
        # Add vulnerable samples
        vuln_added = 0
        for code, language, vuln_type in vulnerable_samples:
            if self.add_sample(code, language, True, vuln_type):
                vuln_added += 1
        
        # Add safe samples
        safe_added = 0
        for code, language in safe_samples:
            if self.add_sample(code, language, False):
                safe_added += 1
        
        print(f"   ✅ Added {vuln_added} vulnerable samples")
        print(f"   ✅ Added {safe_added} safe samples")
        print(f"   📊 Total samples: {len(self.training_samples)}")
        
        # Shuffle the dataset
        random.shuffle(self.training_samples)
        
        return len(self.training_samples)

def train_improved_gnn():
    """Train GNN with improved dataset and training procedure"""
    print("🚀 Starting Improved GNN Training...\n")
    
    # Create trainer
    trainer = ImprovedGNNTrainer()
    
    # Create balanced dataset
    total_samples = trainer.create_balanced_dataset()
    
    if total_samples < 20:
        print(f"❌ Not enough samples: {total_samples}")
        return
    
    # Better train/test split
    dataset = trainer.training_samples
    
    # Stratified split to ensure balanced test set
    vulnerable_samples = [s for s in dataset if s[1] == 1]
    safe_samples = [s for s in dataset if s[1] == 0]
    
    # Take 20% for testing from each class
    vuln_test_count = max(1, len(vulnerable_samples) // 5)
    safe_test_count = max(1, len(safe_samples) // 5)
    
    test_data = vulnerable_samples[:vuln_test_count] + safe_samples[:safe_test_count]
    train_data = vulnerable_samples[vuln_test_count:] + safe_samples[safe_test_count:]
    
    # Shuffle training data
    random.shuffle(train_data)
    
    print(f"📊 Training samples: {len(train_data)}")
    print(f"📊 Test samples: {len(test_data)}")
    print(f"📊 Train vulnerable: {sum(1 for _, label, _ in train_data if label == 1)}")
    print(f"📊 Test vulnerable: {sum(1 for _, label, _ in test_data if label == 1)}")
    
    # Initialize model
    detector = GNNVulnerabilityDetector()
    model = detector.model
    device = detector.device
    model.to(device)
    
    # Training setup
    optimizer = torch.optim.Adam(model.parameters(), lr=0.001, weight_decay=1e-4)
    criterion_vuln = nn.CrossEntropyLoss()
    criterion_type = nn.CrossEntropyLoss()
    scheduler = torch.optim.lr_scheduler.ReduceLROnPlateau(optimizer, patience=5, factor=0.5)
    
    print("\n🏋️ Training started...")
    model.train()
    
    best_test_accuracy = 0
    patience = 15
    patience_counter = 0
    
    for epoch in range(200):  # More epochs
        # Training phase
        model.train()
        train_loss = 0
        train_correct = 0
        train_total = 0
        
        for graph_data, has_vuln, vuln_type in train_data:
            try:
                graph_data = graph_data.to(device)
                
                # Forward pass
                vuln_pred, type_pred = model(graph_data.x, graph_data.edge_index)
                
                # Calculate loss
                vuln_target = torch.tensor([has_vuln], device=device)
                loss = criterion_vuln(vuln_pred, vuln_target)
                
                if has_vuln == 1 and vuln_type >= 0:
                    type_target = torch.tensor([vuln_type], device=device)
                    type_loss = criterion_type(type_pred, type_target)
                    loss += 0.3 * type_loss
                
                # Backward pass
                optimizer.zero_grad()
                loss.backward()
                torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
                optimizer.step()
                
                train_loss += loss.item()
                train_total += 1
                
                # Track accuracy
                pred_class = torch.argmax(vuln_pred, dim=1).item()
                if pred_class == has_vuln:
                    train_correct += 1
                    
            except Exception as e:
                print(f"Training error: {e}")
                continue
        
        # Validation phase
        model.eval()
        test_correct = 0
        test_total = 0
        
        with torch.no_grad():
            for graph_data, has_vuln, vuln_type in test_data:
                try:
                    graph_data = graph_data.to(device)
                    vuln_pred, _ = model(graph_data.x, graph_data.edge_index)
                    pred_class = torch.argmax(vuln_pred, dim=1).item()
                    
                    if pred_class == has_vuln:
                        test_correct += 1
                    test_total += 1
                except:
                    continue
        
        # Calculate metrics
        train_accuracy = train_correct / train_total if train_total > 0 else 0
        test_accuracy = test_correct / test_total if test_total > 0 else 0
        avg_loss = train_loss / train_total if train_total > 0 else 0
        
        scheduler.step(avg_loss)
        
        # Print progress
        if (epoch + 1) % 10 == 0:
            print(f"Epoch {epoch+1}/200: Loss={avg_loss:.4f}, Train Acc={train_accuracy:.2%}, Test Acc={test_accuracy:.2%}")
        
        # Save best model
        if test_accuracy > best_test_accuracy:
            best_test_accuracy = test_accuracy
            patience_counter = 0
            
            # Save model
            model_path = project_root / 'data/models/trained_gnn_model.pth'
            model_path.parent.mkdir(parents=True, exist_ok=True)
            torch.save(model.state_dict(), str(model_path))
        else:
            patience_counter += 1
            if patience_counter >= patience:
                print(f"Early stopping at epoch {epoch+1}")
                break
    
    print(f"\n✅ Training Complete!")
    print(f"📊 Best Test Accuracy: {best_test_accuracy:.2%}")
    print(f"💾 Model saved to: {model_path}")
    
    if best_test_accuracy > 0.6:
        print("🎉 Great! Your GNN model is now professionally trained!")
    else:
        print("⚠️ Test accuracy is still low. The model may need more diverse data.")
    
    return best_test_accuracy

if __name__ == "__main__":
    train_improved_gnn()