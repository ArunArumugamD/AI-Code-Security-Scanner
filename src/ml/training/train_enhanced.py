# src/ml/training/train_gnn_enhanced.py
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

class EnhancedGNNTrainingDataGenerator:
    """Enhanced generator with comprehensive training data"""
    def __init__(self):
        self.graph_builder = CodeGraphBuilder()
        self.training_samples = []
    
    def add_vulnerable_sample(self, code: str, language: str, vuln_type: int):
        """Add a vulnerable code sample"""
        try:
            graph = self.graph_builder.build_graph(code, language)
            if len(graph.nodes()) < 3:  # Skip trivial graphs
                return False
            graph_data = self.graph_builder.to_pytorch_geometric(graph)
            self.training_samples.append((graph_data, 1, vuln_type))
            return True
        except Exception as e:
            print(f"Failed to process vulnerable sample: {e}")
            return False
    
    def add_safe_sample(self, code: str, language: str):
        """Add a safe code sample"""
        try:
            graph = self.graph_builder.build_graph(code, language)
            if len(graph.nodes()) < 3:  # Skip trivial graphs
                return False
            graph_data = self.graph_builder.to_pytorch_geometric(graph)
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

def create_comprehensive_training_dataset():
    """Create a comprehensive dataset with many more examples"""
    generator = EnhancedGNNTrainingDataGenerator()
    db = SessionLocal()
    
    print("📊 Creating comprehensive training dataset...")
    
    # Map vulnerability types
    vuln_type_map = {
        'SQL Injection': 0,
        'XSS': 1,
        'Cross-Site Scripting': 1,
        'Command Injection': 2,
        'Path Traversal': 3,
        'Insecure Deserialization': 4
    }
    
    # Extensive vulnerable examples
    vulnerable_examples = {
        'SQL Injection': [
            # Python SQL injection examples
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
            ("""
def login_user(username, password):
    query = "SELECT * FROM users WHERE username='" + username + "' AND password='" + password + "'"
    result = cursor.execute(query)
    return result.fetchone()
""", 'python'),
            ("""
def get_orders(customer_id):
    sql = f"SELECT o.*, c.name FROM orders o JOIN customers c ON o.customer_id = c.id WHERE c.id = {customer_id}"
    return database.query(sql)
""", 'python'),
            ("""
def delete_record(table, record_id):
    query = f"DELETE FROM {table} WHERE id = {record_id}"
    db.execute(query)
""", 'python'),
            # JavaScript SQL injection
            ("""
function getUserByEmail(email) {
    const query = `SELECT * FROM users WHERE email = '${email}'`;
    return database.query(query);
}
""", 'javascript'),
            ("""
function searchItems(searchTerm) {
    const sql = "SELECT * FROM items WHERE title LIKE '%" + searchTerm + "%'";
    return db.execute(sql);
}
""", 'javascript'),
        ],
        
        'Command Injection': [
            # Python command injection
            ("""
import os
def ping_server(host):
    os.system(f"ping -c 4 {host}")
""", 'python'),
            ("""
def process_file(filename):
    os.system("cat " + filename + " | grep error")
""", 'python'),
            ("""
import subprocess
def backup_data(directory):
    subprocess.call(f"tar -czf backup.tar.gz {directory}", shell=True)
""", 'python'),
            ("""
def scan_network(ip_range):
    command = f"nmap -sP {ip_range}"
    os.popen(command).read()
""", 'python'),
            ("""
def convert_file(input_file, output_format):
    cmd = f"convert {input_file} output.{output_format}"
    os.system(cmd)
""", 'python'),
            # JavaScript command injection
            ("""
const { exec } = require('child_process');
function processData(userInput) {
    exec(`grep "${userInput}" data.txt`, (error, stdout) => {
        console.log(stdout);
    });
}
""", 'javascript'),
        ],
        
        'XSS': [
            # JavaScript XSS examples
            ("""
function displayMessage(userInput) {
    document.getElementById('output').innerHTML = userInput;
}
""", 'javascript'),
            ("""
function createNotification(message) {
    const div = document.createElement('div');
    div.innerHTML = '<p>' + message + '</p>';
    document.body.appendChild(div);
}
""", 'javascript'),
            ("""
function updateProfile(userData) {
    document.querySelector('#profile').innerHTML = `
        <h2>Welcome ${userData.name}</h2>
        <p>Bio: ${userData.bio}</p>
    `;
}
""", 'javascript'),
            ("""
function showError(errorMsg) {
    document.write('<div class="error">' + errorMsg + '</div>');
}
""", 'javascript'),
            # Python XSS (template injection)
            ("""
from flask import render_template_string
def show_greeting(name):
    template = f"<h1>Hello {name}!</h1>"
    return render_template_string(template)
""", 'python'),
        ],
        
        'Path Traversal': [
            # Python path traversal
            ("""
def read_user_file(filename):
    with open('/uploads/' + filename, 'r') as f:
        return f.read()
""", 'python'),
            ("""
def serve_file(filepath):
    full_path = os.path.join('/var/www/', filepath)
    with open(full_path, 'rb') as f:
        return f.read()
""", 'python'),
            ("""
def load_config(config_name):
    config_path = f"/etc/myapp/{config_name}.conf"
    return open(config_path).read()
""", 'python'),
            # JavaScript path traversal
            ("""
const fs = require('fs');
function readFile(filename) {
    return fs.readFileSync('./uploads/' + filename, 'utf8');
}
""", 'javascript'),
        ],
        
        'Insecure Deserialization': [
            # Python deserialization
            ("""
import pickle
def load_session(session_data):
    return pickle.loads(session_data)
""", 'python'),
            ("""
import yaml
def load_config(config_data):
    return yaml.load(config_data)
""", 'python'),
            ("""
def deserialize_object(data):
    import marshal
    return marshal.loads(data)
""", 'python'),
            ("""
def process_data(serialized_data):
    import pickle
    obj = pickle.loads(base64.b64decode(serialized_data))
    return obj.process()
""", 'python'),
        ]
    }
    
    # Add vulnerable samples
    vuln_added = 0
    for vuln_name, samples in vulnerable_examples.items():
        vuln_type = vuln_type_map.get(vuln_name, 0)
        for code, language in samples:
            if generator.add_vulnerable_sample(code, language, vuln_type):
                vuln_added += 1
                print(f"   ✓ Added {vuln_name} sample ({language})")
    
    print(f"Added {vuln_added} vulnerable examples")
    
    # Extensive safe code examples
    safe_examples = [
        # Safe SQL queries
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
def login_user(username, password):
    query = "SELECT * FROM users WHERE username = ? AND password_hash = ?"
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    return cursor.execute(query, (username, password_hash)).fetchone()
""", 'python'),
        
        # Safe command execution
        ("""
import subprocess
def ping_server(host):
    if validate_hostname(host):
        result = subprocess.run(['ping', '-c', '4', host], 
                              capture_output=True, text=True, check=True)
        return result.stdout
""", 'python'),
        ("""
def process_file(filename):
    if validate_filename(filename):
        with open(filename, 'r') as f:
            return [line for line in f if 'error' in line]
""", 'python'),
        ("""
def backup_data(directory):
    if os.path.isdir(directory) and is_safe_path(directory):
        subprocess.run(['tar', '-czf', 'backup.tar.gz', directory], check=True)
""", 'python'),
        
        # Safe HTML output
        ("""
function displayMessage(userInput) {
    const sanitized = escapeHtml(userInput);
    document.getElementById('output').textContent = sanitized;
}
""", 'javascript'),
        ("""
function createNotification(message) {
    const div = document.createElement('div');
    const p = document.createElement('p');
    p.textContent = message;
    div.appendChild(p);
    document.body.appendChild(div);
}
""", 'javascript'),
        ("""
function updateProfile(userData) {
    document.querySelector('#name').textContent = userData.name;
    document.querySelector('#bio').textContent = userData.bio;
}
""", 'javascript'),
        
        # Safe file operations
        ("""
def read_user_file(filename):
    safe_filename = os.path.basename(filename)
    safe_path = os.path.join('/uploads/', safe_filename)
    if os.path.exists(safe_path) and is_safe_path(safe_path):
        with open(safe_path, 'r') as f:
            return f.read()
""", 'python'),
        ("""
def serve_file(filepath):
    safe_path = os.path.join('/var/www/', os.path.basename(filepath))
    if os.path.exists(safe_path) and safe_path.startswith('/var/www/'):
        with open(safe_path, 'rb') as f:
            return f.read()
""", 'python'),
        
        # Safe deserialization
        ("""
import json
def load_session(session_data):
    return json.loads(session_data)
""", 'python'),
        ("""
import yaml
def load_config(config_data):
    return yaml.safe_load(config_data)
""", 'python'),
        
        # Additional safe examples for variety
        ("""
def calculate_total(items):
    total = 0
    for item in items:
        if isinstance(item.price, (int, float)) and item.price > 0:
            total += item.price
    return total
""", 'python'),
        ("""
def validate_email(email):
    import re
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None
""", 'python'),
        ("""
function formatCurrency(amount) {
    if (typeof amount !== 'number' || amount < 0) {
        return '$0.00';
    }
    return '$' + amount.toFixed(2);
}
""", 'javascript'),
        ("""
def hash_password(password):
    import hashlib
    import secrets
    salt = secrets.token_hex(16)
    return hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
""", 'python'),
        ("""
function validateInput(input) {
    const allowedChars = /^[a-zA-Z0-9\s-_]+$/;
    return allowedChars.test(input) && input.length <= 100;
}
""", 'javascript'),
    ]
    
    safe_added = 0
    for safe_code, language in safe_examples:
        if generator.add_safe_sample(safe_code, language):
            safe_added += 1
            print(f"   ✓ Added safe sample ({language})")
    
    print(f"Added {safe_added} safe examples")
    
    # Try to get samples from database if available
    try:
        confirmed_vulns = db.query(VulnerabilityDetection).filter(
            VulnerabilityDetection.verified_by_user == True,
            VulnerabilityDetection.status == 'confirmed'
        ).all()
        
        db_added = 0
        for vuln in confirmed_vulns:
            if vuln.code_snippet and len(vuln.code_snippet.strip()) > 20:
                vuln_name = vuln.pattern.name if vuln.pattern else "SQL Injection"
                vuln_type = vuln_type_map.get(vuln_name, 0)
                
                language = 'python'
                if vuln.file_path.endswith('.js'):
                    language = 'javascript'
                elif vuln.file_path.endswith('.java'):
                    language = 'java'
                
                if generator.add_vulnerable_sample(vuln.code_snippet, language, vuln_type):
                    db_added += 1
        
        print(f"Added {db_added} samples from database")
    except Exception as e:
        print(f"Could not load from database: {e}")
    
    # Save dataset
    generator.save_dataset('data/models/gnn_training_data.pt')
    db.close()
    
    print(f"\n✅ Total training samples: {len(generator.training_samples)}")
    return generator.training_samples

def train_gnn_model():
    """Train the GNN model with enhanced data"""
    print("🚀 Starting Enhanced GNN Training...\n")
    
    # Force recreation of dataset with more samples
    print("Creating comprehensive training dataset...")
    dataset = create_comprehensive_training_dataset()
    
    if len(dataset) < 20:
        print(f"❌ Still not enough training samples! Got {len(dataset)}, need at least 20.")
        print("The model needs more diverse code examples to learn effectively.")
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
    optimizer = torch.optim.Adam(model.parameters(), lr=0.001, weight_decay=1e-5)
    criterion_vuln = nn.CrossEntropyLoss()
    criterion_type = nn.CrossEntropyLoss()
    scheduler = torch.optim.lr_scheduler.StepLR(optimizer, step_size=20, gamma=0.5)
    
    # Training loop
    print("\n🏋️ Training started...")
    model.train()
    
    best_accuracy = 0
    patience = 10
    patience_counter = 0
    
    for epoch in range(100):  # More epochs for better training
        total_loss = 0
        correct = 0
        total_samples = 0
        
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
                    type_loss = criterion_type(type_pred, type_target)
                    loss += 0.5 * type_loss  # Weight the type loss
                
                # Backward pass
                optimizer.zero_grad()
                loss.backward()
                torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)  # Gradient clipping
                optimizer.step()
                
                total_loss += loss.item()
                total_samples += 1
                
                # Track accuracy
                pred_class = torch.argmax(vuln_pred, dim=1).item()
                if pred_class == has_vuln:
                    correct += 1
                    
            except Exception as e:
                print(f"Training error: {e}")
                continue
        
        scheduler.step()
        
        # Calculate epoch metrics
        accuracy = correct / total_samples if total_samples > 0 else 0
        avg_loss = total_loss / total_samples if total_samples > 0 else 0
        
        # Print progress every 10 epochs
        if (epoch + 1) % 10 == 0:
            print(f"Epoch {epoch+1}/100: Loss={avg_loss:.4f}, Accuracy={accuracy:.2%}, LR={scheduler.get_last_lr()[0]:.6f}")
        
        # Early stopping
        if accuracy > best_accuracy:
            best_accuracy = accuracy
            patience_counter = 0
            # Save best model
            model_path = project_root / 'data/models/trained_gnn_model.pth'
            model_path.parent.mkdir(parents=True, exist_ok=True)
            torch.save(model.state_dict(), str(model_path))
        else:
            patience_counter += 1
            if patience_counter >= patience:
                print(f"Early stopping at epoch {epoch+1}")
                break
    
    print(f"\n✅ Training Complete! Best accuracy: {best_accuracy:.2%}")
    
    # Test the model
    print("\n🧪 Testing model...")
    model.eval()
    test_correct = 0
    test_total = 0
    vuln_predictions = []
    vuln_targets = []
    
    with torch.no_grad():
        for graph_data, has_vuln, vuln_type in test_data:
            try:
                graph_data = graph_data.to(device)
                vuln_pred, _ = model(graph_data.x, graph_data.edge_index)
                pred_class = torch.argmax(vuln_pred, dim=1).item()
                
                vuln_predictions.append(pred_class)
                vuln_targets.append(has_vuln)
                
                if pred_class == has_vuln:
                    test_correct += 1
                test_total += 1
            except Exception as e:
                print(f"Test error: {e}")
                continue
    
    test_accuracy = test_correct / test_total if test_total > 0 else 0
    print(f"📊 Test Accuracy: {test_accuracy:.2%}")
    
    # Calculate additional metrics
    from sklearn.metrics import precision_score, recall_score, f1_score
    try:
        precision = precision_score(vuln_targets, vuln_predictions, average='binary')
        recall = recall_score(vuln_targets, vuln_predictions, average='binary')
        f1 = f1_score(vuln_targets, vuln_predictions, average='binary')
        
        print(f"📊 Precision: {precision:.2%}")
        print(f"📊 Recall: {recall:.2%}")
        print(f"📊 F1-Score: {f1:.2%}")
    except:
        print("Could not calculate additional metrics")
    
    print(f"\n💾 Model saved to {model_path}")
    print("\n🎉 GNN is now trained and ready to use!")
    print("The model should now provide much more accurate vulnerability detection!")
    
    # Verify the model works
    print("\n🔍 Testing trained model...")
    detector_test = GNNVulnerabilityDetector(str(model_path))
    print("✅ Trained model loaded successfully!")

if __name__ == "__main__":
    train_gnn_model()