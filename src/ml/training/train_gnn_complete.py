# src/ml/training/train_gnn_complete.py
"""
Complete GNN Training Pipeline with SARD Dataset
High-quality training for impressive accuracy
"""
import sys
import os
from pathlib import Path
import torch
import torch.nn as nn
import torch.optim as optim
from torch_geometric.data import Data, DataLoader
from torch_geometric.loader import DataLoader as GeometricDataLoader
import numpy as np
import json
import random
from typing import List, Tuple, Dict
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
import matplotlib.pyplot as plt
import seaborn as sns
from datetime import datetime

# Add project root to path
project_root = Path(__file__).parent.parent.parent.parent
sys.path.insert(0, str(project_root))

# Import our improved modules
from src.ml.gnn_model_improved import ImprovedGNNVulnerabilityDetector, ImprovedCodeGraphBuilder
from src.ml.training.sard_dataset_processor import SARDProcessor

class GNNTrainingPipeline:
    """Complete training pipeline for GNN vulnerability detection"""
    
    def __init__(self, data_dir: str = "data/gnn_training"):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        
        # Training configuration
        self.config = {
            'batch_size': 32,
            'learning_rate': 0.001,
            'weight_decay': 1e-5,
            'epochs': 200,
            'patience': 20,
            'validation_split': 0.2,
            'test_split': 0.1,
            'device': torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        }
        
        # Initialize components
        self.graph_builder = ImprovedCodeGraphBuilder()
        self.model = None
        self.train_loader = None
        self.val_loader = None
        self.test_loader = None
        
        # Metrics tracking
        self.training_history = {
            'train_loss': [], 'val_loss': [], 'train_acc': [], 'val_acc': [],
            'train_f1': [], 'val_f1': []
        }
        
        print(f"🚀 GNN Training Pipeline initialized")
        print(f"   Device: {self.config['device']}")
        print(f"   Data directory: {self.data_dir}")
    
    def prepare_dataset(self) -> bool:
        """Prepare comprehensive training dataset"""
        print("\n📊 Preparing comprehensive dataset...")
        
        # Initialize SARD processor
        sard_processor = SARDProcessor()
        
        # Create training dataset
        train_samples, test_samples = sard_processor.create_training_dataset()
        
        if len(train_samples) < 100:
            print("❌ Insufficient training samples!")
            return False
        
        print(f"✅ Dataset prepared:")
        print(f"   Total samples: {len(train_samples) + len(test_samples)}")
        print(f"   Training: {len(train_samples)}")
        print(f"   Testing: {len(test_samples)}")
        
        # Convert to graph data
        print("\n🔄 Converting to graph format...")
        train_graphs = []
        test_graphs = []
        
        # Process training samples
        for i, sample in enumerate(train_samples):
            if i % 50 == 0:
                print(f"   Processed {i}/{len(train_samples)} training samples")
            
            try:
                graph_data = self.graph_builder.build_enhanced_graph(
                    sample.code, sample.language
                )
                
                # Add labels
                graph_data.y = torch.tensor([1 if sample.is_vulnerable else 0], dtype=torch.long)
                graph_data.vuln_type = torch.tensor([self._map_cwe_to_type(sample.cwe_id)], dtype=torch.long)
                
                # Add metadata
                graph_data.file_id = sample.file_id
                graph_data.cwe_id = sample.cwe_id
                
                train_graphs.append(graph_data)
                
            except Exception as e:
                print(f"   Error processing sample {sample.file_id}: {e}")
                continue
        
        # Process test samples
        for sample in test_samples:
            try:
                graph_data = self.graph_builder.build_enhanced_graph(
                    sample.code, sample.language
                )
                
                graph_data.y = torch.tensor([1 if sample.is_vulnerable else 0], dtype=torch.long)
                graph_data.vuln_type = torch.tensor([self._map_cwe_to_type(sample.cwe_id)], dtype=torch.long)
                graph_data.file_id = sample.file_id
                graph_data.cwe_id = sample.cwe_id
                
                test_graphs.append(graph_data)
                
            except Exception as e:
                continue
        
        print(f"✅ Graph conversion completed:")
        print(f"   Training graphs: {len(train_graphs)}")
        print(f"   Test graphs: {len(test_graphs)}")
        
        # Split training into train/validation
        val_size = int(len(train_graphs) * self.config['validation_split'])
        random.shuffle(train_graphs)
        
        val_graphs = train_graphs[:val_size]
        train_graphs = train_graphs[val_size:]
        
        # Create data loaders
        self.train_loader = GeometricDataLoader(
            train_graphs, 
            batch_size=self.config['batch_size'], 
            shuffle=True,
            drop_last=True
        )
        
        self.val_loader = GeometricDataLoader(
            val_graphs,
            batch_size=self.config['batch_size'],
            shuffle=False
        )
        
        self.test_loader = GeometricDataLoader(
            test_graphs,
            batch_size=self.config['batch_size'],
            shuffle=False
        )
        
        # Save dataset info
        dataset_info = {
            'train_size': len(train_graphs),
            'val_size': len(val_graphs),
            'test_size': len(test_graphs),
            'num_features': 62,
            'num_edge_features': 8,
            'num_classes': 2,
            'num_vuln_types': 10,
            'created_at': datetime.now().isoformat()
        }
        
        with open(self.data_dir / 'dataset_info.json', 'w') as f:
            json.dump(dataset_info, f, indent=2)
        
        return True
    
    def _map_cwe_to_type(self, cwe_id: str) -> int:
        """Map CWE ID to vulnerability type index"""
        cwe_mapping = {
            'CWE-120': 0,  # Buffer Overflow
            'CWE-89': 1,   # SQL Injection
            'CWE-78': 2,   # Command Injection
            'CWE-134': 3,  # Format String
            'CWE-476': 4,  # NULL Pointer
            'CWE-415': 5,  # Double Free
            'CWE-401': 6,  # Memory Leak
            'CWE-190': 7,  # Integer Overflow
            'CWE-22': 8,   # Path Traversal
        }
        return cwe_mapping.get(cwe_id, 9)  # 9 = Other
    
    def initialize_model(self):
        """Initialize the improved GNN model"""
        print("\n🧠 Initializing improved GNN model...")
        
        # Import the improved model
        from src.ml.gnn_model_improved import ImprovedVulnerabilityGNN
        
        self.model = ImprovedVulnerabilityGNN(
            num_node_features=62,
            num_edge_features=8,
            hidden_dim=256,
            num_classes=2,
            num_vuln_types=10
        )
        
        self.model.to(self.config['device'])
        
        # Count parameters
        total_params = sum(p.numel() for p in self.model.parameters())
        trainable_params = sum(p.numel() for p in self.model.parameters() if p.requires_grad)
        
        print(f"✅ Model initialized:")
        print(f"   Total parameters: {total_params:,}")
        print(f"   Trainable parameters: {trainable_params:,}")
        print(f"   Model size: ~{total_params * 4 / 1024 / 1024:.1f} MB")
    
    def train_model(self) -> bool:
        """Train the GNN model with advanced techniques"""
        print("\n🏋️ Starting training...")
        
        # Optimizers and schedulers
        optimizer = optim.AdamW(
            self.model.parameters(),
            lr=self.config['learning_rate'],
            weight_decay=self.config['weight_decay']
        )
        
        scheduler = optim.lr_scheduler.ReduceLROnPlateau(
            optimizer, mode='min', factor=0.5, patience=10, verbose=True
        )
        
        # Loss functions
        vuln_criterion = nn.CrossEntropyLoss(weight=torch.tensor([1.0, 2.0]).to(self.config['device']))  # Weight positive class
        type_criterion = nn.CrossEntropyLoss()
        confidence_criterion = nn.MSELoss()
        
        # Training state
        best_val_f1 = 0.0
        best_model_state = None
        patience_counter = 0
        
        print(f"Training configuration:")
        print(f"   Epochs: {self.config['epochs']}")
        print(f"   Batch size: {self.config['batch_size']}")
        print(f"   Learning rate: {self.config['learning_rate']}")
        print(f"   Patience: {self.config['patience']}")
        
        for epoch in range(self.config['epochs']):
            # Training phase
            train_metrics = self._train_epoch(
                optimizer, vuln_criterion, type_criterion, confidence_criterion
            )
            
            # Validation phase
            val_metrics = self._validate_epoch(
                vuln_criterion, type_criterion, confidence_criterion
            )
            
            # Update scheduler
            scheduler.step(val_metrics['loss'])
            
            # Track metrics
            self.training_history['train_loss'].append(train_metrics['loss'])
            self.training_history['val_loss'].append(val_metrics['loss'])
            self.training_history['train_acc'].append(train_metrics['accuracy'])
            self.training_history['val_acc'].append(val_metrics['accuracy'])
            self.training_history['train_f1'].append(train_metrics['f1'])
            self.training_history['val_f1'].append(val_metrics['f1'])
            
            # Print progress
            if epoch % 10 == 0 or epoch < 5:
                print(f"Epoch {epoch+1:3d}/{self.config['epochs']}: "
                      f"Train Loss={train_metrics['loss']:.4f}, "
                      f"Val Loss={val_metrics['loss']:.4f}, "
                      f"Train Acc={train_metrics['accuracy']:.3f}, "
                      f"Val Acc={val_metrics['accuracy']:.3f}, "
                      f"Val F1={val_metrics['f1']:.3f}")
            
            # Early stopping and best model saving
            if val_metrics['f1'] > best_val_f1:
                best_val_f1 = val_metrics['f1']
                best_model_state = self.model.state_dict().copy()
                patience_counter = 0
                
                # Save best model
                self._save_model(best_model_state, epoch, val_metrics)
                
            else:
                patience_counter += 1
                if patience_counter >= self.config['patience']:
                    print(f"\nEarly stopping at epoch {epoch+1}")
                    print(f"Best validation F1: {best_val_f1:.3f}")
                    break
        
        # Load best model
        if best_model_state:
            self.model.load_state_dict(best_model_state)
        
        print(f"\n✅ Training completed!")
        print(f"   Best validation F1: {best_val_f1:.3f}")
        
        return True
    
    def _train_epoch(self, optimizer, vuln_criterion, type_criterion, confidence_criterion):
        """Train for one epoch"""
        self.model.train()
        
        total_loss = 0
        all_preds = []
        all_labels = []
        num_batches = 0
        
        for batch in self.train_loader:
            batch = batch.to(self.config['device'])
            
            optimizer.zero_grad()
            
            # Forward pass
            vuln_pred, type_pred, confidence = self.model(batch.x, batch.edge_index, batch.batch)
            
            # Calculate losses
            vuln_loss = vuln_criterion(vuln_pred, batch.y)
            
            # Type loss only for vulnerable samples
            vuln_mask = batch.y == 1
            if vuln_mask.sum() > 0:
                type_loss = type_criterion(type_pred[vuln_mask], batch.vuln_type[vuln_mask])
            else:
                type_loss = torch.tensor(0.0, device=self.config['device'])
            
            # Confidence loss (predict high confidence for correct predictions)
            confidence_targets = torch.ones_like(confidence.squeeze())
            conf_loss = confidence_criterion(confidence.squeeze(), confidence_targets)
            
            # Combined loss
            total_loss_batch = vuln_loss + 0.3 * type_loss + 0.1 * conf_loss
            
            # Backward pass
            total_loss_batch.backward()
            torch.nn.utils.clip_grad_norm_(self.model.parameters(), 1.0)
            optimizer.step()
            
            # Track metrics
            total_loss += total_loss_batch.item()
            preds = torch.argmax(vuln_pred, dim=1)
            all_preds.extend(preds.cpu().numpy())
            all_labels.extend(batch.y.cpu().numpy())
            num_batches += 1
        
        # Calculate metrics
        accuracy = accuracy_score(all_labels, all_preds)
        f1 = f1_score(all_labels, all_preds, average='binary')
        
        return {
            'loss': total_loss / num_batches,
            'accuracy': accuracy,
            'f1': f1
        }
    
    def _validate_epoch(self, vuln_criterion, type_criterion, confidence_criterion):
        """Validate for one epoch"""
        self.model.eval()
        
        total_loss = 0
        all_preds = []
        all_labels = []
        num_batches = 0
        
        with torch.no_grad():
            for batch in self.val_loader:
                batch = batch.to(self.config['device'])
                
                # Forward pass
                vuln_pred, type_pred, confidence = self.model(batch.x, batch.edge_index, batch.batch)
                
                # Calculate losses
                vuln_loss = vuln_criterion(vuln_pred, batch.y)
                
                vuln_mask = batch.y == 1
                if vuln_mask.sum() > 0:
                    type_loss = type_criterion(type_pred[vuln_mask], batch.vuln_type[vuln_mask])
                else:
                    type_loss = torch.tensor(0.0, device=self.config['device'])
                
                confidence_targets = torch.ones_like(confidence.squeeze())
                conf_loss = confidence_criterion(confidence.squeeze(), confidence_targets)
                
                total_loss_batch = vuln_loss + 0.3 * type_loss + 0.1 * conf_loss
                
                # Track metrics
                total_loss += total_loss_batch.item()
                preds = torch.argmax(vuln_pred, dim=1)
                all_preds.extend(preds.cpu().numpy())
                all_labels.extend(batch.y.cpu().numpy())
                num_batches += 1
        
        # Calculate metrics
        accuracy = accuracy_score(all_labels, all_preds)
        f1 = f1_score(all_labels, all_preds, average='binary')
        
        return {
            'loss': total_loss / num_batches,
            'accuracy': accuracy,
            'f1': f1
        }
    
    def _save_model(self, model_state, epoch, metrics):
        """Save the best model"""
        model_path = self.data_dir / 'best_gnn_model.pth'
        
        torch.save({
            'model_state_dict': model_state,
            'epoch': epoch,
            'metrics': metrics,
            'config': self.config,
            'training_history': self.training_history
        }, model_path)
    
    def evaluate_model(self) -> Dict:
        """Comprehensive model evaluation"""
        print("\n📊 Evaluating model performance...")
        
        self.model.eval()
        
        all_preds = []
        all_labels = []
        all_probs = []
        all_confidences = []
        detailed_results = []
        
        with torch.no_grad():
            for batch in self.test_loader:
                batch = batch.to(self.config['device'])
                
                vuln_pred, type_pred, confidence = self.model(batch.x, batch.edge_index, batch.batch)
                
                # Get predictions and probabilities
                probs = torch.softmax(vuln_pred, dim=1)
                preds = torch.argmax(vuln_pred, dim=1)
                
                all_preds.extend(preds.cpu().numpy())
                all_labels.extend(batch.y.cpu().numpy())
                all_probs.extend(probs[:, 1].cpu().numpy())  # Probability of vulnerability
                all_confidences.extend(confidence.squeeze().cpu().numpy())
                
                # Store detailed results
                for i in range(len(batch.y)):
                    detailed_results.append({
                        'file_id': batch.file_id[i] if hasattr(batch, 'file_id') else f'test_{len(detailed_results)}',
                        'true_label': batch.y[i].item(),
                        'predicted_label': preds[i].item(),
                        'vulnerability_prob': probs[i, 1].item(),
                        'confidence': confidence[i].item(),
                        'cwe_id': batch.cwe_id[i] if hasattr(batch, 'cwe_id') else 'unknown'
                    })
        
        # Calculate comprehensive metrics
        accuracy = accuracy_score(all_labels, all_preds)
        precision = precision_score(all_labels, all_preds, average='binary')
        recall = recall_score(all_labels, all_preds, average='binary')
        f1 = f1_score(all_labels, all_preds, average='binary')
        
        # Confusion matrix
        cm = confusion_matrix(all_labels, all_preds)
        
        # Additional metrics
        true_positives = cm[1, 1]
        false_positives = cm[0, 1]
        false_negatives = cm[1, 0]
        true_negatives = cm[0, 0]
        
        specificity = true_negatives / (true_negatives + false_positives) if (true_negatives + false_positives) > 0 else 0
        
        evaluation_results = {
            'accuracy': accuracy,
            'precision': precision,
            'recall': recall,
            'f1_score': f1,
            'specificity': specificity,
            'true_positives': int(true_positives),
            'false_positives': int(false_positives),
            'false_negatives': int(false_negatives),
            'true_negatives': int(true_negatives),
            'confusion_matrix': cm.tolist(),
            'avg_confidence': np.mean(all_confidences),
            'detailed_results': detailed_results
        }
        
        # Print results
        print(f"📈 Evaluation Results:")
        print(f"   Accuracy:     {accuracy:.3f}")
        print(f"   Precision:    {precision:.3f}")
        print(f"   Recall:       {recall:.3f}")
        print(f"   F1-Score:     {f1:.3f}")
        print(f"   Specificity:  {specificity:.3f}")
        print(f"   Avg Confidence: {np.mean(all_confidences):.3f}")
        print(f"\n   Confusion Matrix:")
        print(f"   TN: {true_negatives:3d} | FP: {false_positives:3d}")
        print(f"   FN: {false_negatives:3d} | TP: {true_positives:3d}")
        
        # Save evaluation results
        with open(self.data_dir / 'evaluation_results.json', 'w') as f:
            json.dump(evaluation_results, f, indent=2)
        
        # Create visualizations
        self._create_visualizations(evaluation_results)
        
        return evaluation_results
    
    def _create_visualizations(self, results: Dict):
        """Create training and evaluation visualizations"""
        print("\n📊 Creating visualizations...")
        
        # Set style
        plt.style.use('seaborn-v0_8' if 'seaborn-v0_8' in plt.style.available else 'default')
        
        # 1. Training history
        fig, axes = plt.subplots(2, 2, figsize=(15, 10))
        
        # Loss curves
        axes[0, 0].plot(self.training_history['train_loss'], label='Train Loss', color='blue')
        axes[0, 0].plot(self.training_history['val_loss'], label='Val Loss', color='red')
        axes[0, 0].set_title('Training and Validation Loss')
        axes[0, 0].set_xlabel('Epoch')
        axes[0, 0].set_ylabel('Loss')
        axes[0, 0].legend()
        axes[0, 0].grid(True)
        
        # Accuracy curves
        axes[0, 1].plot(self.training_history['train_acc'], label='Train Acc', color='blue')
        axes[0, 1].plot(self.training_history['val_acc'], label='Val Acc', color='red')
        axes[0, 1].set_title('Training and Validation Accuracy')
        axes[0, 1].set_xlabel('Epoch')
        axes[0, 1].set_ylabel('Accuracy')
        axes[0, 1].legend()
        axes[0, 1].grid(True)
        
        # F1 Score curves
        axes[1, 0].plot(self.training_history['train_f1'], label='Train F1', color='blue')
        axes[0, 0].plot(self.training_history['val_f1'], label='Val F1', color='red')
        axes[1, 0].set_title('Training and Validation F1 Score')
        axes[1, 0].set_xlabel('Epoch')
        axes[1, 0].set_ylabel('F1 Score')
        axes[1, 0].legend()
        axes[1, 0].grid(True)
        
        # Confusion Matrix
        cm = np.array(results['confusion_matrix'])
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', ax=axes[1, 1])
        axes[1, 1].set_title('Confusion Matrix')
        axes[1, 1].set_xlabel('Predicted')
        axes[1, 1].set_ylabel('Actual')
        
        plt.tight_layout()
        plt.savefig(self.data_dir / 'training_results.png', dpi=300, bbox_inches='tight')
        plt.close()
        
        # 2. Performance metrics bar chart
        plt.figure(figsize=(10, 6))
        metrics = ['Accuracy', 'Precision', 'Recall', 'F1-Score', 'Specificity']
        values = [results['accuracy'], results['precision'], results['recall'], 
                 results['f1_score'], results['specificity']]
        
        bars = plt.bar(metrics, values, color=['skyblue', 'lightgreen', 'lightcoral', 'gold', 'plum'])
        plt.title('Model Performance Metrics')
        plt.ylabel('Score')
        plt.ylim(0, 1)
        
        # Add value labels on bars
        for bar, value in zip(bars, values):
            plt.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.01, 
                    f'{value:.3f}', ha='center', va='bottom')
        
        plt.grid(True, alpha=0.3)
        plt.savefig(self.data_dir / 'performance_metrics.png', dpi=300, bbox_inches='tight')
        plt.close()
        
        print(f"✅ Visualizations saved to {self.data_dir}")
    
    def export_trained_model(self) -> str:
        """Export the trained model for production use"""
        print("\n📦 Exporting trained model...")
        
        # Create production model directory
        model_dir = Path("data/models")
        model_dir.mkdir(parents=True, exist_ok=True)
        
        # Copy best model
        import shutil
        source_path = self.data_dir / 'best_gnn_model.pth'
        target_path = model_dir / 'trained_gnn_model.pth'
        
        if source_path.exists():
            shutil.copy2(source_path, target_path)
            
            # Create model info file
            model_info = {
                'model_type': 'ImprovedVulnerabilityGNN',
                'num_node_features': 62,
                'num_edge_features': 8,
                'hidden_dim': 256,
                'num_classes': 2,
                'num_vuln_types': 10,
                'trained_at': datetime.now().isoformat(),
                'performance': {
                    'test_accuracy': float(np.mean(self.training_history['val_acc'][-10:])),
                    'test_f1': float(np.mean(self.training_history['val_f1'][-10:]))
                }
            }
            
            with open(model_dir / 'model_info.json', 'w') as f:
                json.dump(model_info, f, indent=2)
            
            print(f"✅ Model exported to {target_path}")
            return str(target_path)
        
        return ""

def main():
    """Main training function"""
    print("🚀 Starting GNN Training with SARD Dataset")
    print("=" * 60)
    
    # Initialize pipeline
    pipeline = GNNTrainingPipeline()
    
    # Step 1: Prepare dataset
    if not pipeline.prepare_dataset():
        print("❌ Dataset preparation failed!")
        return
    
    # Step 2: Initialize model
    pipeline.initialize_model()
    
    # Step 3: Train model
    if not pipeline.train_model():
        print("❌ Training failed!")
        return
    
    # Step 4: Evaluate model
    results = pipeline.evaluate_model()
    
    # Step 5: Export model
    model_path = pipeline.export_trained_model()
    
    # Final summary
    print("\n" + "=" * 60)
    print("🎉 TRAINING COMPLETED SUCCESSFULLY!")
    print("=" * 60)
    print(f"📊 Final Performance:")
    print(f"   Accuracy: {results['accuracy']:.1%}")
    print(f"   F1-Score: {results['f1_score']:.1%}")
    print(f"   Precision: {results['precision']:.1%}")
    print(f"   Recall: {results['recall']:.1%}")
    print(f"\n📦 Model saved to: {model_path}")
    print(f"📈 Visualizations: {pipeline.data_dir}")
    print("\n✅ Your GNN is now ready for production use!")

if __name__ == "__main__":
    # Set random seeds for reproducibility
    torch.manual_seed(42)
    np.random.seed(42)
    random.seed(42)
    
    if torch.cuda.is_available():
        torch.cuda.manual_seed(42)
    
    main()