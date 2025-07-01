# src/ml/codebert_model.py
import torch
from transformers import RobertaTokenizer, RobertaModel
import numpy as np
from typing import List, Dict, Tuple, Optional
import hashlib
import json
import os
from pathlib import Path

class CodeBERTManager:
    """Manages CodeBERT model for multi-language code embeddings"""
    
    def __init__(self, cache_dir: str = "data/models"):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        
        self.model_name = "microsoft/codebert-base"
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        
        print(f"🤖 Initializing CodeBERT on {self.device}...")
        
        # Load tokenizer and model
        self.tokenizer = RobertaTokenizer.from_pretrained(self.model_name)
        self.model = RobertaModel.from_pretrained(self.model_name)
        self.model.to(self.device)
        self.model.eval()  # Set to evaluation mode
        
        print("✓ CodeBERT model loaded successfully")
        
        # Cache for embeddings
        self.embedding_cache = {}
        self._load_cache()
    
    def _load_cache(self):
        """Load embedding cache from disk"""
        cache_file = self.cache_dir / "embedding_cache.json"
        if cache_file.exists():
            try:
                with open(cache_file, 'r') as f:
                    self.embedding_cache = json.load(f)
                print(f"✓ Loaded {len(self.embedding_cache)} cached embeddings")
            except:
                self.embedding_cache = {}
    
    def _save_cache(self):
        """Save embedding cache to disk"""
        cache_file = self.cache_dir / "embedding_cache.json"
        with open(cache_file, 'w') as f:
            json.dump(self.embedding_cache, f)
    
    def _get_code_hash(self, code: str, language: str) -> str:
        """Generate unique hash for code snippet"""
        content = f"{language}:{code}"
        return hashlib.md5(content.encode()).hexdigest()
    
    def get_embedding(self, code: str, language: str = "python") -> np.ndarray:
        """Generate embedding for a code snippet"""
        # Check cache first
        code_hash = self._get_code_hash(code, language)
        if code_hash in self.embedding_cache:
            return np.array(self.embedding_cache[code_hash])
        
        # Prepare input
        code_tokens = self.tokenizer.tokenize(code)[:510]  # Leave room for special tokens
        tokens = [self.tokenizer.cls_token] + code_tokens + [self.tokenizer.sep_token]
        tokens_ids = self.tokenizer.convert_tokens_to_ids(tokens)
        
        # Convert to tensor
        tokens_tensor = torch.tensor(tokens_ids).unsqueeze(0).to(self.device)
        
        # Generate embedding
        with torch.no_grad():
            outputs = self.model(tokens_tensor)
            # Use the [CLS] token embedding as the representation
            embedding = outputs.last_hidden_state[:, 0, :].squeeze().cpu().numpy()
        
        # Cache the result
        self.embedding_cache[code_hash] = embedding.tolist()
        
        # Save cache periodically
        if len(self.embedding_cache) % 100 == 0:
            self._save_cache()
        
        return embedding
    
    def get_batch_embeddings(self, code_snippets: List[Tuple[str, str]]) -> List[np.ndarray]:
        """Generate embeddings for multiple code snippets efficiently"""
        embeddings = []
        
        for code, language in code_snippets:
            embedding = self.get_embedding(code, language)
            embeddings.append(embedding)
        
        return embeddings
    
    def calculate_similarity(self, embedding1: np.ndarray, embedding2: np.ndarray) -> float:
        """Calculate cosine similarity between two embeddings"""
        # Cosine similarity
        dot_product = np.dot(embedding1, embedding2)
        norm1 = np.linalg.norm(embedding1)
        norm2 = np.linalg.norm(embedding2)
        
        if norm1 == 0 or norm2 == 0:
            return 0.0
        
        similarity = dot_product / (norm1 * norm2)
        return float(similarity)
    
    def find_similar_code(self, query_code: str, code_database: List[Dict], 
                         language: str = "python", top_k: int = 5) -> List[Dict]:
        """Find similar code snippets from a database"""
        query_embedding = self.get_embedding(query_code, language)
        
        similarities = []
        for item in code_database:
            item_embedding = self.get_embedding(item['code'], item.get('language', 'python'))
            similarity = self.calculate_similarity(query_embedding, item_embedding)
            similarities.append({
                **item,
                'similarity': similarity
            })
        
        # Sort by similarity
        similarities.sort(key=lambda x: x['similarity'], reverse=True)
        
        return similarities[:top_k]
    
    def analyze_vulnerability_context(self, code_snippet: str, 
                                    vulnerability_type: str,
                                    language: str = "python") -> Dict[str, float]:
        """Analyze code context to refine vulnerability confidence"""
        # Get embedding for the suspicious code
        code_embedding = self.get_embedding(code_snippet, language)
        
        # Define known vulnerable patterns with their embeddings
        vulnerable_patterns = {
            "sql_injection": [
                "cursor.execute('SELECT * FROM users WHERE id = ' + user_input)",
                "db.query(f'DELETE FROM {table} WHERE id = {id}')",
                "connection.execute('INSERT INTO logs VALUES (' + data + ')')"
            ],
            "xss": [
                "document.getElementById('output').innerHTML = userInput",
                "element.innerHTML = '<div>' + userData + '</div>'",
                "#result.html(request.getParameter('input'))"
            ],
            "command_injection": [
                "os.system('ping ' + ip_address)",
                "subprocess.call(user_command, shell=True)",
                "exec('rm -rf ' + directory)"
            ]
        }
        
        # Get patterns for this vulnerability type
        patterns = vulnerable_patterns.get(vulnerability_type, [])
        if not patterns:
            return {"confidence_boost": 0.0}
        
        # Calculate similarity to known vulnerable patterns
        similarities = []
        for pattern in patterns:
            pattern_embedding = self.get_embedding(pattern, language)
            similarity = self.calculate_similarity(code_embedding, pattern_embedding)
            similarities.append(similarity)
        
        # Average similarity
        avg_similarity = np.mean(similarities) if similarities else 0.0
        max_similarity = np.max(similarities) if similarities else 0.0
        
        # Calculate confidence boost based on similarity
        confidence_boost = 0.0
        if max_similarity > 0.9:
            confidence_boost = 0.2  # Very similar to known vulnerable pattern
        elif max_similarity > 0.8:
            confidence_boost = 0.15
        elif max_similarity > 0.7:
            confidence_boost = 0.1
        elif max_similarity > 0.6:
            confidence_boost = 0.05
        
        return {
            "confidence_boost": confidence_boost,
            "max_similarity": max_similarity,
            "avg_similarity": avg_similarity,
            "similar_to_known_vulnerable": max_similarity > 0.7
        }
    
    def __del__(self):
        """Save cache on cleanup"""
        if hasattr(self, 'embedding_cache') and self.embedding_cache:
            try:
                self._save_cache()
            except:
                pass
