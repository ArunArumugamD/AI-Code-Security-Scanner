# src/ml/self_learning.py
"""
Self-Learning Module that improves scanner accuracy over time
by learning from user feedback and discovered patterns
"""
import json
import numpy as np
from typing import Dict, List, Tuple, Optional, Any
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
from pathlib import Path
import pickle
import hashlib
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
import asyncio
from sqlalchemy.orm import Session

from src.database.models.base import SessionLocal
from src.database.models.vulnerability import VulnerabilityDetection, VulnerabilityPattern
from src.core.base_scanner import Vulnerability, Severity
from src.ml.codebert_model import CodeBERTManager

@dataclass
class FeedbackRecord:
    """Record of user feedback on a vulnerability detection"""
    detection_id: str
    vulnerability_type: str
    code_snippet: str
    file_path: str
    language: str
    was_correct: bool  # True = confirmed vulnerability, False = false positive
    user_notes: Optional[str]
    original_confidence: float
    detection_method: str
    timestamp: datetime
    
    def to_dict(self) -> Dict:
        d = asdict(self)
        d['timestamp'] = self.timestamp.isoformat()
        return d

@dataclass
class LearningMetrics:
    """Metrics tracking learning progress"""
    total_feedback: int
    true_positives: int
    false_positives: int
    accuracy_improvement: float
    patterns_learned: int
    confidence_adjustments: Dict[str, float]
    last_model_update: datetime

class SelfLearningEngine:
    """Engine that learns from user feedback to improve detection accuracy"""
    
    def __init__(self, data_dir: str = "data/learning"):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        
        # Feedback storage
        self.feedback_file = self.data_dir / "feedback_history.json"
        self.feedback_records: List[FeedbackRecord] = self._load_feedback()
        
        # Pattern learning
        self.pattern_file = self.data_dir / "learned_patterns.json"
        self.learned_patterns: Dict[str, List[Dict]] = self._load_patterns()
        
        # Model for pattern classification
        self.pattern_model_file = self.data_dir / "pattern_classifier.pkl"
        self.pattern_classifier = self._load_pattern_classifier()
        self.vectorizer = TfidfVectorizer(max_features=1000, token_pattern=r'\b\w+\b')
        
        # Confidence adjustment factors
        self.confidence_adjustments = self._calculate_confidence_adjustments()
        
        # CodeBERT for similarity learning
        try:
            self.codebert = CodeBERTManager()
            self.use_codebert = True
        except:
            self.use_codebert = False
            
        print(f"✓ Self-Learning Engine initialized with {len(self.feedback_records)} feedback records")
    
    def record_feedback(self, vulnerability: Vulnerability, was_correct: bool, 
                       user_notes: str = "", detection_method: str = "unknown") -> FeedbackRecord:
        """Record user feedback on a vulnerability detection"""
        record = FeedbackRecord(
            detection_id=vulnerability.id,
            vulnerability_type=vulnerability.name,
            code_snippet=vulnerability.code_snippet,
            file_path=vulnerability.file_path,
            language=self._detect_language(vulnerability.file_path),
            was_correct=was_correct,
            user_notes=user_notes,
            original_confidence=vulnerability.confidence,
            detection_method=detection_method,
            timestamp=datetime.utcnow()
        )
        
        # Add to records
        self.feedback_records.append(record)
        self._save_feedback()
        
        # Update patterns if confirmed vulnerability
        if was_correct:
            self._learn_from_true_positive(record)
        else:
            self._learn_from_false_positive(record)
        
        # Update confidence adjustments
        self._update_confidence_factors()
        
        # Retrain pattern classifier if enough new data
        if len(self.feedback_records) % 50 == 0:
            self._retrain_pattern_classifier()
        
        return record
    
    def _learn_from_true_positive(self, record: FeedbackRecord):
        """Learn patterns from confirmed vulnerabilities"""
        vuln_type = record.vulnerability_type
        
        if vuln_type not in self.learned_patterns:
            self.learned_patterns[vuln_type] = []
        
        # Extract pattern features
        pattern_features = self._extract_pattern_features(record.code_snippet)
        
        # Check if similar pattern already exists
        is_novel = True
        for existing in self.learned_patterns[vuln_type]:
            if self._patterns_similar(pattern_features, existing):
                # Update existing pattern confidence
                existing['confirmations'] += 1
                existing['last_seen'] = datetime.utcnow().isoformat()
                is_novel = False
                break
        
        if is_novel:
            # Add new pattern
            self.learned_patterns[vuln_type].append({
                'features': pattern_features,
                'code_example': record.code_snippet,
                'confidence_boost': 0.1,
                'confirmations': 1,
                'first_seen': datetime.utcnow().isoformat(),
                'last_seen': datetime.utcnow().isoformat()
            })
            print(f"🎓 Learned new {vuln_type} pattern!")
        
        self._save_patterns()
    
    def _learn_from_false_positive(self, record: FeedbackRecord):
        """Learn to avoid false positive patterns"""
        # Track false positive patterns to reduce confidence
        fp_key = f"FALSE_POSITIVE_{record.vulnerability_type}"
        
        if fp_key not in self.learned_patterns:
            self.learned_patterns[fp_key] = []
        
        pattern_features = self._extract_pattern_features(record.code_snippet)
        
        self.learned_patterns[fp_key].append({
            'features': pattern_features,
            'code_example': record.code_snippet,
            'confidence_penalty': -0.2,
            'detection_method': record.detection_method,
            'timestamp': datetime.utcnow().isoformat()
        })
        
        print(f"📝 Learned to avoid false positive pattern for {record.vulnerability_type}")
        self._save_patterns()
    
    def adjust_confidence(self, vulnerability: Vulnerability, 
                         detection_methods: List[str]) -> float:
        """Adjust confidence based on learned patterns and historical accuracy"""
        adjusted_confidence = vulnerability.confidence
        
        # 1. Apply historical accuracy adjustment
        vuln_type = vulnerability.name
        if vuln_type in self.confidence_adjustments:
            adjustment = self.confidence_adjustments[vuln_type]
            adjusted_confidence *= adjustment
        
        # 2. Check against learned patterns
        pattern_boost = self._check_learned_patterns(
            vulnerability.code_snippet,
            vuln_type
        )
        adjusted_confidence += pattern_boost
        
        # 3. Check against false positive patterns
        fp_penalty = self._check_false_positive_patterns(
            vulnerability.code_snippet,
            vuln_type
        )
        adjusted_confidence += fp_penalty
        
        # 4. Apply detection method reliability
        for method in detection_methods:
            method_accuracy = self._get_method_accuracy(method)
            if method_accuracy < 0.7:  # Unreliable method
                adjusted_confidence *= 0.9
        
        # 5. Time decay factor (recent feedback is more relevant)
        time_factor = self._calculate_time_decay_factor()
        adjusted_confidence *= time_factor
        
        # Ensure bounds
        return max(0.1, min(0.99, adjusted_confidence))
    
    def _check_learned_patterns(self, code_snippet: str, vuln_type: str) -> float:
        """Check if code matches learned vulnerability patterns"""
        if vuln_type not in self.learned_patterns:
            return 0.0
        
        max_boost = 0.0
        code_features = self._extract_pattern_features(code_snippet)
        
        for pattern in self.learned_patterns[vuln_type]:
            similarity = self._calculate_pattern_similarity(code_features, pattern['features'])
            
            if similarity > 0.8:
                # High similarity to confirmed pattern
                boost = pattern.get('confidence_boost', 0.1) * similarity
                boost *= min(pattern.get('confirmations', 1) / 10, 2.0)  # More confirmations = higher boost
                max_boost = max(max_boost, boost)
        
        return max_boost
    
    def _check_false_positive_patterns(self, code_snippet: str, vuln_type: str) -> float:
        """Check if code matches known false positive patterns"""
        fp_key = f"FALSE_POSITIVE_{vuln_type}"
        if fp_key not in self.learned_patterns:
            return 0.0
        
        max_penalty = 0.0
        code_features = self._extract_pattern_features(code_snippet)
        
        for pattern in self.learned_patterns[fp_key]:
            similarity = self._calculate_pattern_similarity(code_features, pattern['features'])
            
            if similarity > 0.85:  # Very similar to false positive
                penalty = pattern.get('confidence_penalty', -0.2) * similarity
                max_penalty = min(max_penalty, penalty)  # Most negative
        
        return max_penalty
    
    def _extract_pattern_features(self, code_snippet: str) -> Dict[str, Any]:
        """Extract features from code for pattern learning"""
        features = {
            'tokens': self._tokenize_code(code_snippet),
            'length': len(code_snippet),
            'line_count': code_snippet.count('\n') + 1,
            'has_user_input': any(term in code_snippet.lower() for term in ['input', 'request', 'user', 'param']),
            'has_validation': any(term in code_snippet for term in ['validate', 'sanitize', 'escape', 'check']),
            'structure_hash': hashlib.md5(self._normalize_code(code_snippet).encode()).hexdigest()[:8]
        }
        
        # Add CodeBERT embedding if available
        if self.use_codebert:
            try:
                embedding = self.codebert.get_embedding(code_snippet, 'python')
                features['embedding'] = embedding.tolist()
            except:
                pass
        
        return features
    
    def _tokenize_code(self, code: str) -> List[str]:
        """Simple code tokenization"""
        import re
        # Remove comments and strings
        code = re.sub(r'#.*', '', code)  # Python comments
        code = re.sub(r'//.*', '', code)  # JS/Java comments
        code = re.sub(r'"[^"]*"', 'STRING', code)
        code = re.sub(r"'[^']*'", 'STRING', code)
        
        # Tokenize
        tokens = re.findall(r'\b\w+\b', code.lower())
        return tokens[:50]  # Limit token count
    
    def _normalize_code(self, code: str) -> str:
        """Normalize code for comparison"""
        # Remove whitespace variations
        lines = [line.strip() for line in code.split('\n') if line.strip()]
        return '\n'.join(lines)
    
    def _patterns_similar(self, features1: Dict, features2: Dict) -> bool:
        """Check if two patterns are similar"""
        # Quick check on structure
        if features1.get('structure_hash') == features2.get('structure_hash'):
            return True
        
        # Token similarity
        tokens1 = set(features1.get('tokens', []))
        tokens2 = set(features2.get('tokens', []))
        
        if tokens1 and tokens2:
            jaccard = len(tokens1 & tokens2) / len(tokens1 | tokens2)
            if jaccard > 0.7:
                return True
        
        # Embedding similarity if available
        if 'embedding' in features1 and 'embedding' in features2:
            similarity = self._cosine_similarity(
                np.array(features1['embedding']),
                np.array(features2['embedding'])
            )
            return similarity > 0.85
        
        return False
    
    def _calculate_pattern_similarity(self, features1: Dict, features2: Dict) -> float:
        """Calculate detailed similarity between patterns"""
        scores = []
        
        # Token similarity
        tokens1 = set(features1.get('tokens', []))
        tokens2 = set(features2.get('tokens', []))
        if tokens1 and tokens2:
            jaccard = len(tokens1 & tokens2) / len(tokens1 | tokens2)
            scores.append(jaccard)
        
        # Structure similarity
        if features1.get('structure_hash') == features2.get('structure_hash'):
            scores.append(1.0)
        else:
            scores.append(0.0)
        
        # Feature similarity
        feature_score = 0.0
        if features1.get('has_user_input') == features2.get('has_user_input'):
            feature_score += 0.5
        if features1.get('has_validation') == features2.get('has_validation'):
            feature_score += 0.5
        scores.append(feature_score)
        
        # Embedding similarity
        if 'embedding' in features1 and 'embedding' in features2:
            similarity = self._cosine_similarity(
                np.array(features1['embedding']),
                np.array(features2['embedding'])
            )
            scores.append(similarity)
        
        return np.mean(scores) if scores else 0.0
    
    def _cosine_similarity(self, vec1: np.ndarray, vec2: np.ndarray) -> float:
        """Calculate cosine similarity between vectors"""
        dot_product = np.dot(vec1, vec2)
        norm1 = np.linalg.norm(vec1)
        norm2 = np.linalg.norm(vec2)
        
        if norm1 == 0 or norm2 == 0:
            return 0.0
        
        return dot_product / (norm1 * norm2)
    
    def _calculate_confidence_adjustments(self) -> Dict[str, float]:
        """Calculate confidence adjustment factors based on historical accuracy"""
        adjustments = {}
        
        # Group feedback by vulnerability type
        type_feedback = {}
        for record in self.feedback_records:
            vuln_type = record.vulnerability_type
            if vuln_type not in type_feedback:
                type_feedback[vuln_type] = {'correct': 0, 'total': 0}
            
            type_feedback[vuln_type]['total'] += 1
            if record.was_correct:
                type_feedback[vuln_type]['correct'] += 1
        
        # Calculate adjustment factors
        for vuln_type, stats in type_feedback.items():
            if stats['total'] >= 5:  # Need minimum feedback
                accuracy = stats['correct'] / stats['total']
                
                # Adjustment factor (0.5 to 1.5)
                if accuracy < 0.5:
                    adjustment = 0.5 + accuracy  # Reduce confidence
                else:
                    adjustment = 1.0 + (accuracy - 0.5) * 0.5  # Boost confidence
                
                adjustments[vuln_type] = adjustment
        
        return adjustments
    
    def _update_confidence_factors(self):
        """Update confidence adjustment factors"""
        self.confidence_adjustments = self._calculate_confidence_adjustments()
    
    def _get_method_accuracy(self, method: str) -> float:
        """Get historical accuracy for a detection method"""
        method_records = [r for r in self.feedback_records if r.detection_method == method]
        
        if len(method_records) < 10:
            return 0.75  # Default accuracy
        
        correct = sum(1 for r in method_records if r.was_correct)
        return correct / len(method_records)
    
    def _calculate_time_decay_factor(self) -> float:
        """Recent feedback is more relevant than old feedback"""
        if not self.feedback_records:
            return 1.0
        
        # Find most recent feedback
        latest = max(r.timestamp for r in self.feedback_records)
        days_old = (datetime.utcnow() - latest).days
        
        # Decay factor (1.0 for recent, 0.8 for old)
        if days_old < 7:
            return 1.0
        elif days_old < 30:
            return 0.95
        elif days_old < 90:
            return 0.9
        else:
            return 0.8
    
    def _retrain_pattern_classifier(self):
        """Retrain the pattern classification model"""
        print("🔄 Retraining pattern classifier...")
        
        # Prepare training data
        X = []
        y = []
        
        for record in self.feedback_records[-500:]:  # Use recent 500 records
            # Simple features for classifier
            features = [
                len(record.code_snippet),
                record.code_snippet.count('\n'),
                1 if 'eval' in record.code_snippet else 0,
                1 if 'exec' in record.code_snippet else 0,
                1 if 'system' in record.code_snippet else 0,
                1 if 'SELECT' in record.code_snippet else 0,
                1 if 'innerHTML' in record.code_snippet else 0,
                record.original_confidence
            ]
            
            X.append(features)
            y.append(1 if record.was_correct else 0)
        
        if len(X) > 50:
            # Train new classifier
            self.pattern_classifier = RandomForestClassifier(n_estimators=100, random_state=42)
            self.pattern_classifier.fit(X, y)
            
            # Save model
            with open(self.pattern_model_file, 'wb') as f:
                pickle.dump(self.pattern_classifier, f)
            
            # Calculate accuracy
            from sklearn.model_selection import cross_val_score
            scores = cross_val_score(self.pattern_classifier, X, y, cv=5)
            print(f"✓ Classifier retrained with accuracy: {scores.mean():.2%}")
    
    def suggest_new_patterns(self) -> List[Dict[str, Any]]:
        """Suggest new vulnerability patterns based on learning"""
        suggestions = []
        
        # Find common patterns in true positives
        for vuln_type, patterns in self.learned_patterns.items():
            if vuln_type.startswith("FALSE_POSITIVE_"):
                continue
            
            # High-confidence patterns with multiple confirmations
            for pattern in patterns:
                if pattern.get('confirmations', 0) >= 3:
                    suggestions.append({
                        'type': vuln_type,
                        'pattern': pattern['code_example'],
                        'confidence': pattern.get('confidence_boost', 0.1),
                        'confirmations': pattern['confirmations'],
                        'description': f"Learned pattern for {vuln_type}"
                    })
        
        # Sort by confirmations
        suggestions.sort(key=lambda x: x['confirmations'], reverse=True)
        
        return suggestions[:10]  # Top 10 suggestions
    
    def export_learning_report(self) -> LearningMetrics:
        """Generate report on learning progress"""
        total_feedback = len(self.feedback_records)
        true_positives = sum(1 for r in self.feedback_records if r.was_correct)
        false_positives = total_feedback - true_positives
        
        # Calculate accuracy improvement
        if total_feedback >= 20:
            # Compare first 10 vs last 10 feedback
            early_records = self.feedback_records[:10]
            recent_records = self.feedback_records[-10:]
            
            early_accuracy = sum(1 for r in early_records if r.was_correct) / 10
            recent_accuracy = sum(1 for r in recent_records if r.was_correct) / 10
            
            accuracy_improvement = recent_accuracy - early_accuracy
        else:
            accuracy_improvement = 0.0
        
        # Count learned patterns
        patterns_learned = sum(
            len(patterns) for vuln_type, patterns in self.learned_patterns.items()
            if not vuln_type.startswith("FALSE_POSITIVE_")
        )
        
        return LearningMetrics(
            total_feedback=total_feedback,
            true_positives=true_positives,
            false_positives=false_positives,
            accuracy_improvement=accuracy_improvement,
            patterns_learned=patterns_learned,
            confidence_adjustments=self.confidence_adjustments,
            last_model_update=datetime.utcnow()
        )
    
    def _detect_language(self, file_path: str) -> str:
        """Detect language from file extension"""
        ext_map = {
            '.py': 'python',
            '.js': 'javascript',
            '.java': 'java',
            '.php': 'php',
            '.c': 'c',
            '.cpp': 'cpp'
        }
        
        for ext, lang in ext_map.items():
            if file_path.endswith(ext):
                return lang
        return 'unknown'
    
    def _load_feedback(self) -> List[FeedbackRecord]:
        """Load feedback history from disk"""
        if self.feedback_file.exists():
            try:
                with open(self.feedback_file, 'r') as f:
                    data = json.load(f)
                    records = []
                    for item in data:
                        item['timestamp'] = datetime.fromisoformat(item['timestamp'])
                        records.append(FeedbackRecord(**item))
                    return records
            except:
                pass
        return []
    
    def _save_feedback(self):
        """Save feedback history to disk"""
        data = [record.to_dict() for record in self.feedback_records]
        with open(self.feedback_file, 'w') as f:
            json.dump(data, f, indent=2)
    
    def _load_patterns(self) -> Dict[str, List[Dict]]:
        """Load learned patterns from disk"""
        if self.pattern_file.exists():
            try:
                with open(self.pattern_file, 'r') as f:
                    return json.load(f)
            except:
                pass
        return {}
    
    def _save_patterns(self):
        """Save learned patterns to disk"""
        with open(self.pattern_file, 'w') as f:
            json.dump(self.learned_patterns, f, indent=2)
    
    def _load_pattern_classifier(self):
        """Load pattern classifier model"""
        if self.pattern_model_file.exists():
            try:
                with open(self.pattern_model_file, 'rb') as f:
                    return pickle.load(f)
            except:
                pass
        return None


# Integration with main scanner
class LearningEnabledScanner:
    """Scanner that uses self-learning to improve accuracy"""
    
    def __init__(self, base_scanner):
        self.base_scanner = base_scanner
        self.learning_engine = SelfLearningEngine()
        self.pending_feedback = {}  # Store detections awaiting feedback
    
    async def scan_with_learning(self, code: str, language: str, 
                                file_path: str) -> List[Vulnerability]:
        """Scan code and apply learned adjustments"""
        # Get base detections
        vulnerabilities = await self.base_scanner.analyze(code, language, file_path)
        
        # Apply learning adjustments
        adjusted_vulns = []
        for vuln in vulnerabilities:
            # Adjust confidence based on learning
            original_confidence = vuln.confidence
            vuln.confidence = self.learning_engine.adjust_confidence(
                vuln,
                self._get_detection_methods(vuln)
            )
            
            # Add learning metadata
            vuln.learning_metadata = {
                'original_confidence': original_confidence,
                'confidence_adjusted': vuln.confidence != original_confidence,
                'adjustment_reason': self._get_adjustment_reason(original_confidence, vuln.confidence)
            }
            
            adjusted_vulns.append(vuln)
            
            # Store for potential feedback
            self.pending_feedback[vuln.id] = vuln
        
        return adjusted_vulns
    
    def record_user_feedback(self, detection_id: str, was_correct: bool, notes: str = ""):
        """Record user feedback on a detection"""
        if detection_id in self.pending_feedback:
            vuln = self.pending_feedback[detection_id]
            
            record = self.learning_engine.record_feedback(
                vuln,
                was_correct,
                notes,
                self._get_primary_detection_method(vuln)
            )
            
            # Update database if detection exists
            self._update_database_feedback(detection_id, was_correct, notes)
            
            # Remove from pending
            del self.pending_feedback[detection_id]
            
            print(f"✓ Feedback recorded: {vuln.name} was {'correct' if was_correct else 'false positive'}")
            
            # Check if we should suggest new patterns
            suggestions = self.learning_engine.suggest_new_patterns()
            if suggestions:
                print(f"💡 New patterns available for review: {len(suggestions)} suggestions")
            
            return record
        else:
            print(f"Warning: Detection {detection_id} not found in pending feedback")
    
    def get_learning_metrics(self) -> LearningMetrics:
        """Get current learning metrics"""
        return self.learning_engine.export_learning_report()
    
    def _get_detection_methods(self, vuln: Vulnerability) -> List[str]:
        """Extract detection methods from vulnerability"""
        methods = []
        
        if "PATTERN" in vuln.id:
            methods.append("pattern")
        if "AST" in vuln.id or "PARSE" in vuln.id:
            methods.append("ast")
        if "AI-" in vuln.id:
            methods.append("ai")
        if "GNN" in vuln.id:
            methods.append("gnn")
        if "HYBRID" in vuln.id:
            methods.append("hybrid")
        
        return methods if methods else ["unknown"]
    
    def _get_primary_detection_method(self, vuln: Vulnerability) -> str:
        """Get primary detection method"""
        methods = self._get_detection_methods(vuln)
        return methods[0] if methods else "unknown"
    
    def _get_adjustment_reason(self, original: float, adjusted: float) -> str:
        """Explain confidence adjustment"""
        if adjusted > original:
            return "Boosted due to similarity with confirmed patterns"
        elif adjusted < original:
            return "Reduced due to similarity with false positive patterns"
        else:
            return "No adjustment needed"
    
    def _update_database_feedback(self, detection_id: str, was_correct: bool, notes: str):
        """Update database with feedback"""
        db = SessionLocal()
        try:
            detection = db.query(VulnerabilityDetection).filter(
                VulnerabilityDetection.detection_id == detection_id
            ).first()
            
            if detection:
                detection.verified_by_user = True
                detection.status = 'confirmed' if was_correct else 'false_positive'
                if not was_correct:
                    detection.suppressed = True
                    detection.suppression_reason = f"User feedback: {notes}"
                
                db.commit()
        finally:
            db.close()