# src/ml/zero_day_detector.py
"""
Zero-Day Pattern Detection using Anomaly Detection and Pattern Evolution
Identifies previously unknown vulnerability patterns
"""
import numpy as np
from typing import List, Dict, Tuple, Optional, Set
from datetime import datetime, timedelta
from dataclasses import dataclass
import json
from pathlib import Path
from sklearn.ensemble import IsolationForest
from sklearn.cluster import DBSCAN
import torch
from collections import defaultdict

from src.ml.codebert_model import CodeBERTManager
from src.ml.code_graph import CodeGraphBuilder
from src.core.base_scanner import Vulnerability, Severity

@dataclass
class ZeroDayCandidate:
    """Potential zero-day vulnerability"""
    pattern_id: str
    code_snippet: str
    file_path: str
    line_number: int
    anomaly_score: float
    cluster_id: int
    similar_patterns: List[str]
    first_seen: datetime
    occurrences: int
    risk_assessment: str
    predicted_cwe: Optional[str]
    confidence: float

@dataclass
class PatternEvolution:
    """Tracks how vulnerability patterns evolve"""
    base_pattern: str
    mutations: List[str]
    timeline: List[datetime]
    severity_trend: List[float]

class ZeroDayDetector:
    """Detects potential zero-day vulnerabilities using ML anomaly detection"""
    
    def __init__(self, data_dir: str = "data/zero_day"):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        
        # ML models
        self.codebert = CodeBERTManager()
        self.graph_builder = CodeGraphBuilder()
        
        # Anomaly detection models
        self.isolation_forest = IsolationForest(
            contamination=0.1,  # Expect 10% anomalies
            random_state=42
        )
        
        # Clustering for pattern grouping
        self.dbscan = DBSCAN(eps=0.3, min_samples=2)
        
        # Pattern storage
        self.known_patterns_file = self.data_dir / "known_patterns.json"
        self.zero_day_candidates_file = self.data_dir / "zero_day_candidates.json"
        self.pattern_evolution_file = self.data_dir / "pattern_evolution.json"
        
        # Load existing data
        self.known_patterns = self._load_known_patterns()
        self.zero_day_candidates = self._load_candidates()
        self.pattern_evolution = self._load_evolution()
        
        # Pattern fingerprints cache
        self.fingerprint_cache = {}
        
        # Statistical thresholds
        self.anomaly_threshold = -0.5
        self.evolution_threshold = 0.7
        
        print("✓ Zero-Day Detector initialized")
    
    async def analyze_for_zero_days(self, code: str, language: str, 
                                   file_path: str) -> List[ZeroDayCandidate]:
        """Analyze code for potential zero-day patterns"""
        candidates = []
        
        # Extract code segments
        segments = self._extract_code_segments(code, language)
        
        for segment in segments:
            # Generate multi-dimensional fingerprint
            fingerprint = await self._generate_fingerprint(
                segment['code'], language
            )
            
            # Check if it's anomalous
            anomaly_score = self._detect_anomaly(fingerprint)
            
            if anomaly_score < self.anomaly_threshold:
                # Potential zero-day pattern
                candidate = await self._analyze_anomaly(
                    segment, fingerprint, anomaly_score, 
                    language, file_path
                )
                
                if candidate and candidate.confidence > 0.6:
                    candidates.append(candidate)
                    self._record_candidate(candidate)
        
        # Check for pattern evolution
        evolution_candidates = await self._detect_pattern_evolution(
            code, language, file_path
        )
        candidates.extend(evolution_candidates)
        
        return candidates
    
    def _extract_code_segments(self, code: str, language: str) -> List[Dict]:
        """Extract interesting code segments for analysis"""
        segments = []
        lines = code.split('\n')
        
        # Function-level segments
        current_function = []
        function_start = 0
        in_function = False
        
        for i, line in enumerate(lines):
            # Simple function detection
            if any(keyword in line for keyword in ['def ', 'function ', 'public ', 'private ']):
                if current_function and in_function:
                    segments.append({
                        'code': '\n'.join(current_function),
                        'start_line': function_start + 1,
                        'type': 'function'
                    })
                current_function = [line]
                function_start = i
                in_function = True
            elif in_function:
                current_function.append(line)
        
        # Add last function
        if current_function:
            segments.append({
                'code': '\n'.join(current_function),
                'start_line': function_start + 1,
                'type': 'function'
            })
        
        # Also analyze interesting patterns
        pattern_segments = self._extract_pattern_segments(code, lines)
        segments.extend(pattern_segments)
        
        return segments
    
    def _extract_pattern_segments(self, code: str, lines: List[str]) -> List[Dict]:
        """Extract segments with interesting patterns"""
        segments = []
        
        # Patterns that might indicate new vulnerability types
        interesting_patterns = [
            # Data flow patterns
            (r'(\w+)\s*=.*\n.*\1', 'data_flow'),
            # Unusual function combinations
            (r'(eval|exec|system).*\n.*(request|input|user)', 'dangerous_combo'),
            # Reflection patterns
            (r'getattr.*\(.*,.*request', 'reflection'),
            # Dynamic imports
            (r'__import__.*\(.*\+', 'dynamic_import'),
            # Unsafe protocols
            (r'pickle.*loads.*request', 'unsafe_protocol'),
        ]
        
        import re
        for pattern, pattern_type in interesting_patterns:
            for match in re.finditer(pattern, code, re.MULTILINE | re.IGNORECASE):
                start_line = code[:match.start()].count('\n') + 1
                segments.append({
                    'code': match.group(0),
                    'start_line': start_line,
                    'type': pattern_type
                })
        
        return segments
    
    async def _generate_fingerprint(self, code: str, language: str) -> np.ndarray:
        """Generate multi-dimensional fingerprint for code"""
        # Check cache
        cache_key = hash(code + language)
        if cache_key in self.fingerprint_cache:
            return self.fingerprint_cache[cache_key]
        
        features = []
        
        # 1. Semantic embedding from CodeBERT
        embedding = self.codebert.get_embedding(code, language)
        features.extend(embedding[:100])  # Use first 100 dimensions
        
        # 2. Structural features from AST
        try:
            graph = self.graph_builder.build_graph(code, language)
            structural_features = [
                len(graph.nodes()),
                len(graph.edges()),
                graph.number_of_nodes() / max(len(code.split('\n')), 1),  # Density
                self._calculate_graph_complexity(graph),
            ]
            features.extend(structural_features)
        except:
            features.extend([0, 0, 0, 0])
        
        # 3. Statistical features
        statistical_features = [
            len(code),
            code.count('\n'),
            len(set(code.split())),  # Unique tokens
            sum(1 for c in code if c in '()[]{}'),  # Bracket complexity
            sum(1 for line in code.split('\n') if line.strip().startswith('#')),  # Comments
        ]
        features.extend(statistical_features)
        
        # 4. Security-specific features
        security_features = [
            float(any(danger in code.lower() for danger in ['eval', 'exec', 'system'])),
            float('sql' in code.lower() or 'query' in code.lower()),
            float('request' in code.lower() or 'input' in code.lower()),
            float('password' in code.lower() or 'secret' in code.lower()),
            float(any(proto in code for proto in ['pickle', 'marshal', 'yaml'])),
        ]
        features.extend(security_features)
        
        fingerprint = np.array(features)
        
        # Cache it
        self.fingerprint_cache[cache_key] = fingerprint
        
        return fingerprint
    
    def _calculate_graph_complexity(self, graph) -> float:
        """Calculate complexity metric from code graph"""
        if len(graph.nodes()) == 0:
            return 0.0
        
        # Simplified complexity: edges per node
        return len(graph.edges()) / len(graph.nodes())
    
    def _detect_anomaly(self, fingerprint: np.ndarray) -> float:
        """Detect if fingerprint is anomalous"""
        # Train or update isolation forest if needed
        if len(self.known_patterns) > 100:
            known_fingerprints = np.array([
                p['fingerprint'] for p in self.known_patterns.values()
                if 'fingerprint' in p
            ])
            
            if len(known_fingerprints) > 10:
                self.isolation_forest.fit(known_fingerprints)
                
                # Predict anomaly score
                anomaly_score = self.isolation_forest.score_samples([fingerprint])[0]
                return anomaly_score
        
        # Default: compare to known patterns
        min_distance = float('inf')
        for pattern_data in self.known_patterns.values():
            if 'fingerprint' in pattern_data:
                distance = np.linalg.norm(
                    fingerprint - np.array(pattern_data['fingerprint'])
                )
                min_distance = min(min_distance, distance)
        
        # Convert distance to anomaly score
        return -min_distance / 100
    
    async def _analyze_anomaly(self, segment: Dict, fingerprint: np.ndarray,
                              anomaly_score: float, language: str,
                              file_path: str) -> Optional[ZeroDayCandidate]:
        """Analyze anomalous code segment"""
        # Find similar patterns using clustering
        all_fingerprints = [fingerprint]
        pattern_ids = ['current']
        
        for pid, pdata in self.known_patterns.items():
            if 'fingerprint' in pdata:
                all_fingerprints.append(np.array(pdata['fingerprint']))
                pattern_ids.append(pid)
        
        if len(all_fingerprints) > 5:
            # Cluster patterns
            clusters = self.dbscan.fit_predict(all_fingerprints)
            current_cluster = clusters[0]
            
            # Find similar patterns in same cluster
            similar_patterns = [
                pattern_ids[i] for i, c in enumerate(clusters)
                if c == current_cluster and i > 0
            ][:5]
        else:
            similar_patterns = []
            current_cluster = -1
        
        # Risk assessment based on code analysis
        risk_assessment = self._assess_risk(segment['code'])
        
        # Predict potential CWE category
        predicted_cwe = self._predict_cwe(fingerprint, segment['code'])
        
        # Calculate confidence
        confidence = self._calculate_confidence(
            anomaly_score, risk_assessment, len(similar_patterns)
        )
        
        # Create candidate
        candidate = ZeroDayCandidate(
            pattern_id=f"ZERO-DAY-{datetime.now().strftime('%Y%m%d%H%M%S')}",
            code_snippet=segment['code'],
            file_path=file_path,
            line_number=segment['start_line'],
            anomaly_score=anomaly_score,
            cluster_id=current_cluster,
            similar_patterns=similar_patterns,
            first_seen=datetime.now(),
            occurrences=1,
            risk_assessment=risk_assessment,
            predicted_cwe=predicted_cwe,
            confidence=confidence
        )
        
        return candidate
    
    def _assess_risk(self, code: str) -> str:
        """Assess security risk of code"""
        risk_indicators = {
            'critical': ['eval', 'exec', 'pickle.loads', '__import__'],
            'high': ['system', 'subprocess', 'os.', 'request.'],
            'medium': ['open(', 'file', 'path'],
        }
        
        code_lower = code.lower()
        
        for level, indicators in risk_indicators.items():
            if any(ind in code_lower for ind in indicators):
                return f"{level.upper()}: Potential security-sensitive operations"
        
        return "LOW: No immediate security indicators"
    
    def _predict_cwe(self, fingerprint: np.ndarray, code: str) -> Optional[str]:
        """Predict most likely CWE category"""
        # Simple heuristic-based prediction
        code_lower = code.lower()
        
        if 'sql' in code_lower or 'query' in code_lower:
            return "CWE-89"  # SQL Injection
        elif 'eval' in code_lower or 'exec' in code_lower:
            return "CWE-94"  # Code Injection
        elif 'system' in code_lower or 'subprocess' in code_lower:
            return "CWE-78"  # OS Command Injection
        elif 'pickle' in code_lower or 'marshal' in code_lower:
            return "CWE-502"  # Deserialization
        elif any(path in code_lower for path in ['../', '..\\', 'path']):
            return "CWE-22"  # Path Traversal
        
        return None
    
    def _calculate_confidence(self, anomaly_score: float, 
                            risk_assessment: str,
                            similar_count: int) -> float:
        """Calculate confidence in zero-day detection"""
        confidence = 0.5
        
        # Anomaly contribution
        if anomaly_score < -1.0:
            confidence += 0.3
        elif anomaly_score < -0.5:
            confidence += 0.2
        
        # Risk level contribution
        if 'CRITICAL' in risk_assessment:
            confidence += 0.2
        elif 'HIGH' in risk_assessment:
            confidence += 0.1
        
        # Similar patterns reduce confidence (might be variant)
        if similar_count > 3:
            confidence -= 0.1
        elif similar_count > 0:
            confidence -= 0.05
        
        return min(max(confidence, 0.0), 1.0)
    
    async def _detect_pattern_evolution(self, code: str, language: str,
                                      file_path: str) -> List[ZeroDayCandidate]:
        """Detect evolved versions of known patterns"""
        candidates = []
        
        # Check each known vulnerability pattern
        for pattern_id, evolution in self.pattern_evolution.items():
            # Get base pattern embedding
            if pattern_id in self.known_patterns:
                base_embedding = self.known_patterns[pattern_id].get('embedding')
                
                if base_embedding:
                    # Check if current code is similar but different
                    code_embedding = self.codebert.get_embedding(code, language)
                    similarity = self.codebert.calculate_similarity(
                        np.array(base_embedding), code_embedding
                    )
                    
                    # Evolved pattern: similar but not identical
                    if 0.6 < similarity < 0.9:
                        # Check if it's a new mutation
                        is_new_mutation = True
                        for mutation in evolution.get('mutations', []):
                            mut_embedding = np.array(mutation['embedding'])
                            mut_similarity = self.codebert.calculate_similarity(
                                code_embedding, mut_embedding
                            )
                            if mut_similarity > 0.95:
                                is_new_mutation = False
                                break
                        
                        if is_new_mutation:
                            candidate = ZeroDayCandidate(
                                pattern_id=f"EVOLUTION-{pattern_id}-{len(evolution.get('mutations', []))}",
                                code_snippet=code[:500],
                                file_path=file_path,
                                line_number=1,
                                anomaly_score=-0.6,
                                cluster_id=-1,
                                similar_patterns=[pattern_id],
                                first_seen=datetime.now(),
                                occurrences=1,
                                risk_assessment=f"Evolution of {pattern_id}",
                                predicted_cwe=self.known_patterns[pattern_id].get('cwe'),
                                confidence=0.7
                            )
                            candidates.append(candidate)
                            
                            # Record evolution
                            self._record_evolution(pattern_id, code, code_embedding)
        
        return candidates
    
    def _record_candidate(self, candidate: ZeroDayCandidate):
        """Record zero-day candidate"""
        self.zero_day_candidates[candidate.pattern_id] = {
            'code_snippet': candidate.code_snippet,
            'file_path': candidate.file_path,
            'line_number': candidate.line_number,
            'anomaly_score': candidate.anomaly_score,
            'first_seen': candidate.first_seen.isoformat(),
            'occurrences': candidate.occurrences,
            'risk_assessment': candidate.risk_assessment,
            'predicted_cwe': candidate.predicted_cwe,
            'confidence': candidate.confidence
        }
        self._save_candidates()
    
    def _record_evolution(self, pattern_id: str, code: str, embedding: np.ndarray):
        """Record pattern evolution"""
        if pattern_id not in self.pattern_evolution:
            self.pattern_evolution[pattern_id] = {
                'base_pattern': pattern_id,
                'mutations': [],
                'timeline': []
            }
        
        self.pattern_evolution[pattern_id]['mutations'].append({
            'code': code[:500],
            'embedding': embedding.tolist(),
            'timestamp': datetime.now().isoformat()
        })
        
        self._save_evolution()
    
    def get_zero_day_summary(self) -> Dict[str, any]:
        """Get summary of zero-day detection"""
        summary = {
            'total_candidates': len(self.zero_day_candidates),
            'high_confidence': sum(
                1 for c in self.zero_day_candidates.values()
                if c.get('confidence', 0) > 0.8
            ),
            'recent_24h': sum(
                1 for c in self.zero_day_candidates.values()
                if datetime.fromisoformat(c['first_seen']) > 
                   datetime.now() - timedelta(hours=24)
            ),
            'risk_distribution': defaultdict(int),
            'predicted_cwes': defaultdict(int),
            'evolution_patterns': len(self.pattern_evolution)
        }
        
        # Count risk levels
        for candidate in self.zero_day_candidates.values():
            risk = candidate['risk_assessment'].split(':')[0]
            summary['risk_distribution'][risk] += 1
            
            if candidate.get('predicted_cwe'):
                summary['predicted_cwes'][candidate['predicted_cwe']] += 1
        
        return dict(summary)
    
    def _load_known_patterns(self) -> Dict:
        """Load known vulnerability patterns"""
        if self.known_patterns_file.exists():
            with open(self.known_patterns_file, 'r') as f:
                return json.load(f)
        
        # Initialize with basic patterns
        return {
            'SQL-001': {'name': 'SQL Injection', 'cwe': 'CWE-89'},
            'XSS-001': {'name': 'Cross-Site Scripting', 'cwe': 'CWE-79'},
            'CMD-001': {'name': 'Command Injection', 'cwe': 'CWE-78'}
        }
    
    def _load_candidates(self) -> Dict:
        """Load zero-day candidates"""
        if self.zero_day_candidates_file.exists():
            with open(self.zero_day_candidates_file, 'r') as f:
                return json.load(f)
        return {}
    
    def _load_evolution(self) -> Dict:
        """Load pattern evolution data"""
        if self.pattern_evolution_file.exists():
            with open(self.pattern_evolution_file, 'r') as f:
                return json.load(f)
        return {}
    
    def _save_candidates(self):
        """Save zero-day candidates"""
        with open(self.zero_day_candidates_file, 'w') as f:
            json.dump(self.zero_day_candidates, f, indent=2)
    
    def _save_evolution(self):
        """Save pattern evolution"""
        with open(self.pattern_evolution_file, 'w') as f:
            json.dump(self.pattern_evolution, f, indent=2)


# API endpoint
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from src.database.models.base import get_db

router = APIRouter(prefix="/api/zero-day", tags=["Zero-Day Detection"])

zero_day_detector = ZeroDayDetector()

@router.post("/analyze")
async def analyze_for_zero_days(
    code: str,
    language: str = "python",
    file_path: str = "unknown"
):
    """Analyze code for potential zero-day patterns"""
    candidates = await zero_day_detector.analyze_for_zero_days(
        code, language, file_path
    )
    
    return {
        "candidates": [
            {
                "pattern_id": c.pattern_id,
                "risk": c.risk_assessment,
                "confidence": c.confidence,
                "predicted_cwe": c.predicted_cwe,
                "line": c.line_number,
                "snippet": c.code_snippet[:200] + "..." if len(c.code_snippet) > 200 else c.code_snippet
            }
            for c in candidates
        ],
        "summary": zero_day_detector.get_zero_day_summary()
    }

@router.get("/summary")
async def get_zero_day_summary():
    """Get zero-day detection summary"""
    return zero_day_detector.get_zero_day_summary()

@router.get("/candidates")
async def get_all_candidates():
    """Get all zero-day candidates"""
    return {
        "candidates": zero_day_detector.zero_day_candidates,
        "total": len(zero_day_detector.zero_day_candidates)
    }