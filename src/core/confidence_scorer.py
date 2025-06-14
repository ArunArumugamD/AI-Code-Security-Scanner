# src/core/confidence_scorer.py
import numpy as np
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass
from enum import Enum
import json
from pathlib import Path

class ConfidenceFactors(Enum):
    """Factors that influence confidence scoring"""
    PATTERN_MATCH = "pattern_match"
    AST_ANALYSIS = "ast_analysis"
    AI_DETECTION = "ai_detection"
    CONTEXT_ANALYSIS = "context_analysis"
    HISTORICAL_DATA = "historical_data"
    CODE_COMPLEXITY = "code_complexity"
    USER_FEEDBACK = "user_feedback"

@dataclass
class ConfidenceScore:
    """Detailed confidence score with breakdown"""
    overall_confidence: float
    factors: Dict[str, float]
    explanation: str
    reliability_rating: str  # "high", "medium", "low"
    
    def to_dict(self) -> Dict:
        return {
            "overall_confidence": self.overall_confidence,
            "factors": self.factors,
            "explanation": self.explanation,
            "reliability_rating": self.reliability_rating
        }

class ConfidenceScorer:
    """Advanced confidence scoring system for vulnerability detection"""
    
    def __init__(self, history_file: str = "data/confidence_history.json"):
        self.history_file = Path(history_file)
        self.history_file.parent.mkdir(parents=True, exist_ok=True)
        
        # Load historical accuracy data
        self.historical_accuracy = self._load_history()
        
        # Weight factors for different detection methods
        self.method_weights = {
            "pattern": 0.7,      # Traditional pattern matching
            "ast": 0.8,          # AST analysis
            "codebert": 0.9,     # CodeBERT AI
            "gnn": 0.85,         # Graph Neural Network
            "hybrid": 0.95       # Hybrid AI model
        }
        
        # Context modifiers
        self.context_modifiers = {
            "in_test_file": -0.3,        # Lower confidence in test files
            "in_comment": -0.5,          # Much lower if in comment
            "user_input_nearby": 0.2,    # Higher if user input detected
            "security_function": -0.2,   # Lower if in security function
            "validated_input": -0.3,     # Lower if input is validated
            "third_party_library": -0.1  # Slightly lower in libraries
        }
        
        print("✓ Confidence Scorer initialized")
    
    def calculate_confidence(self, 
                           vulnerability_type: str,
                           detection_methods: List[Tuple[str, float]],
                           code_context: Dict[str, any],
                           file_path: str) -> ConfidenceScore:
        """Calculate comprehensive confidence score"""
        
        factors = {}
        
        # 1. Base confidence from detection methods
        base_confidence = self._calculate_base_confidence(detection_methods)
        factors["base_detection"] = base_confidence
        
        # 2. Context analysis
        context_score = self._analyze_context(code_context, file_path)
        factors["context"] = context_score
        
        # 3. Historical accuracy for this vulnerability type
        historical_score = self._get_historical_accuracy(vulnerability_type)
        factors["historical"] = historical_score
        
        # 4. Code complexity factor
        complexity_score = self._analyze_complexity(code_context)
        factors["complexity"] = complexity_score
        
        # 5. Cross-validation between methods
        validation_score = self._cross_validate_methods(detection_methods)
        factors["validation"] = validation_score
        
        # 6. Calculate weighted overall confidence
        weights = {
            "base_detection": 0.4,
            "context": 0.2,
            "historical": 0.15,
            "complexity": 0.1,
            "validation": 0.15
        }
        
        overall_confidence = sum(
            factors[key] * weights[key] 
            for key in weights if key in factors
        )
        
        # Apply bounds
        overall_confidence = max(0.0, min(1.0, overall_confidence))
        
        # Determine reliability rating
        reliability = self._calculate_reliability(factors, detection_methods)
        
        # Generate explanation
        explanation = self._generate_explanation(
            vulnerability_type, factors, detection_methods, overall_confidence
        )
        
        return ConfidenceScore(
            overall_confidence=overall_confidence,
            factors=factors,
            explanation=explanation,
            reliability_rating=reliability
        )
    
    def _calculate_base_confidence(self, detection_methods: List[Tuple[str, float]]) -> float:
        """Calculate base confidence from detection methods"""
        if not detection_methods:
            return 0.0
        
        weighted_sum = 0.0
        total_weight = 0.0
        
        for method, score in detection_methods:
            weight = self.method_weights.get(method, 0.5)
            weighted_sum += score * weight
            total_weight += weight
        
        return weighted_sum / total_weight if total_weight > 0 else 0.0
    
    def _analyze_context(self, code_context: Dict[str, any], file_path: str) -> float:
        """Analyze code context to adjust confidence"""
        context_score = 1.0
        
        # Check file type
        if any(test_indicator in file_path.lower() 
               for test_indicator in ['test_', '_test.', '/tests/', '\\tests\\']):
            context_score += self.context_modifiers["in_test_file"]
        
        # Check code properties
        if code_context.get("in_comment", False):
            context_score += self.context_modifiers["in_comment"]
        
        if code_context.get("has_user_input", False):
            context_score += self.context_modifiers["user_input_nearby"]
        
        if code_context.get("has_validation", False):
            context_score += self.context_modifiers["validated_input"]
        
        # Check if in security-related function
        func_name = code_context.get("function_name", "").lower()
        if any(sec_term in func_name for sec_term in ["sanitize", "validate", "escape", "filter"]):
            context_score += self.context_modifiers["security_function"]
        
        return max(0.0, min(1.0, context_score))
    
    def _get_historical_accuracy(self, vulnerability_type: str) -> float:
        """Get historical accuracy for this vulnerability type"""
        if vulnerability_type in self.historical_accuracy:
            data = self.historical_accuracy[vulnerability_type]
            if data["total"] > 0:
                return data["correct"] / data["total"]
        return 0.75  # Default confidence for new types
    
    def _analyze_complexity(self, code_context: Dict[str, any]) -> float:
        """Analyze code complexity impact on confidence"""
        complexity = code_context.get("cyclomatic_complexity", 1)
        lines = code_context.get("lines_of_code", 1)
        
        # Higher complexity = slightly lower confidence
        if complexity > 10:
            return 0.7
        elif complexity > 5:
            return 0.85
        else:
            return 1.0
    
    def _cross_validate_methods(self, detection_methods: List[Tuple[str, float]]) -> float:
        """Cross-validate between different detection methods"""
        if len(detection_methods) < 2:
            return 0.5  # Single method, neutral validation
        
        # Calculate variance between methods
        scores = [score for _, score in detection_methods]
        variance = np.var(scores)
        
        # Low variance = high agreement = high validation score
        if variance < 0.05:
            return 0.95
        elif variance < 0.1:
            return 0.8
        elif variance < 0.2:
            return 0.6
        else:
            return 0.4
    
    def _calculate_reliability(self, factors: Dict[str, float], 
                             detection_methods: List[Tuple[str, float]]) -> str:
        """Calculate reliability rating"""
        # High reliability: Multiple AI methods agree with high scores
        ai_methods = [m for m, _ in detection_methods if m in ["codebert", "gnn", "hybrid"]]
        ai_scores = [s for m, s in detection_methods if m in ["codebert", "gnn", "hybrid"]]
        
        if len(ai_methods) >= 2 and all(s > 0.8 for s in ai_scores):
            return "high"
        elif factors.get("validation", 0) > 0.7 and factors.get("base_detection", 0) > 0.7:
            return "high"
        elif factors.get("base_detection", 0) > 0.5:
            return "medium"
        else:
            return "low"
    
    def _generate_explanation(self, vuln_type: str, factors: Dict[str, float],
                            detection_methods: List[Tuple[str, float]], 
                            overall_confidence: float) -> str:
        """Generate human-readable explanation of confidence score"""
        explanation = f"Confidence Analysis for {vuln_type}:\n"
        
        # Overall assessment
        if overall_confidence > 0.8:
            explanation += f"HIGH CONFIDENCE ({overall_confidence:.1%}): Strong evidence from multiple sources.\n"
        elif overall_confidence > 0.6:
            explanation += f"MODERATE CONFIDENCE ({overall_confidence:.1%}): Reasonable evidence, manual review recommended.\n"
        else:
            explanation += f"LOW CONFIDENCE ({overall_confidence:.1%}): Weak evidence, likely false positive.\n"
        
        # Detection method summary
        explanation += "\nDetection Methods:\n"
        for method, score in detection_methods:
            explanation += f"  • {method.upper()}: {score:.1%}\n"
        
        # Factor breakdown
        explanation += "\nConfidence Factors:\n"
        for factor, score in factors.items():
            explanation += f"  • {factor.replace('_', ' ').title()}: {score:.1%}\n"
        
        # Context warnings
        if factors.get("context", 1.0) < 0.7:
            explanation += "\n⚠️ Context suggests lower confidence (test file, comment, or validated input)."
        
        return explanation
    
    def update_feedback(self, vulnerability_type: str, was_correct: bool):
        """Update historical accuracy based on user feedback"""
        if vulnerability_type not in self.historical_accuracy:
            self.historical_accuracy[vulnerability_type] = {"correct": 0, "total": 0}
        
        self.historical_accuracy[vulnerability_type]["total"] += 1
        if was_correct:
            self.historical_accuracy[vulnerability_type]["correct"] += 1
        
        self._save_history()
    
    def _load_history(self) -> Dict:
        """Load historical accuracy data"""
        if self.history_file.exists():
            try:
                with open(self.history_file, 'r') as f:
                    return json.load(f)
            except:
                pass
        return {}
    
    def _save_history(self):
        """Save historical accuracy data"""
        with open(self.history_file, 'w') as f:
            json.dump(self.historical_accuracy, f, indent=2)
    
    def get_confidence_report(self) -> Dict:
        """Get overall confidence scoring report"""
        report = {
            "historical_accuracy": {},
            "method_weights": self.method_weights,
            "total_feedbacks": sum(
                data["total"] for data in self.historical_accuracy.values()
            )
        }
        
        for vuln_type, data in self.historical_accuracy.items():
            if data["total"] > 0:
                accuracy = data["correct"] / data["total"]
                report["historical_accuracy"][vuln_type] = {
                    "accuracy": accuracy,
                    "samples": data["total"]
                }
        
        return report
