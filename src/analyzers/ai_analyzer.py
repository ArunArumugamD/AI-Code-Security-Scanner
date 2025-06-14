# src/analyzers/ai_analyzer.py
import asyncio
import numpy as np
from typing import List, Dict, Optional
from src.core.base_scanner import BaseAnalyzer, Vulnerability, Severity
from src.ml.codebert_model import CodeBERTManager
from src.database.models.base import SessionLocal
from src.database.models.vulnerability import VulnerabilityPattern, VulnerabilityDetection

class AIEnhancedAnalyzer(BaseAnalyzer):
    """AI-powered analyzer using CodeBERT embeddings"""
    
    def __init__(self):
        super().__init__(
            name="AI-Enhanced Security Analyzer",
            supported_languages=['python', 'javascript', 'java', 'php', 'c', 'cpp']
        )
        self.is_ai_powered = True
        
        # Initialize CodeBERT
        try:
            self.codebert = CodeBERTManager()
            self.ai_ready = True
            print("✓ AI-Enhanced Analyzer initialized with CodeBERT")
        except Exception as e:
            print(f"⚠ AI features disabled: {e}")
            self.ai_ready = False
            self.codebert = None
        
        # Load known vulnerable code samples from database
        self._load_vulnerability_samples()
    
    def _load_vulnerability_samples(self):
        """Load historical vulnerability samples for similarity matching"""
        self.vulnerability_samples = []
        
        db = SessionLocal()
        try:
            # Get recent confirmed vulnerabilities as training samples
            samples = db.query(VulnerabilityDetection).filter(
                VulnerabilityDetection.status == 'confirmed',
                VulnerabilityDetection.confidence_score > 0.8
            ).limit(100).all()
            
            for sample in samples:
                self.vulnerability_samples.append({
                    'code': sample.code_snippet,
                    'severity': sample.severity,
                    'type': sample.pattern.name if sample.pattern else 'unknown',
                    'language': self._guess_language(sample.file_path)
                })
            
            print(f"✓ Loaded {len(self.vulnerability_samples)} vulnerability samples")
            
        finally:
            db.close()
    
    def _guess_language(self, file_path: str) -> str:
        """Guess language from file extension"""
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
        return 'python'  # default
    
    async def analyze(self, code: str, language: str, file_path: str) -> List[Vulnerability]:
        """Analyze code using AI-powered techniques"""
        if not self.ai_ready or not self.codebert:
            return []  # Skip if AI not available
        
        vulnerabilities = []
        
        # Split code into functions/blocks for analysis
        code_blocks = self._extract_code_blocks(code, language)
        
        for block in code_blocks:
            # Run AI analysis in thread pool to avoid blocking
            result = await asyncio.to_thread(
                self._analyze_code_block,
                block['code'],
                language,
                block['start_line'],
                file_path
            )
            
            if result:
                vulnerabilities.extend(result)
        
        return vulnerabilities
    
    def _extract_code_blocks(self, code: str, language: str) -> List[Dict]:
        """Extract logical code blocks (functions, methods) for analysis"""
        blocks = []
        lines = code.split('\n')
        
        # Simple extraction - can be improved with proper parsing
        current_block = []
        block_start = 0
        in_function = False
        
        for i, line in enumerate(lines):
            # Detect function/method start
            if any(keyword in line for keyword in ['def ', 'function ', 'public ', 'private ']):
                if current_block and in_function:
                    # Save previous block
                    blocks.append({
                        'code': '\n'.join(current_block),
                        'start_line': block_start + 1
                    })
                current_block = [line]
                block_start = i
                in_function = True
            elif in_function:
                current_block.append(line)
                
                # Detect function end (empty line after content)
                if not line.strip() and len(current_block) > 3:
                    blocks.append({
                        'code': '\n'.join(current_block),
                        'start_line': block_start + 1
                    })
                    current_block = []
                    in_function = False
        
        # Add last block
        if current_block:
            blocks.append({
                'code': '\n'.join(current_block),
                'start_line': block_start + 1
            })
        
        # If no blocks found, analyze whole code
        if not blocks:
            blocks = [{'code': code, 'start_line': 1}]
        
        return blocks
    
    def _analyze_code_block(self, code_block: str, language: str, 
                           start_line: int, file_path: str) -> List[Vulnerability]:
        """Analyze a single code block using AI"""
        vulnerabilities = []
        
        # Get embedding for this code block
        try:
            code_embedding = self.codebert.get_embedding(code_block, language)
        except Exception as e:
            print(f"Error generating embedding: {e}")
            return vulnerabilities
        
        # Find similar vulnerable code
        if self.vulnerability_samples:
            similar_vulns = self.codebert.find_similar_code(
                code_block,
                self.vulnerability_samples,
                language,
                top_k=3
            )
            
            for similar in similar_vulns:
                if similar['similarity'] > 0.75:  # High similarity threshold
                    # Analyze context for specific vulnerability type
                    vuln_type_key = self._get_vuln_type_key(similar['type'])
                    context_analysis = self.codebert.analyze_vulnerability_context(
                        code_block,
                        vuln_type_key,
                        language
                    )
                    
                    # Calculate final confidence
                    base_confidence = similar['similarity']
                    final_confidence = min(
                        base_confidence + context_analysis['confidence_boost'],
                        0.95
                    )
                    
                    if final_confidence > 0.7:
                        vuln = Vulnerability(
                            id=f"AI-{file_path}-{start_line}-{similar['type']}",
                            name=f"AI-Detected: {similar['type']}",
                            description=f"Code pattern similar to known {similar['type']} vulnerability",
                            severity=self._map_severity(similar['severity']),
                            confidence=final_confidence,
                            file_path=file_path,
                            line_start=start_line,
                            line_end=start_line + len(code_block.split('\n')) - 1,
                            code_snippet=code_block[:200],
                            ai_explanation=self._generate_explanation(
                                similar, context_analysis, final_confidence
                            )
                        )
                        vulnerabilities.append(vuln)
        
        # Additional AI-based pattern detection
        ai_patterns = self._detect_ai_patterns(code_block, language, code_embedding)
        for pattern in ai_patterns:
            vuln = Vulnerability(
                id=f"AI-PATTERN-{file_path}-{start_line}-{pattern['type']}",
                name=f"AI Pattern: {pattern['name']}",
                description=pattern['description'],
                severity=Severity.MEDIUM,
                confidence=pattern['confidence'],
                file_path=file_path,
                line_start=start_line,
                line_end=start_line + len(code_block.split('\n')) - 1,
                code_snippet=code_block[:200],
                ai_explanation=pattern['explanation']
            )
            vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _get_vuln_type_key(self, vuln_type: str) -> str:
        """Map vulnerability type to key for context analysis"""
        mapping = {
            'SQL Injection': 'sql_injection',
            'Cross-Site Scripting': 'xss',
            'Command Injection': 'command_injection'
        }
        
        for key, value in mapping.items():
            if key in vuln_type:
                return value
        
        return vuln_type.lower().replace(' ', '_')
    
    def _map_severity(self, severity_str: str) -> Severity:
        """Map string severity to enum"""
        mapping = {
            'critical': Severity.CRITICAL,
            'high': Severity.HIGH,
            'medium': Severity.MEDIUM,
            'low': Severity.LOW
        }
        return mapping.get(severity_str.lower(), Severity.MEDIUM)
    
    def _generate_explanation(self, similar_vuln: Dict, 
                            context_analysis: Dict,
                            confidence: float) -> str:
        """Generate AI explanation for the vulnerability"""
        explanation = f"AI Analysis: This code is {similar_vuln['similarity']:.0%} similar to a known {similar_vuln['type']} vulnerability. "
        
        if context_analysis['similar_to_known_vulnerable']:
            explanation += "The pattern strongly matches known vulnerable code structures. "
        
        explanation += f"Confidence level: {confidence:.0%}. "
        
        if confidence > 0.85:
            explanation += "High probability of vulnerability - immediate review recommended."
        elif confidence > 0.75:
            explanation += "Moderate probability - manual review advised."
        
        return explanation
    
    def _detect_ai_patterns(self, code_block: str, language: str, 
                           embedding: np.ndarray) -> List[Dict]:
        """Detect additional patterns using AI heuristics"""
        patterns = []
        
        # Example: Detect hardcoded secrets using embedding similarity
        secret_patterns = [
            "password = 'hardcoded_value'",
            "api_key = 'AKIA1234567890ABCDEF'",
            "secret_key = 'my_secret_key_123'"
        ]
        
        for pattern in secret_patterns:
            pattern_embedding = self.codebert.get_embedding(pattern, language)
            similarity = self.codebert.calculate_similarity(embedding, pattern_embedding)
            
            if similarity > 0.7:
                patterns.append({
                    'type': 'hardcoded_secret',
                    'name': 'Potential Hardcoded Secret',
                    'description': 'AI detected possible hardcoded credentials or secrets',
                    'confidence': similarity,
                    'explanation': f'Code pattern {similarity:.0%} similar to hardcoded secret patterns'
                })
                break
        
        return patterns

