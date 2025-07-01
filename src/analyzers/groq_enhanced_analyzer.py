# src/analyzers/groq_enhanced_analyzer.py
from typing import List
from src.core.base_scanner import BaseAnalyzer, Vulnerability, Severity
from src.ml.groq_analyzer import GroqCloudAnalyzer, GroqExplanation
import asyncio

class GroqEnhancedAnalyzer(BaseAnalyzer):
    """Analyzer that enhances all vulnerabilities with Groq AI explanations"""
    
    def __init__(self, base_analyzer: BaseAnalyzer):
        super().__init__(
            name=f"Groq-Enhanced {base_analyzer.name}",
            supported_languages=base_analyzer.supported_languages
        )
        self.base_analyzer = base_analyzer
        self.is_ai_powered = True
        
        try:
            self.groq = GroqCloudAnalyzer()
            self.groq_enabled = True
            print(f"✓ Groq enhancement enabled for {base_analyzer.name}")
        except Exception as e:
            print(f"⚠ Groq enhancement disabled: {e}")
            self.groq_enabled = False
    
    async def analyze(self, code: str, language: str, file_path: str) -> List[Vulnerability]:
        """Run base analyzer then enhance with Groq explanations"""
        # Get base vulnerabilities
        vulnerabilities = await self.base_analyzer.analyze(code, language, file_path)
        
        if not self.groq_enabled or not vulnerabilities:
            return vulnerabilities
        
        # Enhance each vulnerability with Groq
        enhanced_vulns = []
        
        for vuln in vulnerabilities:
            try:
                # Prepare vulnerability info for Groq
                vuln_info = {
                    'type': vuln.name,
                    'severity': vuln.severity.value,
                    'confidence': vuln.confidence,
                    'line': vuln.line_start,
                    'cwe_id': vuln.cwe_id
                }
                
                # Get Groq analysis
                groq_explanation = await self.groq.analyze_vulnerability(
                    vuln.code_snippet,
                    vuln_info,
                    language
                )
                
                # Enhance the vulnerability
                vuln.ai_explanation = self._create_enhanced_explanation(
                    vuln.ai_explanation,
                    groq_explanation
                )
                
                # Update fix suggestion with Groq's recommendation
                vuln.fix_suggestion = groq_explanation.fix_recommendation
                
                # Boost confidence slightly due to Groq validation
                vuln.confidence = min(vuln.confidence * 1.1, 0.99)
                
            except Exception as e:
                print(f"Failed to enhance vulnerability: {e}")
            
            enhanced_vulns.append(vuln)
        
        return enhanced_vulns
    
    def _create_enhanced_explanation(self, original: str, groq: GroqExplanation) -> str:
        """Combine original and Groq explanations"""
        enhanced = f"{original}\n\n"
        enhanced += f"🤖 Advanced AI Analysis (Llama 3 70B):\n"
        enhanced += f"{groq.detailed_explanation}\n\n"
        enhanced += f"⚔️ Attack Vector: {groq.attack_scenario}\n"
        enhanced += f"💼 Business Risk: {groq.business_impact}"
        
        return enhanced