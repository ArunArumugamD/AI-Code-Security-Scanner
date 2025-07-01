# src/core/scanner_engine_groq.py
import asyncio
from typing import List, Dict, Optional
from src.core.scanner_engine import EnhancedScannerEngine
from src.analyzers.groq_enhanced_analyzer import GroqEnhancedAnalyzer
from src.analyzers.pattern_scanner import PatternBasedScanner
from src.analyzers.parser_analyzer import ParserBasedAnalyzer
from src.analyzers.ai_analyzer import AIEnhancedAnalyzer
from src.analyzers.gnn_analyzer import GNNStructuralAnalyzer
from src.analyzers.hybrid_analyzer import HybridAIAnalyzer

class GroqEnhancedScannerEngine(EnhancedScannerEngine):
    """Scanner engine with Groq AI enhancement for all analyzers"""
    
    def _initialize_analyzers(self):
        """Initialize all analyzers with Groq enhancement"""
        
        # Base analyzers
        pattern_scanner = PatternBasedScanner()
        parser_analyzer = ParserBasedAnalyzer()
        
        # Wrap base analyzers with Groq enhancement
        self.register_analyzer(GroqEnhancedAnalyzer(pattern_scanner))
        self.register_analyzer(GroqEnhancedAnalyzer(parser_analyzer))
        
        # AI analyzers (already have good explanations, but can still enhance)
        try:
            ai_analyzer = AIEnhancedAnalyzer()
            if ai_analyzer.ai_ready:
                self.register_analyzer(GroqEnhancedAnalyzer(ai_analyzer))
        except:
            pass
        
        try:
            gnn_analyzer = GNNStructuralAnalyzer()
            if gnn_analyzer.enabled:
                self.register_analyzer(GroqEnhancedAnalyzer(gnn_analyzer))
        except:
            pass
        
        try:
            hybrid_analyzer = HybridAIAnalyzer()
            if hybrid_analyzer.enabled:
                self.register_analyzer(GroqEnhancedAnalyzer(hybrid_analyzer))
        except:
            pass
        
        print(f"✓ Initialized {len(self.analyzers)} Groq-enhanced analyzers")
    
    async def scan_code(self, code: str, language: str, file_path: str) -> List:
        """Enhanced scan with Groq explanations"""
        vulnerabilities = await super().scan_code(code, language, file_path)
        
        # Log Groq enhancement stats
        groq_enhanced = sum(1 for v in vulnerabilities if "Llama 3 70B" in v.ai_explanation)
        if groq_enhanced > 0:
            print(f"🤖 Groq enhanced {groq_enhanced}/{len(vulnerabilities)} vulnerabilities")
        
        return vulnerabilities


# Update main scanner to use Groq-enhanced version
async def groq_quick_scan(code: str, language: str = None) -> List:
    """Quick scan with Groq AI enhancement"""
    from src.core.language_detector import LanguageDetector
    
    if not language:
        language = LanguageDetector.detect_from_content(code)
    
    engine = GroqEnhancedScannerEngine()
    return await engine.scan_code(code, language, "quick_scan.tmp")