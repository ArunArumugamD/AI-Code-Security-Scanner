# src/core/scanner_engine_no_groq.py
"""Scanner engine without Groq for distributed scanning"""
from src.core.scanner_engine import EnhancedScannerEngine
from src.analyzers.pattern_scanner import PatternBasedScanner
from src.analyzers.parser_analyzer import ParserBasedAnalyzer

class BasicScannerEngine(EnhancedScannerEngine):
    """Scanner without Groq enhancement for distributed workers"""
    
    def _initialize_analyzers(self):
        """Initialize only base analyzers (no Groq)"""
        self.register_analyzer(PatternBasedScanner())
        self.register_analyzer(ParserBasedAnalyzer())
        print(f"✓ Initialized {len(self.analyzers)} basic analyzers (Groq disabled for distributed)")