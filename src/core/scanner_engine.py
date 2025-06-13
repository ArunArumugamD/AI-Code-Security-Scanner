# src/core/scanner_engine.py
import asyncio
from typing import List, Dict, Optional, Set
from datetime import datetime
import hashlib
from src.core.base_scanner import ScannerEngine, Vulnerability
from src.database.models.base import SessionLocal
from src.database.operations import VulnerabilityDB
from src.analyzers.parser_analyzer import ParserBasedAnalyzer
from src.analyzers.pattern_scanner import PatternBasedScanner
from src.core.language_detector import LanguageDetector

class EnhancedScannerEngine(ScannerEngine):
    """Enhanced scanner engine with database persistence and deduplication"""
    
    def __init__(self, project_id: Optional[int] = None):
        super().__init__()
        self.project_id = project_id
        self.scan_id = None
        self.db = SessionLocal()
        self._initialize_analyzers()
    
    def _initialize_analyzers(self):
        """Initialize and register all analyzers"""
        # Register pattern-based scanner
        self.register_analyzer(PatternBasedScanner())
        
        # Register AST-based analyzer
        self.register_analyzer(ParserBasedAnalyzer())
        
        print(f"✓ Initialized {len(self.analyzers)} analyzers")
    
    async def start_scan(self, scan_type: str = 'full') -> int:
        """Start a new scan session"""
        if self.project_id:
            scan = VulnerabilityDB.create_scan(self.db, self.project_id, scan_type)
            self.scan_id = scan.id
            print(f"✓ Started scan: {scan.scan_id}")
            return scan.id
        return None
    
    async def scan_file(self, file_path: str, content: Optional[str] = None) -> List[Vulnerability]:
        """Scan a single file"""
        # Read file if content not provided
        if content is None:
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
            except Exception as e:
                print(f"Error reading {file_path}: {e}")
                return []
        
        # Detect language
        language = LanguageDetector.detect_from_file(file_path)
        if not language:
            language = LanguageDetector.detect_from_content(content)
        
        if not language or not LanguageDetector.is_supported(language):
            print(f"Unsupported language in {file_path}")
            return []
        
        print(f"🔍 Scanning {file_path} ({language})...")
        
        # Run analyzers
        vulnerabilities = await self.scan_code(content, language, file_path)
        
        # Store in database if we have a scan session
        if self.scan_id and self.project_id:
            for vuln in vulnerabilities:
                self._store_vulnerability(vuln)
        
        # Deduplicate and merge similar vulnerabilities
        vulnerabilities = self._deduplicate_vulnerabilities(vulnerabilities)
        
        return vulnerabilities
    
    def _store_vulnerability(self, vuln: Vulnerability):
        """Store vulnerability in database"""
        try:
            detection_data = {
                'file_path': vuln.file_path,
                'line_start': vuln.line_start,
                'line_end': vuln.line_end,
                'severity': vuln.severity.value,
                'confidence_score': vuln.confidence,
                'code_snippet': vuln.code_snippet[:500],  # Limit snippet size
                'ai_explanation': vuln.ai_explanation,
                'project_id': self.project_id
            }
            
            VulnerabilityDB.record_detection(self.db, self.scan_id, detection_data)
            
        except Exception as e:
            print(f"Error storing vulnerability: {e}")
    
    def _deduplicate_vulnerabilities(self, vulnerabilities: List[Vulnerability]) -> List[Vulnerability]:
        """Remove duplicate vulnerabilities and merge confidence scores"""
        unique_vulns = {}
        
        for vuln in vulnerabilities:
            # Create a unique key based on location and type
            key = (vuln.file_path, vuln.line_start, vuln.name)
            
            if key in unique_vulns:
                # Merge with existing - take highest confidence
                existing = unique_vulns[key]
                if vuln.confidence > existing.confidence:
                    unique_vulns[key] = vuln
            else:
                unique_vulns[key] = vuln
        
        return list(unique_vulns.values())
    
    async def scan_directory(self, directory: str, extensions: List[str] = None) -> Dict[str, List[Vulnerability]]:
        """Scan all files in a directory"""
        import os
        
        if extensions is None:
            extensions = ['.py', '.js', '.java', '.php', '.c', '.cpp', '.h', '.hpp']
        
        results = {}
        total_files = 0
        
        for root, _, files in os.walk(directory):
            for file in files:
                if any(file.endswith(ext) for ext in extensions):
                    file_path = os.path.join(root, file)
                    total_files += 1
                    
                    try:
                        vulns = await self.scan_file(file_path)
                        if vulns:
                            results[file_path] = vulns
                    except Exception as e:
                        print(f"Error scanning {file_path}: {e}")
        
        print(f"\n✓ Scanned {total_files} files")
        return results
    
    def get_scan_summary(self) -> Dict[str, int]:
        """Get summary of current scan"""
        if not self.project_id:
            return {}
        
        return VulnerabilityDB.get_vulnerability_stats(self.db, self.project_id)
    
    def __del__(self):
        """Cleanup database connection"""
        if hasattr(self, 'db'):
            self.db.close()

# Convenience function for quick scanning
async def quick_scan(code: str, language: str = None) -> List[Vulnerability]:
    """Quick scan without database persistence"""
    if not language:
        language = LanguageDetector.detect_from_content(code)
    
    engine = ScannerEngine()
    engine.register_analyzer(PatternBasedScanner())
    engine.register_analyzer(ParserBasedAnalyzer())
    
    return await engine.scan_code(code, language, "quick_scan.tmp")
