# src/core/language_detector.py
import os
from typing import Optional, Dict, List
from pathlib import Path

class LanguageDetector:
    """Intelligent language detection from file extension and content"""
    
    # Map extensions to languages
    EXTENSION_MAP = {
        '.py': 'python',
        '.js': 'javascript', 
        '.jsx': 'javascript',
        '.ts': 'javascript',
        '.tsx': 'javascript',
        '.java': 'java',
        '.php': 'php',
        '.c': 'c',
        '.cpp': 'cpp',
        '.cc': 'cpp',
        '.cxx': 'cpp',
        '.h': 'c',
        '.hpp': 'cpp',
        '.hxx': 'cpp'
    }
    
    # Language signatures for content-based detection
    SIGNATURES = {
        'python': ['def ', 'import ', 'from ', 'class ', '__init__'],
        'javascript': ['function', 'const ', 'let ', 'var ', '=>', 'require('],
        'java': ['public class', 'private ', 'protected ', 'package ', 'import java'],
        'php': ['<?php', 'namespace ', 'use ', 'function ', '$'],
        'c': ['#include <', 'int main(', 'void ', 'struct ', 'typedef'],
        'cpp': ['#include <', 'using namespace', 'class ', 'template<', '::']
    }
    
    @classmethod
    def detect_from_file(cls, file_path: str) -> Optional[str]:
        """Detect language from file path and content"""
        path = Path(file_path)
        
        # First try extension
        ext = path.suffix.lower()
        if ext in cls.EXTENSION_MAP:
            return cls.EXTENSION_MAP[ext]
        
        # Then try content analysis
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read(1000)  # Read first 1KB
                return cls.detect_from_content(content)
        except:
            return None
    
    @classmethod
    def detect_from_content(cls, content: str) -> Optional[str]:
        """Detect language from code content"""
        content_lower = content.lower()
        scores = {}
        
        for lang, signatures in cls.SIGNATURES.items():
            score = sum(1 for sig in signatures if sig.lower() in content_lower)
            if score > 0:
                scores[lang] = score
        
        if scores:
            return max(scores, key=scores.get)
        return None
    
    @classmethod
    def is_supported(cls, language: str) -> bool:
        """Check if language is supported"""
        return language in ['python', 'javascript', 'java', 'php', 'c', 'cpp']
