# test_parser.py
import asyncio
from src.core.code_parser import UniversalCodeParser
from src.core.language_detector import LanguageDetector
from src.analyzers.parser_analyzer import ParserBasedAnalyzer
from src.core.base_scanner import ScannerEngine
import os

async def test_parser():
    print("🔍 Testing Multi-Language Parser System\n")
    
    # Test 1: Language Detection
    print("1️⃣ Testing Language Detection:")
    test_files = [
        "tests/samples/vulnerable.py",
        "tests/samples/vulnerable.js", 
        "tests/samples/Vulnerable.java"
    ]
    
    for file_path in test_files:
        if os.path.exists(file_path):
            lang = LanguageDetector.detect_from_file(file_path)
            print(f"   ✓ {file_path}: Detected as {lang}")
    
    # Test 2: AST Parsing
    print("\n2️⃣ Testing AST Parsing:")
    parser = UniversalCodeParser()
    
    with open("tests/samples/vulnerable.py", 'r') as f:
        py_code = f.read()
    
    ast = parser.parse(py_code, 'python')
    print(f"   ✓ Python AST nodes: {count_nodes(ast)}")
    
    # Test 3: Function Extraction
    print("\n3️⃣ Testing Function Extraction:")
    functions = parser.extract_functions(py_code, 'python')
    for func in functions:
        print(f"   ✓ Found: {func.name}() - Complexity: {func.complexity}")
    
    # Test 4: Security Pattern Detection
    print("\n4️⃣ Testing Security Pattern Detection:")
    patterns = parser.find_security_patterns(py_code, 'python')
    for pattern in patterns:
        print(f"   ⚠️  Line {pattern['line']}: {pattern['pattern']} - {pattern['risk']}")
    
    # Test 5: Full Analysis
    print("\n5️⃣ Testing Full Security Analysis:")
    engine = ScannerEngine()
    analyzer = ParserBasedAnalyzer()
    engine.register_analyzer(analyzer)
    
    vulnerabilities = await engine.scan_code(py_code, 'python', 'test.py')
    print(f"   ✓ Found {len(vulnerabilities)} vulnerabilities")
    
    for vuln in vulnerabilities[:3]:  # Show first 3
        print(f"   🔴 {vuln.severity.value.upper()}: {vuln.name} (Line {vuln.line_start})")
        print(f"      Confidence: {vuln.confidence*100:.0f}%")
        print(f"      Fix: {vuln.fix_suggestion}\n")

def count_nodes(node):
    if not node:
        return 0
    return 1 + sum(count_nodes(child) for child in node.children)

if __name__ == "__main__":
    asyncio.run(test_parser())
