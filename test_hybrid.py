# test_hybrid.py
import asyncio
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.ml.hybrid_model import HybridAnalysisEngine
from src.analyzers.hybrid_analyzer import HybridAIAnalyzer

async def test_hybrid_model():
    print("🚀 Testing Hybrid AI Model (GNN + CodeBERT)\n")
    
    # Test code with multiple vulnerabilities
    test_code = '''
import os
import pickle
from flask import request, render_template_string

def search_users(search_term):
    # SQL Injection vulnerability
    query = f"SELECT * FROM users WHERE name LIKE '%{search_term}%'"
    results = db.execute(query)
    
    # XSS vulnerability
    template = '<h1>Search Results</h1><div>' + search_term + '</div>'
    
    # Command injection
    if validate_input(search_term):
        os.system(f"grep {search_term} /var/log/access.log")
    
    return render_template_string(template, results=results)

def load_session(session_data):
    # Insecure deserialization
    return pickle.loads(session_data)
'''
    
    # Test 1: Hybrid Engine Direct Test
    print("1️⃣ Testing Hybrid Analysis Engine...")
    try:
        engine = HybridAnalysisEngine()
        
        # Analyze the code
        prediction = engine.analyze(test_code, "python")
        
        print(f"   ✓ Vulnerability Score: {prediction.vulnerability_score:.1%}")
        print(f"   ✓ Type Detected: {prediction.vulnerability_type}")
        print(f"   ✓ Confidence: {prediction.confidence:.1%}")
        print(f"\n   📊 Component Scores:")
        print(f"      • GNN (Structure): {prediction.gnn_score:.1%}")
        print(f"      • CodeBERT (Semantics): {prediction.codebert_score:.1%}")
        print(f"\n   🔍 Features:")
        for feature, value in prediction.combined_features.items():
            print(f"      • {feature}: {value:.3f}")
        
        print(f"\n   📝 AI Explanation:")
        for line in prediction.explanation.split('\n'):
            if line.strip():
                print(f"      {line}")
                
    except Exception as e:
        print(f"   ❌ Engine test failed: {e}")
        import traceback
        traceback.print_exc()
    
    # Test 2: Hybrid Analyzer Integration
    print("\n\n2️⃣ Testing Hybrid Analyzer Integration...")
    try:
        analyzer = HybridAIAnalyzer()
        
        if analyzer.enabled:
            vulnerabilities = await analyzer.analyze(test_code, "python", "test_hybrid.py")
            
            print(f"   ✓ Found {len(vulnerabilities)} vulnerabilities\n")
            
            for vuln in vulnerabilities:
                print(f"   🚨 {vuln.name}")
                print(f"      Severity: {vuln.severity.value}")
                print(f"      Confidence: {vuln.confidence:.1%}")
                print(f"      Location: Lines {vuln.line_start}-{vuln.line_end}")
                print(f"      CWE: {vuln.cwe_id}")
                
                if hasattr(vuln, 'ai_metadata'):
                    print(f"      AI Scores: GNN={vuln.ai_metadata['gnn_score']:.1%}, "
                          f"CodeBERT={vuln.ai_metadata['codebert_score']:.1%}")
                
                print(f"      Fix: {vuln.fix_suggestion[:80]}...")
                print()
        else:
            print("   ⚠ Hybrid analyzer not enabled")
            
    except Exception as e:
        print(f"   ❌ Analyzer test failed: {e}")
        import traceback
        traceback.print_exc()
    
    # Test 3: Comparison with Individual Models
    print("\n3️⃣ Comparing Hybrid vs Individual Models...")
    
    simple_code = '''
def get_user(user_id):
    query = "SELECT * FROM users WHERE id = " + user_id
    return db.execute(query)
'''
    
    try:
        # Test with simpler code
        prediction = engine.analyze(simple_code, "python")
        
        print(f"   Simple SQL Injection Test:")
        print(f"   • Hybrid Score: {prediction.vulnerability_score:.1%}")
        print(f"   • GNN Only: {prediction.gnn_score:.1%}")
        print(f"   • CodeBERT Only: {prediction.codebert_score:.1%}")
        
        improvement = prediction.vulnerability_score - max(prediction.gnn_score, prediction.codebert_score)
        if improvement > 0:
            print(f"   ✨ Hybrid model improved detection by {improvement:.1%}!")
        
    except Exception as e:
        print(f"   ❌ Comparison failed: {e}")
    
    print("\n✅ Hybrid model testing completed!")

if __name__ == "__main__":
    print("=" * 60)
    print("HYBRID AI MODEL TEST - Combining GNN + CodeBERT")
    print("=" * 60)
    print("\nThis combines:")
    print("• Graph Neural Networks (structural analysis)")
    print("• CodeBERT (semantic understanding)")
    print("• Feature fusion for maximum accuracy")
    print("=" * 60 + "\n")
    
    asyncio.run(test_hybrid_model())
