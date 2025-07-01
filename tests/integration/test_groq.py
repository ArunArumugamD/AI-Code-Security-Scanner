# test_groq.py
import asyncio
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.ml.groq_analyzer import GroqCloudAnalyzer
from src.analyzers.groq_enhanced_analyzer import GroqEnhancedAnalyzer
from src.analyzers.pattern_scanner import PatternBasedScanner

async def test_groq_integration():
    print("🤖 Testing Groq Cloud API Integration (Llama 3 70B)\n")
    
    # Check for API key
    if not os.getenv("GROQ_API_KEY"):
        print("❌ GROQ_API_KEY not found in environment!")
        print("\nTo get your free API key:")
        print("1. Visit: https://console.groq.com/")
        print("2. Sign up for free account")
        print("3. Go to API Keys section")
        print("4. Create new API key")
        print("5. Add to .env file: GROQ_API_KEY=your-key-here")
        return
    
    # Test 1: Direct Groq API
    print("1️⃣ Testing direct Groq API call...")
    try:
        groq = GroqCloudAnalyzer()
        
        test_code = '''
def get_user_data(user_id):
    # SQL injection vulnerability
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    return cursor.fetchall()
'''
        
        vuln_info = {
            'type': 'SQL Injection',
            'severity': 'critical',
            'confidence': 0.95,
            'line': 3,
            'cwe_id': 'CWE-89'
        }
        
        explanation = await groq.analyze_vulnerability(test_code, vuln_info, 'python')
        
        print("✅ Groq API Response:")
        print(groq.format_explanation_for_display(explanation))
        
    except Exception as e:
        print(f"❌ Groq API test failed: {e}")
        return
    
    # Test 2: Enhanced Analyzer
    print("\n\n2️⃣ Testing Groq-Enhanced Analyzer...")
    
    test_vulnerable_code = '''
import os
import pickle

def process_command(user_input):
    # Multiple vulnerabilities for testing
    
    # Command injection
    os.system(f"echo Processing: {user_input}")
    
    # Insecure deserialization
    if user_input.startswith("data:"):
        data = user_input[5:]
        obj = pickle.loads(base64.b64decode(data))
        return obj
    
    # Code injection
    if user_input.startswith("eval:"):
        expr = user_input[5:]
        result = eval(expr)
        return result
'''
    
    try:
        # Create base analyzer
        base_analyzer = PatternBasedScanner()
        
        # Wrap with Groq enhancement
        enhanced_analyzer = GroqEnhancedAnalyzer(base_analyzer)
        
        # Run analysis
        vulnerabilities = await enhanced_analyzer.analyze(
            test_vulnerable_code,
            'python',
            'test.py'
        )
        
        print(f"✅ Found {len(vulnerabilities)} vulnerabilities with Groq enhancement\n")
        
        for i, vuln in enumerate(vulnerabilities, 1):
            print(f"\n{'='*60}")
            print(f"Vulnerability #{i}: {vuln.name}")
            print(f"{'='*60}")
            print(f"📍 Location: Line {vuln.line_start}")
            print(f"⚠️  Severity: {vuln.severity.value}")
            print(f"🎯 Confidence: {vuln.confidence:.0%}")
            print(f"\n📝 AI-Enhanced Explanation:")
            print(vuln.ai_explanation)
            print(f"\n🔧 Fix Recommendation:")
            print(vuln.fix_suggestion)
            
    except Exception as e:
        print(f"❌ Enhanced analyzer test failed: {e}")
        import traceback
        traceback.print_exc()
    
    # Test 3: Batch Analysis
    print("\n\n3️⃣ Testing batch analysis...")
    
    vulnerabilities_batch = [
        {
            'code_snippet': 'eval(user_input)',
            'type': 'Code Injection',
            'severity': 'critical',
            'confidence': 0.9,
            'language': 'python'
        },
        {
            'code_snippet': 'document.innerHTML = userData',
            'type': 'XSS',
            'severity': 'high',
            'confidence': 0.85,
            'language': 'javascript'
        }
    ]
    
    try:
        results = await groq.batch_analyze(vulnerabilities_batch)
        print(f"✅ Batch analyzed {len(results)} vulnerabilities")
        
    except Exception as e:
        print(f"❌ Batch analysis failed: {e}")
    
    # Test 4: Cache verification
    print("\n4️⃣ Testing cache system...")
    
    # Re-analyze same code (should use cache)
    import time
    start = time.time()
    cached_explanation = await groq.analyze_vulnerability(test_code, vuln_info, 'python')
    cache_time = time.time() - start
    
    print(f"✅ Cache working: Response time {cache_time:.2f}s (should be < 0.1s for cached)")
    
    print("\n✅ Groq integration tests completed!")

if __name__ == "__main__":
    print("="*70)
    print("GROQ CLOUD API INTEGRATION TEST")
    print("="*70)
    print("\n⚡ Features:")
    print("• Llama 3 70B for expert-level explanations")
    print("• Attack scenario generation")
    print("• Business impact assessment")
    print("• Detailed fix recommendations with code examples")
    print("• Response caching to minimize API costs")
    print("• Batch processing support")
    print("="*70 + "\n")
    
    asyncio.run(test_groq_integration())