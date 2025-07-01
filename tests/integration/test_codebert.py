# test_codebert.py
import asyncio
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.ml.codebert_model import CodeBERTManager
from src.analyzers.ai_analyzer import AIEnhancedAnalyzer

async def test_codebert():
    print("🧪 Testing CodeBERT Integration\n")
    
    # Test 1: Initialize CodeBERT
    print("1️⃣ Initializing CodeBERT model...")
    try:
        codebert = CodeBERTManager()
        print("   ✓ CodeBERT initialized successfully")
    except Exception as e:
        print(f"   ❌ Failed to initialize: {e}")
        print("   Note: First run will download ~400MB model from Hugging Face")
        return
    
    # Test 2: Generate embeddings
    print("\n2️⃣ Testing embedding generation...")
    test_code = '''
def process_user_input(user_data):
    query = "SELECT * FROM users WHERE name = '" + user_data + "'"
    cursor.execute(query)
'''
    
    embedding = codebert.get_embedding(test_code, "python")
    print(f"   ✓ Generated embedding with shape: {embedding.shape}")
    print(f"   ✓ Embedding sample: [{embedding[0]:.4f}, {embedding[1]:.4f}, ...]")
    
    # Test 3: Similarity detection
    print("\n3️⃣ Testing similarity detection...")
    
    safe_code = '''
def process_user_input(user_data):
    query = "SELECT * FROM users WHERE name = ?"
    cursor.execute(query, (user_data,))
'''
    
    vulnerable_code = '''
def get_user(id):
    sql = "SELECT * FROM users WHERE id = " + id
    return db.execute(sql)
'''
    
    safe_embedding = codebert.get_embedding(safe_code, "python")
    vuln_embedding = codebert.get_embedding(vulnerable_code, "python")
    
    similarity1 = codebert.calculate_similarity(embedding, safe_embedding)
    similarity2 = codebert.calculate_similarity(embedding, vuln_embedding)
    
    print(f"   ✓ Similarity to safe code: {similarity1:.2%}")
    print(f"   ✓ Similarity to vulnerable code: {similarity2:.2%}")
    
    # Test 4: Context analysis
    print("\n4️⃣ Testing vulnerability context analysis...")
    context = codebert.analyze_vulnerability_context(
        test_code,
        "sql_injection",
        "python"
    )
    print(f"   ✓ Confidence boost: {context['confidence_boost']}")
    print(f"   ✓ Max similarity to known patterns: {context['max_similarity']:.2%}")
    print(f"   ✓ Similar to vulnerable: {context['similar_to_known_vulnerable']}")
    
    # Test 5: AI Analyzer
    print("\n5️⃣ Testing AI-Enhanced Analyzer...")
    ai_analyzer = AIEnhancedAnalyzer()
    
    if ai_analyzer.ai_ready:
        vulnerabilities = await ai_analyzer.analyze(test_code, "python", "test.py")
        print(f"   ✓ AI Analyzer found {len(vulnerabilities)} vulnerabilities")
        
        for vuln in vulnerabilities:
            print(f"     • {vuln.name} (Confidence: {vuln.confidence:.0%})")
            if vuln.ai_explanation:
                print(f"       AI: {vuln.ai_explanation[:100]}...")
    else:
        print("   ⚠ AI features not available")
    
    print("\n✅ CodeBERT integration test completed!")

if __name__ == "__main__":
    print("Note: First run will download CodeBERT model (~400MB)")
    print("This may take a few minutes...\n")
    asyncio.run(test_codebert())
