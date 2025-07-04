# tests/integration/test_self_learning.py
"""Test the self-learning module"""
import asyncio
import sys
import os
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, project_root)


from src.ml.self_learning import SelfLearningEngine, LearningEnabledScanner
from src.core.base_scanner import Vulnerability, Severity
from src.analyzers.pattern_scanner import PatternBasedScanner
import json

async def test_self_learning():
    print("🧠 Testing Self-Learning Module\n")
    
    # Test 1: Initialize Learning Engine
    print("1️⃣ Testing learning engine initialization...")
    engine = SelfLearningEngine()
    
    initial_metrics = engine.export_learning_report()
    print(f"   ✓ Learning engine initialized")
    print(f"   ✓ Existing feedback records: {initial_metrics.total_feedback}")
    print(f"   ✓ Patterns learned: {initial_metrics.patterns_learned}")
    
    # Test 2: Record feedback
    print("\n2️⃣ Testing feedback recording...")
    
    # Create test vulnerabilities
    test_vulns = [
        Vulnerability(
            id="TEST-SQL-001",
            name="SQL Injection",
            description="Test SQL injection",
            severity=Severity.CRITICAL,
            confidence=0.9,
            file_path="test.py",
            line_start=10,
            line_end=10,
            code_snippet='query = "SELECT * FROM users WHERE id = " + user_id'
        ),
        Vulnerability(
            id="TEST-XSS-001",
            name="XSS",
            description="Test XSS",
            severity=Severity.HIGH,
            confidence=0.85,
            file_path="test.js",
            line_start=20,
            line_end=20,
            code_snippet='element.innerHTML = userInput'
        ),
        Vulnerability(
            id="TEST-FALSE-001",
            name="SQL Injection",
            description="False positive",
            severity=Severity.HIGH,
            confidence=0.8,
            file_path="test_db.py",
            line_start=30,
            line_end=30,
            code_snippet='# Test code: query = "SELECT * FROM test WHERE id = " + test_id'
        )
    ]
    
    # Record feedback
    print("   Recording feedback for test vulnerabilities:")
    
    # True positive SQL injection
    record1 = engine.record_feedback(
        test_vulns[0],
        was_correct=True,
        user_notes="Confirmed SQL injection vulnerability",
        detection_method="pattern"
    )
    print(f"   ✓ Recorded: SQL Injection - TRUE POSITIVE")
    
    # True positive XSS
    record2 = engine.record_feedback(
        test_vulns[1],
        was_correct=True,
        user_notes="Confirmed XSS vulnerability",
        detection_method="pattern"
    )
    print(f"   ✓ Recorded: XSS - TRUE POSITIVE")
    
    # False positive
    record3 = engine.record_feedback(
        test_vulns[2],
        was_correct=False,
        user_notes="This is in test code, not a real vulnerability",
        detection_method="pattern"
    )
    print(f"   ✓ Recorded: SQL Injection - FALSE POSITIVE")
    
    # Test 3: Check confidence adjustments
    print("\n3️⃣ Testing confidence adjustments...")
    
    # Test with new vulnerability similar to confirmed one
    new_vuln = Vulnerability(
        id="TEST-SQL-002",
        name="SQL Injection",
        description="Similar SQL injection",
        severity=Severity.CRITICAL,
        confidence=0.7,  # Lower initial confidence
        file_path="app.py",
        line_start=50,
        line_end=50,
        code_snippet='db.execute("SELECT * FROM products WHERE id = " + product_id)'
    )
    
    adjusted_confidence = engine.adjust_confidence(new_vuln, ["pattern"])
    print(f"   ✓ Original confidence: {new_vuln.confidence:.2%}")
    print(f"   ✓ Adjusted confidence: {adjusted_confidence:.2%}")
    
    if adjusted_confidence > new_vuln.confidence:
        print(f"   ✓ Confidence boosted due to similarity with confirmed patterns!")
    
    # Test with false positive pattern
    fp_vuln = Vulnerability(
        id="TEST-SQL-003",
        name="SQL Injection",
        description="Similar to false positive",
        severity=Severity.HIGH,
        confidence=0.8,
        file_path="test_queries.py",
        line_start=60,
        line_end=60,
        code_snippet='# Testing: query = "SELECT * FROM mock WHERE id = " + mock_id'
    )
    
    fp_adjusted = engine.adjust_confidence(fp_vuln, ["pattern"])
    print(f"\n   ✓ False positive pattern test:")
    print(f"   ✓ Original confidence: {fp_vuln.confidence:.2%}")
    print(f"   ✓ Adjusted confidence: {fp_adjusted:.2%}")
    
    if fp_adjusted < fp_vuln.confidence:
        print(f"   ✓ Confidence reduced due to similarity with false positive patterns!")
    
    # Test 4: Pattern suggestions
    print("\n4️⃣ Testing pattern suggestions...")
    
    # Add more feedback to trigger pattern learning
    for i in range(3):
        similar_vuln = Vulnerability(
            id=f"TEST-SQL-{i+10}",
            name="SQL Injection",
            description="Another SQL injection",
            severity=Severity.CRITICAL,
            confidence=0.95,
            file_path=f"file{i}.py",
            line_start=100+i,
            line_end=100+i,
            code_snippet=f'cursor.execute("SELECT * FROM table{i} WHERE x = " + input{i})'
        )
        engine.record_feedback(similar_vuln, True, "Confirmed", "pattern")
    
    suggestions = engine.suggest_new_patterns()
    print(f"   ✓ Generated {len(suggestions)} pattern suggestions")
    
    for i, suggestion in enumerate(suggestions[:3]):
        print(f"\n   Pattern {i+1}:")
        print(f"   • Type: {suggestion['type']}")
        print(f"   • Confirmations: {suggestion['confirmations']}")
        print(f"   • Confidence boost: {suggestion['confidence']}")
        print(f"   • Example: {suggestion['pattern'][:50]}...")
    
    # Test 5: Learning metrics
    print("\n5️⃣ Testing learning metrics...")
    
    metrics = engine.export_learning_report()
    print(f"   ✓ Total feedback: {metrics.total_feedback}")
    print(f"   ✓ True positives: {metrics.true_positives}")
    print(f"   ✓ False positives: {metrics.false_positives}")
    
    if metrics.total_feedback > 0:
        accuracy = metrics.true_positives / metrics.total_feedback
        print(f"   ✓ Current accuracy: {accuracy:.1%}")
    
    print(f"   ✓ Patterns learned: {metrics.patterns_learned}")
    
    if metrics.confidence_adjustments:
        print(f"\n   Confidence adjustments by type:")
        for vuln_type, adjustment in metrics.confidence_adjustments.items():
            print(f"   • {vuln_type}: {adjustment:.2f}x")
    
    # Test 6: Integration with scanner
    print("\n6️⃣ Testing scanner integration...")
    
    base_scanner = PatternBasedScanner()
    learning_scanner = LearningEnabledScanner(base_scanner)
    
    test_code = '''
def get_user_data(user_id):
    # Dangerous SQL query
    query = "SELECT * FROM users WHERE id = " + str(user_id)
    return db.execute(query)
    
def safe_query(user_id):
    # Safe parameterized query
    query = "SELECT * FROM users WHERE id = ?"
    return db.execute(query, (user_id,))
'''
    
    # Scan with learning
    vulnerabilities = await learning_scanner.scan_with_learning(
        test_code,
        "python",
        "test_integration.py"
    )
    
    print(f"   ✓ Found {len(vulnerabilities)} vulnerabilities with learning adjustments")
    
    for vuln in vulnerabilities:
        if hasattr(vuln, 'learning_metadata'):
            meta = vuln.learning_metadata
            print(f"\n   • {vuln.name} at line {vuln.line_start}")
            print(f"     Original confidence: {meta['original_confidence']:.2%}")
            print(f"     Adjusted confidence: {vuln.confidence:.2%}")
            print(f"     Reason: {meta['adjustment_reason']}")
    
    # Test 7: Persistence
    print("\n7️⃣ Testing persistence...")
    
    # Create new engine instance to test loading
    new_engine = SelfLearningEngine()
    new_metrics = new_engine.export_learning_report()
    
    print(f"   ✓ Loaded {new_metrics.total_feedback} feedback records from disk")
    print(f"   ✓ Loaded {new_metrics.patterns_learned} learned patterns")
    
    if new_metrics.total_feedback == metrics.total_feedback:
        print(f"   ✅ Persistence working correctly!")
    
    print("\n✅ Self-learning module test completed!")
    
    # Display learning progress visualization
    print("\n📊 Learning Progress Visualization:")
    print("=" * 50)
    
    if metrics.total_feedback >= 10:
        # Simple ASCII chart of accuracy over time
        print("Accuracy Trend:")
        
        # Group feedback by batches of 5
        batch_size = 5
        batches = []
        
        for i in range(0, len(engine.feedback_records), batch_size):
            batch = engine.feedback_records[i:i+batch_size]
            if batch:
                correct = sum(1 for r in batch if r.was_correct)
                accuracy = correct / len(batch)
                batches.append(accuracy)
        
        # Display chart
        for i, acc in enumerate(batches):
            bar_length = int(acc * 40)
            bar = "█" * bar_length + "░" * (40 - bar_length)
            print(f"Batch {i+1}: [{bar}] {acc:.0%}")
    
    print("=" * 50)

if __name__ == "__main__":
    print("=" * 60)
    print("SELF-LEARNING MODULE TEST")
    print("=" * 60)
    print("\n🧠 This module makes the scanner smarter over time by:")
    print("• Learning from user feedback (true/false positives)")
    print("• Adjusting confidence scores based on patterns")
    print("• Suggesting new detection patterns")
    print("• Reducing false positives automatically")
    print("• Improving accuracy with each scan")
    print("=" * 60 + "\n")
    
    asyncio.run(test_self_learning())