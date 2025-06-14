# test_confidence.py
import asyncio
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.core.confidence_scorer import ConfidenceScorer
from src.core.enhanced_scanner import EnhancedVulnerabilityScanner

async def test_confidence_scoring():
    print("🎯 Testing Confidence Scoring System\n")
    
    # Test vulnerable code with varying confidence levels
    test_cases = [
        {
            "name": "Clear SQL Injection",
            "code": '''
def get_user(user_id):
    # Obvious SQL injection - direct concatenation
    query = "SELECT * FROM users WHERE id = " + user_id
    return db.execute(query)
''',
            "language": "python",
            "expected_confidence": "high"
        },
        {
            "name": "Possible SQL Injection in Test File",
            "code": '''
def test_sql_query():
    # This is in a test file
    test_id = "1 OR 1=1"
    query = "SELECT * FROM users WHERE id = " + test_id
    assert_raises(SQLError, db.execute, query)
''',
            "language": "python",
            "file_path": "tests/test_database.py",
            "expected_confidence": "low"
        },
        {
            "name": "Validated Input",
            "code": '''
def get_user_safe(user_id):
    # Input is validated first
    if not user_id.isdigit():
        raise ValueError("Invalid user ID")
    
    # Still concatenating but after validation
    query = "SELECT * FROM users WHERE id = " + user_id
    return db.execute(query)
''',
            "language": "python",
            "expected_confidence": "medium"
        }
    ]
    
    # Test 1: Basic Confidence Scoring
    print("1️⃣ Testing confidence scorer directly...")
    scorer = ConfidenceScorer()
    
    test_detections = [
        ("pattern", 0.9),
        ("ast", 0.85),
        ("codebert", 0.92),
        ("gnn", 0.78)
    ]
    
    confidence = scorer.calculate_confidence(
        vulnerability_type="SQL Injection",
        detection_methods=test_detections,
        code_context={"has_user_input": True, "lines_of_code": 5},
        file_path="app.py"
    )
    
    print(f"   ✓ Overall Confidence: {confidence.overall_confidence:.1%}")
    print(f"   ✓ Reliability: {confidence.reliability_rating}")
    print("   ✓ Factor Breakdown:")
    for factor, score in confidence.factors.items():
        print(f"     • {factor}: {score:.1%}")
    
    # Test 2: Enhanced Scanner with Confidence
    print("\n2️⃣ Testing enhanced scanner with confidence scoring...")
    
    scanner = EnhancedVulnerabilityScanner()
    
    for test_case in test_cases:
        print(f"\n   Testing: {test_case['name']}")
        
        results = await scanner.scan_with_confidence(
            test_case["code"],
            test_case["language"],
            test_case.get("file_path", "test.py")
        )
        
        if results:
            for result in results:
                vuln = result["vulnerability"]
                conf = result["confidence_analysis"]
                
                print(f"   ✓ Found: {vuln.name}")
                print(f"     • Confidence: {conf.overall_confidence:.1%} ({conf.reliability_rating})")
                print(f"     • Expected: {test_case['expected_confidence']} confidence")
                
                # Verify confidence aligns with expectations
                if test_case['expected_confidence'] == 'high' and conf.overall_confidence > 0.7:
                    print("     ✅ Confidence level matches expectation")
                elif test_case['expected_confidence'] == 'low' and conf.overall_confidence < 0.5:
                    print("     ✅ Confidence level matches expectation")
                elif test_case['expected_confidence'] == 'medium' and 0.4 < conf.overall_confidence < 0.7:
                    print("     ✅ Confidence level matches expectation")
                else:
                    print("     ⚠️  Confidence level doesn't match expectation")
        else:
            print("   ℹ️  No vulnerabilities detected")
    
    # Test 3: Generate Confidence Report
    print("\n3️⃣ Generating confidence report...")
    
    all_results = []
    for test_case in test_cases[:1]:  # Just use first case for report
        results = await scanner.scan_with_confidence(
            test_case["code"],
            test_case["language"],
            "report_test.py"
        )
        all_results.extend(results)
    
    if all_results:
        report = scanner.generate_confidence_report(all_results)
        print("\n" + report)
    
    # Test 4: Historical Learning
    print("\n4️⃣ Testing historical learning...")
    
    # Simulate user feedback
    scorer.update_feedback("SQL Injection", was_correct=True)
    scorer.update_feedback("SQL Injection", was_correct=True)
    scorer.update_feedback("SQL Injection", was_correct=False)  # One false positive
    
    accuracy_report = scorer.get_confidence_report()
    print(f"   ✓ Historical Accuracy Report:")
    print(f"     • Total Feedbacks: {accuracy_report['total_feedbacks']}")
    
    if accuracy_report['historical_accuracy']:
        for vuln_type, data in accuracy_report['historical_accuracy'].items():
            print(f"     • {vuln_type}: {data['accuracy']:.1%} accurate ({data['samples']} samples)")
    
    print("\n✅ Confidence scoring test completed!")

if __name__ == "__main__":
    print("=" * 60)
    print("CONFIDENCE SCORING SYSTEM TEST")
    print("=" * 60)
    print("\nThis system provides:")
    print("• Multi-factor confidence calculation")
    print("• Context-aware scoring")
    print("• Historical accuracy tracking")
    print("• Cross-validation between detection methods")
    print("• Detailed explanations")
    print("=" * 60 + "\n")
    
    asyncio.run(test_confidence_scoring())
