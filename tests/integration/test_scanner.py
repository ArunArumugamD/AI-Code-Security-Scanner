# test_scanner.py
import asyncio
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.core.scanner_engine import EnhancedScannerEngine, quick_scan

async def test_scanner():
    print("🧪 Testing Scanner Engine\n")
    
    # Test 1: Quick scan without database
    print("1️⃣ Testing quick scan (no database):")
    
    vulnerable_code = '''
import os
import pickle

def unsafe_command(user_input):
    # This should trigger command injection detection
    os.system(f"echo {user_input}")
    
def unsafe_sql(user_id):
    # This should trigger SQL injection detection
    query = "SELECT * FROM users WHERE id = " + user_id
    cursor.execute(query)

def unsafe_pickle(data):
    # This should trigger deserialization detection
    return pickle.loads(data)
'''
    
    results = await quick_scan(vulnerable_code, 'python')
    print(f"   ✓ Found {len(results)} vulnerabilities in quick scan")
    for vuln in results:
        print(f"     • {vuln.name} at line {vuln.line_start} ({vuln.confidence:.0%} confidence)")
    
    # Test 2: Test pattern scanner with JavaScript
    print("\n2️⃣ Testing JavaScript scanning:")
    
    js_code = '''
function processUser(userData) {
    // XSS vulnerability
    document.getElementById('output').innerHTML = userData;
    
    // Code injection
    eval(userData.expression);
    
    // Another XSS
    document.write('<div>' + userData.name + '</div>');
}
'''
    
    results = await quick_scan(js_code, 'javascript')
    print(f"   ✓ Found {len(results)} vulnerabilities in JavaScript")
    for vuln in results:
        print(f"     • {vuln.name} at line {vuln.line_start}")
    
    # Test 3: Test with sample files
    print("\n3️⃣ Testing file scanning:")
    
    if os.path.exists("tests/samples/vulnerable.py"):
        from src.database.models.base import SessionLocal
        from src.database.models.vulnerability import Project
        
        db = SessionLocal()
        project = db.query(Project).first()
        db.close()
        
        if project:
            scanner = EnhancedScannerEngine(project_id=project.id)
            await scanner.start_scan('test')
            
            results = await scanner.scan_file("tests/samples/vulnerable.py")
            print(f"   ✓ Found {len(results)} vulnerabilities in vulnerable.py")
            
            summary = scanner.get_scan_summary()
            print(f"   ✓ Database updated: {summary.get('total', 0)} total vulnerabilities")
    
    print("\n✅ Scanner engine tests completed!")

if __name__ == "__main__":
    asyncio.run(test_scanner())
