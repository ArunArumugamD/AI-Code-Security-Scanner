# test_database.py
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from datetime import datetime
from src.database.models.base import SessionLocal
from src.database.operations import VulnerabilityDB

def test_database():
    print('🗄️  Testing PostgreSQL Vulnerability Knowledge Base\n')
    
    db = SessionLocal()
    
    try:
        # Test 1: Check patterns
        from src.database.models.vulnerability import VulnerabilityPattern
        pattern_count = db.query(VulnerabilityPattern).count()
        print(f'1️⃣ Vulnerability Patterns: {pattern_count}')
        
        if pattern_count > 0:
            print('   Sample patterns:')
            for p in db.query(VulnerabilityPattern).limit(3):
                print(f'   • {p.name} ({p.severity}) - {p.cwe_id}')
        
        # Test 2: Create project
        print('\n2️⃣ Creating test project...')
        project = VulnerabilityDB.create_project(
            db, 
            name='Test Security Project',
            description='Testing database functionality',
            languages=['python', 'javascript']
        )
        print(f'   ✓ Created project: {project.name} (ID: {project.id})')
        
        # Test 3: Create scan
        print('\n3️⃣ Creating scan record...')
        scan = VulnerabilityDB.create_scan(db, project.id, scan_type='full')
        print(f'   ✓ Created scan: {scan.scan_id}')
        
        # Test 4: Record vulnerabilities
        print('\n4️⃣ Recording test vulnerabilities...')
        vulns = [
            {
                'file_path': 'app/main.py',
                'line_start': 45,
                'line_end': 47,
                'severity': 'critical',
                'confidence_score': 0.95,
                'code_snippet': 'cursor.execute(\'SELECT * FROM users WHERE id = \' + user_id)',
                'ai_explanation': 'SQL injection vulnerability detected.',
                'project_id': project.id
            },
            {
                'file_path': 'app/views.py', 
                'line_start': 123,
                'line_end': 123,
                'severity': 'high',
                'confidence_score': 0.87,
                'code_snippet': 'return \'<div>\' + request.args.get(\'name\') + \'</div>\'',
                'ai_explanation': 'XSS vulnerability. User input rendered without escaping.',
                'project_id': project.id
            }
        ]
        
        for vuln_data in vulns:
            detection = VulnerabilityDB.record_detection(db, scan.id, vuln_data)
            print(f'   ✓ Recorded: {detection.severity} vulnerability at line {detection.line_start}')
        
        # Test 5: Query statistics
        print('\n5️⃣ Querying vulnerability statistics...')
        stats = VulnerabilityDB.get_vulnerability_stats(db, project.id)
        print(f'   ✓ Total vulnerabilities: {stats["total"]}')
        print(f'   ✓ Critical: {stats["critical"]}, High: {stats["high"]}')
        print(f'   ✓ Average confidence: {stats["average_confidence"]:.2%}')
        
        print('\n✅ All database tests passed!')
        
    except Exception as e:
        print(f'\n❌ Database test failed: {e}')
        import traceback
        traceback.print_exc()
    finally:
        db.close()

if __name__ == '__main__':
    test_database()
