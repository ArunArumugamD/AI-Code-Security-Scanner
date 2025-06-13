# test_setup.py
from src.core.base_scanner import ScannerEngine, Vulnerability, Severity
import asyncio

async def test_setup():
    engine = ScannerEngine()
    print('✓ Scanner engine initialized')
    
    vuln = Vulnerability(
        id='TEST-001',
        name='Test Vulnerability',
        description='Setup verification',
        severity=Severity.INFO,
        confidence=1.0,
        file_path='test.py',
        line_start=1,
        line_end=1,
        code_snippet='# test'
    )
    print(f'✓ Vulnerability object created: {vuln.id}')
    print('✓ All systems operational!')

asyncio.run(test_setup())
