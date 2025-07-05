# test_websocket_examples.py
"""
Comprehensive test of WebSocket vulnerability detection
Shows various vulnerability types being detected in real-time
"""
import asyncio
import websockets
import json
import time

class VulnerabilityTester:
    def __init__(self):
        self.ws = None
        self.vulnerabilities_found = []
        
    async def connect(self):
        """Connect to WebSocket server"""
        self.ws = await websockets.connect("ws://localhost:8000/ws/test-examples")
        print("✅ Connected to WebSocket server\n")
        
        # Start listener
        asyncio.create_task(self.listen())
        await asyncio.sleep(0.5)
    
    async def listen(self):
        """Listen for scan results"""
        try:
            async for message in self.ws:
                data = json.loads(message)
                if data.get("type") == "scan_completed":
                    vulns = data.get("vulnerabilities", [])
                    if vulns:
                        print(f"\n🚨 Found {len(vulns)} vulnerabilities:")
                        for v in vulns:
                            print(f"   • {v['severity'].upper()}: {v['name']} at line {v['line_start']}")
                            print(f"     Fix: {v['fix_suggestion'][:60]}...")
                        self.vulnerabilities_found.extend(vulns)
                    else:
                        print("\n✅ No vulnerabilities found in this code")
        except Exception as e:
            print(f"Listener error: {e}")
    
    async def test_vulnerability(self, name: str, code: str, language: str = "python"):
        """Test a specific vulnerability"""
        print(f"\n{'='*60}")
        print(f"Testing: {name}")
        print(f"Language: {language}")
        print(f"{'='*60}")
        print("Code:")
        print("-" * 40)
        for i, line in enumerate(code.strip().split('\n'), 1):
            print(f"{i:3d} | {line}")
        print("-" * 40)
        
        # Send code
        await self.ws.send(json.dumps({
            "type": "code_update",
            "code": code,
            "file_path": f"test_{name.lower().replace(' ', '_')}.{language[:2]}",
            "language": language
        }))
        
        # Wait for scan results
        await asyncio.sleep(3)
    
    async def run_all_tests(self):
        """Run all vulnerability tests"""
        await self.connect()
        
        # Test 1: SQL Injection
        await self.test_vulnerability(
            "SQL Injection",
            """
def get_user_info(user_id):
    # Vulnerable to SQL injection
    query = "SELECT * FROM users WHERE id = " + user_id
    return db.execute(query)

def search_products(search_term):
    # Another SQL injection
    sql = f"SELECT * FROM products WHERE name LIKE '%{search_term}%'"
    return db.execute(sql)
"""
        )
        
        # Test 2: Command Injection
        await self.test_vulnerability(
            "Command Injection",
            """
import os

def ping_server(hostname):
    # Command injection vulnerability
    os.system(f"ping -c 4 {hostname}")
    
def process_file(filename):
    # Another command injection
    os.system("cat " + filename + " | grep error")
"""
        )
        
        # Test 3: XSS in JavaScript
        await self.test_vulnerability(
            "Cross-Site Scripting (XSS)",
            """
function displayUserMessage(message) {
    // XSS vulnerability - using innerHTML with user input
    document.getElementById('output').innerHTML = message;
}

function showComment(comment) {
    // Another XSS vulnerability
    var div = document.createElement('div');
    div.innerHTML = '<p>' + comment + '</p>';
    document.body.appendChild(div);
}
""",
            "javascript"
        )
        
        # Test 4: Path Traversal
        await self.test_vulnerability(
            "Path Traversal",
            """
def read_user_file(filename):
    # Path traversal vulnerability
    with open(f"/var/data/{filename}", 'r') as f:
        return f.read()

def download_report(report_name):
    # Another path traversal
    file_path = "./reports/" + report_name
    return send_file(file_path)
"""
        )
        
        # Test 5: Eval/Exec Usage
        await self.test_vulnerability(
            "Code Injection via eval/exec",
            """
def calculate_expression(expr):
    # Dangerous eval usage
    result = eval(expr)
    return result

def run_user_code(code):
    # Dangerous exec usage
    exec(code)
    return "Code executed"
"""
        )
        
        # Test 6: SAFE Code (Should find no vulnerabilities)
        await self.test_vulnerability(
            "SAFE Code Examples",
            """
def get_user_info_safe(user_id):
    # Safe parameterized query
    query = "SELECT * FROM users WHERE id = ?"
    return db.execute(query, (user_id,))

def ping_server_safe(hostname):
    # Safe subprocess usage
    import subprocess
    # Validate hostname first
    if not hostname.replace('.', '').replace('-', '').isalnum():
        raise ValueError("Invalid hostname")
    subprocess.run(['ping', '-c', '4', hostname], check=True)

def display_message_safe(message):
    # Safe - using textContent instead of innerHTML
    # element.textContent = message
    pass
"""
        )
        
        # Summary
        print(f"\n{'='*60}")
        print("📊 Test Summary")
        print(f"{'='*60}")
        print(f"Total vulnerabilities found: {len(self.vulnerabilities_found)}")
        
        # Count by severity
        severity_count = {}
        for v in self.vulnerabilities_found:
            sev = v['severity']
            severity_count[sev] = severity_count.get(sev, 0) + 1
        
        print("\nBy Severity:")
        for sev, count in sorted(severity_count.items()):
            emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵"}.get(sev, "⚪")
            print(f"  {emoji} {sev.upper()}: {count}")
        
        # Count by type
        type_count = {}
        for v in self.vulnerabilities_found:
            vtype = v['name']
            type_count[vtype] = type_count.get(vtype, 0) + 1
        
        print("\nBy Type:")
        for vtype, count in sorted(type_count.items()):
            print(f"  • {vtype}: {count}")
        
        await self.ws.close()

async def main():
    print("🔍 WebSocket Vulnerability Detection Test")
    print("This will test various vulnerability types\n")
    
    tester = VulnerabilityTester()
    await tester.run_all_tests()

if __name__ == "__main__":
    asyncio.run(main())