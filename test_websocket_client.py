# test_websocket_client.py
"""
Test client for WebSocket real-time scanning
Simulates an IDE sending code updates
"""
import asyncio
import websockets
import json
import time
from datetime import datetime

class WebSocketTestClient:
    def __init__(self, url="ws://localhost:8000/ws"):
        self.url = url
        self.websocket = None
        
    async def connect(self):
        """Connect to WebSocket server"""
        print(f"🔌 Connecting to {self.url}...")
        self.websocket = await websockets.connect(self.url)
        
        # Start listener task
        asyncio.create_task(self.listen())
        
        # Wait for connection message
        await asyncio.sleep(0.5)
    
    async def listen(self):
        """Listen for messages from server"""
        try:
            async for message in self.websocket:
                data = json.loads(message)
                await self.handle_message(data)
        except Exception as e:
            print(f"❌ Listener error: {e}")
    
    async def handle_message(self, data):
        """Handle incoming message"""
        msg_type = data.get("type")
        
        if msg_type == "connection":
            print(f"✅ Connected! Client ID: {data.get('client_id')}")
            print(f"   Features: {', '.join(data.get('features', []))}")
            
        elif msg_type == "scan_started":
            print(f"🔍 Scanning {data.get('file_path')}...")
            
        elif msg_type == "scan_completed":
            vulns = data.get("vulnerabilities", [])
            summary = data.get("summary", {})
            scan_time = data.get("scan_time", 0)
            
            print(f"\n📊 Scan Results (took {scan_time:.2f}s):")
            print(f"   Total: {summary.get('total', 0)} vulnerabilities")
            
            if vulns:
                print("\n   Vulnerabilities found:")
                for vuln in vulns:
                    severity_emoji = {
                        "critical": "🔴",
                        "high": "🟠",
                        "medium": "🟡",
                        "low": "🔵"
                    }.get(vuln['severity'], "⚪")
                    
                    print(f"\n   {severity_emoji} {vuln['name']} (Line {vuln['line_start']})")
                    print(f"      Severity: {vuln['severity']}")
                    print(f"      Confidence: {vuln['confidence']:.0%}")
                    print(f"      Fix: {vuln['fix_suggestion'][:80]}...")
            else:
                print("   ✅ No vulnerabilities found!")
                
        elif msg_type == "notification":
            print(f"\n📢 Notification: {data.get('message', 'No message')}")
            
        else:
            print(f"📨 {msg_type}: {json.dumps(data, indent=2)}")
    
    async def send_code_update(self, code, file_path="test.py", language="python"):
        """Send code update to server"""
        message = {
            "type": "code_update",
            "code": code,
            "file_path": file_path,
            "language": language
        }
        await self.websocket.send(json.dumps(message))
        print(f"\n📤 Sent code update ({len(code)} chars)")
    
    async def simulate_typing(self):
        """Simulate developer typing code with vulnerabilities"""
        print("\n🎯 Simulating developer typing code...\n")
        
        # Progressive code snippets (simulating typing)
        code_stages = [
            # Stage 1: Basic function
            """def get_user(user_id):
    pass""",
            
            # Stage 2: Add database query (vulnerable)
            """def get_user(user_id):
    query = "SELECT * FROM users WHERE id = " """,
            
            # Stage 3: Complete vulnerable query
            """def get_user(user_id):
    query = "SELECT * FROM users WHERE id = " + user_id
    return db.execute(query)""",
            
            # Stage 4: Add another function
            """def get_user(user_id):
    query = "SELECT * FROM users WHERE id = " + user_id
    return db.execute(query)

def process_command(cmd):
    os.system(cmd)""",
            
            # Stage 5: Fix one vulnerability
            """def get_user(user_id):
    query = "SELECT * FROM users WHERE id = ?"
    return db.execute(query, (user_id,))

def process_command(cmd):
    os.system(cmd)"""
        ]
        
        for i, code in enumerate(code_stages):
            print(f"\n⌨️  Typing stage {i+1}/{len(code_stages)}...")
            await self.send_code_update(code)
            
            # Wait to simulate typing delay
            await asyncio.sleep(2)
        
        print("\n✅ Typing simulation complete!")
    
    async def test_features(self):
        """Test various WebSocket features"""
        print("\n🧪 Testing WebSocket features...")
        
        # Test 1: Ping/Pong
        print("\n1️⃣ Testing ping/pong...")
        await self.websocket.send(json.dumps({"type": "ping"}))
        await asyncio.sleep(0.5)
        
        # Test 2: Set language
        print("\n2️⃣ Setting language to JavaScript...")
        await self.websocket.send(json.dumps({
            "type": "set_language",
            "language": "javascript"
        }))
        await asyncio.sleep(0.5)
        
        # Test 3: JavaScript code
        print("\n3️⃣ Sending JavaScript code...")
        js_code = """
function processUser(userData) {
    document.getElementById('output').innerHTML = userData;
    eval(userData.command);
}
"""
        await self.send_code_update(js_code, "app.js", "javascript")
        await asyncio.sleep(2)
        
        # Test 4: Get stats
        print("\n4️⃣ Getting server statistics...")
        await self.websocket.send(json.dumps({"type": "get_stats"}))
        await asyncio.sleep(0.5)
    
    async def run_demo(self):
        """Run full demo"""
        try:
            await self.connect()
            await self.simulate_typing()
            await self.test_features()
            
            print("\n🎉 Demo complete! Press Ctrl+C to exit.")
            
            # Keep connection alive
            while True:
                await asyncio.sleep(1)
                
        except KeyboardInterrupt:
            print("\n👋 Closing connection...")
        finally:
            if self.websocket:
                await self.websocket.close()

async def main():
    """Run the test client"""
    print("🚀 WebSocket Test Client")
    print("=" * 50)
    print("This client simulates an IDE sending code updates")
    print("and receiving real-time vulnerability alerts.")
    print("=" * 50)
    
    client = WebSocketTestClient()
    await client.run_demo()

if __name__ == "__main__":
    asyncio.run(main())