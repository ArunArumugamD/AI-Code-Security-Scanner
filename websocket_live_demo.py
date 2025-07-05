# websocket_live_demo.py
"""
Live demonstration of real-time vulnerability detection
Simulates a developer typing code character by character
"""
import asyncio
import websockets
import json
import sys
import time

class LiveCodingDemo:
    def __init__(self):
        self.ws = None
        self.current_vulns = []
        
    async def connect(self):
        self.ws = await websockets.connect("ws://localhost:8000/ws/live-demo")
        asyncio.create_task(self.listen())
        await asyncio.sleep(0.5)
        
    async def listen(self):
        """Listen for scan results and display them"""
        try:
            async for message in self.ws:
                data = json.loads(message)
                if data.get("type") == "scan_completed":
                    self.current_vulns = data.get("vulnerabilities", [])
                    self.display_results()
        except:
            pass
    
    def display_results(self):
        """Display current vulnerabilities"""
        # Clear previous output (Windows)
        print("\033[10;0H\033[J", end="")  # Move cursor and clear
        
        print("\n" + "="*60)
        if self.current_vulns:
            print(f"🚨 VULNERABILITIES DETECTED: {len(self.current_vulns)}")
            for v in self.current_vulns:
                severity_icon = {
                    "critical": "🔴",
                    "high": "🟠", 
                    "medium": "🟡",
                    "low": "🔵"
                }.get(v['severity'], "⚪")
                print(f"\n{severity_icon} {v['name']} (Line {v['line_start']})")
                print(f"   {v['description'][:60]}...")
        else:
            print("✅ No vulnerabilities detected")
        print("="*60)
    
    async def type_code(self, code: str, delay: float = 0.1):
        """Simulate typing code character by character"""
        current = ""
        
        for char in code:
            current += char
            
            # Clear screen and show current code
            print("\033[2J\033[H")  # Clear screen, move to top
            print("🔴 LIVE CODING DEMO - Watch vulnerabilities appear in real-time!")
            print("="*60)
            print("📝 Code Editor:")
            print("-"*60)
            
            # Display code with line numbers
            lines = current.split('\n')
            for i, line in enumerate(lines, 1):
                print(f"{i:3d} | {line}")
            
            # Send update
            await self.ws.send(json.dumps({
                "type": "code_update",
                "code": current,
                "file_path": "demo.py",
                "language": "python"
            }))
            
            # Display current vulnerabilities
            self.display_results()
            
            # Typing delay
            await asyncio.sleep(delay)
    
    async def demo_scenario(self):
        """Run a demo scenario"""
        await self.connect()
        
        print("🎬 Starting Live Coding Demo...")
        print("Watch as vulnerabilities are detected while typing!\n")
        await asyncio.sleep(2)
        
        # Scenario 1: SQL Injection appears as we type
        code1 = """def authenticate_user(username, password):
    # Building SQL query
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    return db.execute(query)
"""
        
        print("\n📌 Scenario 1: SQL Injection Detection")
        await asyncio.sleep(2)
        await self.type_code(code1, delay=0.05)
        await asyncio.sleep(3)
        
        # Scenario 2: Fix the vulnerability
        code2 = """def authenticate_user(username, password):
    # Building SQL query - FIXED with parameterized query
    query = "SELECT * FROM users WHERE username = ?"
    return db.execute(query, (username,))
"""
        
        print("\n📌 Scenario 2: Fixing the vulnerability...")
        await asyncio.sleep(2)
        await self.type_code(code2, delay=0.05)
        await asyncio.sleep(3)
        
        # Scenario 3: Multiple vulnerabilities
        code3 = """import os

def process_user_input(user_input, filename):
    # Multiple vulnerabilities will appear
    os.system("echo " + user_input)
    
    eval(user_input)
    
    with open("/data/" + filename) as f:
        return f.read()
"""
        
        print("\n📌 Scenario 3: Multiple vulnerabilities...")
        await asyncio.sleep(2)
        await self.type_code(code3, delay=0.05)
        await asyncio.sleep(3)
        
        print("\n✅ Demo complete!")
        print("\nKey observations:")
        print("• Vulnerabilities detected in real-time as you type")
        print("• No need to click 'scan' - it's automatic")
        print("• Fixes are validated immediately")
        print("• Multiple vulnerability types detected")
        
        await self.ws.close()

async def main():
    demo = LiveCodingDemo()
    await demo.demo_scenario()

if __name__ == "__main__":
    print("="*60)
    print("WEBSOCKET REAL-TIME VULNERABILITY DETECTION DEMO")
    print("="*60)
    print("\nThis demo simulates typing code and shows how")
    print("vulnerabilities are detected instantly!\n")
    
    asyncio.run(main())