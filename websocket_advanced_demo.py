# websocket_advanced_demo.py
import asyncio
import websockets
import json
import random

async def stress_test():
    """Stress test with multiple concurrent clients"""
    print("🚀 WebSocket Stress Test")
    print("Creating 10 concurrent clients...")
    
    clients = []
    
    # Create multiple clients
    for i in range(10):
        client_id = f"stress-test-{i}"
        ws = await websockets.connect(f"ws://localhost:8000/ws/{client_id}")
        clients.append((client_id, ws))
        print(f"✓ Client {i+1} connected")
    
    # Send code from all clients simultaneously
    vulnerable_code = """
def process_payment(card_number, amount):
    # SQL injection vulnerability
    query = f"UPDATE accounts SET balance = balance - {amount} WHERE card = '{card_number}'"
    db.execute(query)
    
    # Command injection
    os.system(f"log_payment {card_number} {amount}")
"""
    
    tasks = []
    for client_id, ws in clients:
        message = {
            "type": "code_update",
            "code": vulnerable_code,
            "file_path": f"{client_id}.py",
            "language": "python"
        }
        task = ws.send(json.dumps(message))
        tasks.append(task)
    
    await asyncio.gather(*tasks)
    print(f"\n✓ Sent code updates from {len(clients)} clients")
    
    # Wait for responses
    await asyncio.sleep(3)
    
    # Get stats
    ws = clients[0][1]
    await ws.send(json.dumps({"type": "get_stats"}))
    
    # Clean up
    for _, ws in clients:
        await ws.close()
    
    print("\n✅ Stress test complete!")

async def incremental_scan_demo():
    """Demo incremental scanning with code changes"""
    print("\n🔄 Incremental Scanning Demo")
    
    ws = await websockets.connect("ws://localhost:8000/ws/incremental-demo")
    
    # Listen for messages
    async def listen():
        async for message in ws:
            data = json.loads(message)
            if data["type"] == "scan_completed":
                vulns = len(data.get("vulnerabilities", []))
                print(f"   Found {vulns} vulnerabilities")
    
    asyncio.create_task(listen())
    
    # Simulate typing with incremental changes
    code_versions = [
        "def transfer_money(from_account, to_account, amount):\n    pass",
        "def transfer_money(from_account, to_account, amount):\n    # Check balance\n    balance_query = ",
        "def transfer_money(from_account, to_account, amount):\n    # Check balance\n    balance_query = 'SELECT balance FROM accounts WHERE id = ' + from_account",
        "def transfer_money(from_account, to_account, amount):\n    # Check balance\n    balance_query = 'SELECT balance FROM accounts WHERE id = ?'\n    balance = db.execute(balance_query, (from_account,))"
    ]
    
    for i, code in enumerate(code_versions):
        print(f"\n📝 Sending version {i+1}...")
        await ws.send(json.dumps({
            "type": "code_update",
            "code": code,
            "file_path": "transfer.py",
            "language": "python"
        }))
        await asyncio.sleep(2)
    
    await ws.close()
    print("\n✅ Incremental scan demo complete!")

if __name__ == "__main__":
    print("🧪 Advanced WebSocket Demos\n")
    print("1. Stress Test - Multiple concurrent clients")
    print("2. Incremental Scanning - Real-time code evolution\n")
    
    choice = input("Select demo (1 or 2): ")
    
    if choice == "1":
        asyncio.run(stress_test())
    elif choice == "2":
        asyncio.run(incremental_scan_demo())
    else:
        print("Invalid choice")
