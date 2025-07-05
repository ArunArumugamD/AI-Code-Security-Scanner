# websocket_monitor.py
import asyncio
import websockets
import json
import time
from datetime import datetime

async def monitor_performance():
    """Monitor WebSocket server performance"""
    ws = await websockets.connect("ws://localhost:8000/ws/monitor")
    
    print("📊 WebSocket Performance Monitor")
    print("=" * 50)
    
    while True:
        # Get stats
        await ws.send(json.dumps({"type": "get_stats"}))
        
        # Wait for response
        response = await ws.recv()
        data = json.loads(response)
        
        if data.get("type") == "stats":
            stats = data.get("data", {})
            
            # Clear screen (Windows)
            import os
            os.system('cls' if os.name == 'nt' else 'clear')
            
            print("📊 WebSocket Performance Monitor")
            print("=" * 50)
            print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            print(f"\nConnections:")
            print(f"  Active: {stats.get('active_connections', 0)}")
            print(f"  Total: {stats.get('total_connections', 0)}")
            print(f"\nActivity:")
            print(f"  Messages sent: {stats.get('messages_sent', 0)}")
            print(f"  Scans performed: {stats.get('scans_performed', 0)}")
            print(f"  Active sessions: {stats.get('active_sessions', 0)}")
            
            clients = stats.get('clients', [])
            if clients:
                print(f"\nConnected Clients:")
                for client in clients:
                    print(f"  • {client['id']} - {client.get('active_file', 'No file')}")
        
        # Update every 2 seconds
        await asyncio.sleep(2)

if __name__ == "__main__":
    asyncio.run(monitor_performance())
