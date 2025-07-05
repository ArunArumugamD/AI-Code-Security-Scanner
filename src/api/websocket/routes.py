# src/api/websocket/routes.py
"""
WebSocket routes for real-time scanning
"""
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Depends
from typing import Optional
import json
import uuid
import logging
from datetime import datetime

from src.api.websocket.connection_manager import manager
from src.database.models.base import get_db, SessionLocal

logger = logging.getLogger(__name__)

router = APIRouter()

@router.websocket("/ws/{client_id}")
async def websocket_endpoint(
    websocket: WebSocket,
    client_id: Optional[str] = None
):
    """
    WebSocket endpoint for real-time code scanning
    
    Protocol:
    - Client connects with optional client_id
    - Client sends code updates
    - Server performs incremental scanning
    - Server sends back vulnerabilities in real-time
    """
    # Generate client ID if not provided
    if not client_id:
        client_id = f"client-{uuid.uuid4().hex[:8]}"
    
    # Accept connection
    client = await manager.connect(websocket, client_id)
    
    try:
        # Message processing loop
        while True:
            # Receive message
            data = await websocket.receive_text()
            
            try:
                # Parse JSON message
                message = json.loads(data)
                
                # Handle message
                await manager.handle_message(client_id, message)
                
            except json.JSONDecodeError:
                await manager.send_personal_message({
                    "type": "error",
                    "message": "Invalid JSON format"
                }, client_id)
                
            except Exception as e:
                logger.error(f"Error handling message: {e}")
                await manager.send_personal_message({
                    "type": "error",
                    "message": f"Error processing message: {str(e)}"
                }, client_id)
                
    except WebSocketDisconnect:
        await manager.disconnect(client_id)
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
        await manager.disconnect(client_id)

@router.websocket("/ws")
async def websocket_endpoint_auto_id(websocket: WebSocket):
    """WebSocket endpoint with auto-generated client ID"""
    await websocket_endpoint(websocket, None)


# Additional WebSocket utilities
@router.get("/api/websocket/status")
async def get_websocket_status():
    """Get WebSocket server status"""
    return {
        "status": "active",
        "stats": manager.get_stats(),
        "timestamp": datetime.utcnow().isoformat()
    }

@router.post("/api/websocket/broadcast")
async def broadcast_message(message: dict):
    """Broadcast a message to all connected clients (admin only)"""
    await manager.broadcast_notification(message)
    return {
        "success": True,
        "clients_notified": len(manager.active_connections)
    }


# Update main.py to include WebSocket routes
def register_websocket_routes(app):
    """Register WebSocket routes with the main app"""
    app.include_router(router)