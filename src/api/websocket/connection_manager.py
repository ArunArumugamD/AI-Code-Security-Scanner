# src/api/websocket/connection_manager.py
"""
WebSocket connection manager for real-time scanning
Handles multiple concurrent connections and broadcasts updates
"""
from typing import Dict, List, Set, Optional, Any
from dataclasses import dataclass, asdict
from datetime import datetime
import json
import asyncio
from fastapi import WebSocket, WebSocketDisconnect
import logging

logger = logging.getLogger(__name__)

@dataclass
class Client:
    """Represents a connected WebSocket client"""
    id: str
    websocket: WebSocket
    project_id: Optional[int] = None
    active_file: Optional[str] = None
    language: Optional[str] = None
    connected_at: datetime = None
    
    def __post_init__(self):
        if self.connected_at is None:
            self.connected_at = datetime.utcnow()

@dataclass
class ScanSession:
    """Represents an active scanning session"""
    session_id: str
    client_id: str
    file_path: str
    language: str
    last_scan: datetime
    pending_scan: bool = False
    scan_task: Optional[asyncio.Task] = None

class ConnectionManager:
    """Manages WebSocket connections and scanning sessions"""
    
    def __init__(self):
        # Active connections
        self.active_connections: Dict[str, Client] = {}
        
        # Scanning sessions
        self.scan_sessions: Dict[str, ScanSession] = {}
        
        # Message queues for each client
        self.message_queues: Dict[str, asyncio.Queue] = {}
        
        # Scan throttling (to avoid scanning on every keystroke)
        self.scan_delay = 0.5  # seconds
        
        # Statistics
        self.stats = {
            "total_connections": 0,
            "messages_sent": 0,
            "scans_performed": 0
        }
        
        logger.info("WebSocket ConnectionManager initialized")
    
    async def connect(self, websocket: WebSocket, client_id: str) -> Client:
        """Accept a new WebSocket connection"""
        await websocket.accept()
        
        # Create client
        client = Client(
            id=client_id,
            websocket=websocket
        )
        
        # Store connection
        self.active_connections[client_id] = client
        self.message_queues[client_id] = asyncio.Queue()
        
        # Update stats
        self.stats["total_connections"] += 1
        
        # Send welcome message
        await self.send_personal_message({
            "type": "connection",
            "status": "connected",
            "client_id": client_id,
            "message": "Connected to AISec Scanner WebSocket",
            "features": [
                "real-time scanning",
                "incremental analysis",
                "live vulnerability alerts",
                "ai-powered suggestions"
            ]
        }, client_id)
        
        logger.info(f"Client {client_id} connected. Total active: {len(self.active_connections)}")
        
        # Broadcast connection event
        await self.broadcast({
            "type": "client_connected",
            "client_id": client_id,
            "total_clients": len(self.active_connections)
        }, exclude=client_id)
        
        return client
    
    async def disconnect(self, client_id: str):
        """Handle client disconnection"""
        if client_id not in self.active_connections:
            return
            
        # Cancel any pending scans
        await self.cancel_client_scans(client_id)
        
        # Remove client
        del self.active_connections[client_id]
        
        # Clean up message queue
        if client_id in self.message_queues:
            del self.message_queues[client_id]
        
        # Clean up scan sessions
        sessions_to_remove = [
            sid for sid, session in self.scan_sessions.items()
            if session.client_id == client_id
        ]
        for sid in sessions_to_remove:
            del self.scan_sessions[sid]
        
        logger.info(f"Client {client_id} disconnected. Active connections: {len(self.active_connections)}")
        
        # Only broadcast if there are other clients
        if len(self.active_connections) > 0:
            await self.broadcast({
                "type": "client_disconnected",
                "client_id": client_id,
                "total_clients": len(self.active_connections)
            })
    
    async def send_personal_message(self, message: dict, client_id: str):
        """Send message to specific client"""
        if client_id in self.active_connections:
            client = self.active_connections[client_id]
            try:
                await client.websocket.send_json(message)
                self.stats["messages_sent"] += 1
            except Exception as e:
                logger.error(f"Error sending message to {client_id}: {e}")
                await self.disconnect(client_id)
    
    async def broadcast(self, message: dict, exclude: Optional[str] = None):
        """Broadcast message to all connected clients"""
        disconnected_clients = []
        
        # Create a copy of the connections to avoid iteration issues
        clients_copy = list(self.active_connections.items())
        
        for client_id, client in clients_copy:
            if client_id != exclude:
                try:
                    await client.websocket.send_json(message)
                    self.stats["messages_sent"] += 1
                except Exception as e:
                    logger.error(f"Error broadcasting to {client_id}: {e}")
                    disconnected_clients.append(client_id)
        
        # Clean up disconnected clients
        for client_id in disconnected_clients:
            await self.disconnect(client_id)
    
    async def handle_code_update(self, client_id: str, data: dict):
        """Handle code update from client (with throttling)"""
        code = data.get("code", "")
        file_path = data.get("file_path", "untitled")
        language = data.get("language", "python")
        
        # Create session key
        session_key = f"{client_id}:{file_path}"
        
        # Cancel existing scan task if any
        if session_key in self.scan_sessions:
            session = self.scan_sessions[session_key]
            if session.scan_task and not session.scan_task.done():
                session.scan_task.cancel()
        
        # Create or update session
        session = ScanSession(
            session_id=session_key,
            client_id=client_id,
            file_path=file_path,
            language=language,
            last_scan=datetime.utcnow(),
            pending_scan=True
        )
        
        # Schedule scan with delay (debouncing)
        scan_task = asyncio.create_task(
            self._delayed_scan(session, code, self.scan_delay)
        )
        session.scan_task = scan_task
        
        self.scan_sessions[session_key] = session
        
        # Send acknowledgment
        await self.send_personal_message({
            "type": "code_update_received",
            "status": "scanning_scheduled",
            "file_path": file_path,
            "code_length": len(code)
        }, client_id)
    
    async def _delayed_scan(self, session: ScanSession, code: str, delay: float):
        """Perform scan after delay (for debouncing)"""
        try:
            # Wait for delay (will be cancelled if new update comes)
            await asyncio.sleep(delay)
            
            # Perform scan
            await self.perform_scan(session, code)
            
        except asyncio.CancelledError:
            # Scan was cancelled (new update arrived)
            logger.debug(f"Scan cancelled for {session.file_path}")
    
    async def perform_scan(self, session: ScanSession, code: str):
        """Perform actual vulnerability scan"""
        from src.core.scanner_engine import quick_scan
        
        start_time = datetime.utcnow()
        client_id = session.client_id
        
        try:
            # Send scan started message
            await self.send_personal_message({
                "type": "scan_started",
                "file_path": session.file_path,
                "timestamp": start_time.isoformat()
            }, client_id)
            
            # Perform scan
            vulnerabilities = await quick_scan(code, session.language)
            
            # Calculate scan time
            scan_time = (datetime.utcnow() - start_time).total_seconds()
            
            # Prepare vulnerability data
            vuln_data = []
            for vuln in vulnerabilities:
                vuln_data.append({
                    "id": vuln.id,
                    "name": vuln.name,
                    "description": vuln.description,
                    "severity": vuln.severity.value,
                    "confidence": vuln.confidence,
                    "line_start": vuln.line_start,
                    "line_end": vuln.line_end,
                    "code_snippet": vuln.code_snippet[:100],  # Limit size
                    "fix_suggestion": vuln.fix_suggestion,
                    "ai_explanation": vuln.ai_explanation[:200] if vuln.ai_explanation else None
                })
            
            # Send results
            await self.send_personal_message({
                "type": "scan_completed",
                "file_path": session.file_path,
                "scan_time": scan_time,
                "vulnerabilities": vuln_data,
                "summary": {
                    "total": len(vulnerabilities),
                    "critical": sum(1 for v in vulnerabilities if v.severity.value == "critical"),
                    "high": sum(1 for v in vulnerabilities if v.severity.value == "high"),
                    "medium": sum(1 for v in vulnerabilities if v.severity.value == "medium"),
                    "low": sum(1 for v in vulnerabilities if v.severity.value == "low")
                }
            }, client_id)
            
            # Update stats
            self.stats["scans_performed"] += 1
            
            # Update session
            session.pending_scan = False
            
        except Exception as e:
            logger.error(f"Error during scan: {e}")
            await self.send_personal_message({
                "type": "scan_error",
                "error": str(e),
                "file_path": session.file_path
            }, client_id)
    
    async def cancel_client_scans(self, client_id: str):
        """Cancel all pending scans for a client"""
        for session_key, session in list(self.scan_sessions.items()):
            if session.client_id == client_id:
                if session.scan_task and not session.scan_task.done():
                    session.scan_task.cancel()
    
    async def handle_message(self, client_id: str, message: dict):
        """Handle incoming WebSocket message"""
        msg_type = message.get("type")
        
        if msg_type == "code_update":
            await self.handle_code_update(client_id, message)
            
        elif msg_type == "set_project":
            project_id = message.get("project_id")
            if client_id in self.active_connections:
                self.active_connections[client_id].project_id = project_id
                await self.send_personal_message({
                    "type": "project_set",
                    "project_id": project_id
                }, client_id)
                
        elif msg_type == "set_language":
            language = message.get("language")
            if client_id in self.active_connections:
                self.active_connections[client_id].language = language
                await self.send_personal_message({
                    "type": "language_set",
                    "language": language
                }, client_id)
                
        elif msg_type == "ping":
            await self.send_personal_message({
                "type": "pong",
                "timestamp": datetime.utcnow().isoformat()
            }, client_id)
            
        elif msg_type == "get_stats":
            await self.send_personal_message({
                "type": "stats",
                "data": self.get_stats()
            }, client_id)
            
        else:
            logger.warning(f"Unknown message type: {msg_type}")
    
    def get_stats(self) -> dict:
        """Get connection manager statistics"""
        return {
            **self.stats,
            "active_connections": len(self.active_connections),
            "active_sessions": len(self.scan_sessions),
            "clients": [
                {
                    "id": client.id,
                    "connected_at": client.connected_at.isoformat(),
                    "active_file": client.active_file,
                    "language": client.language
                }
                for client in self.active_connections.values()
            ]
        }
    
    async def broadcast_notification(self, notification: dict):
        """Broadcast a notification to all clients"""
        message = {
            "type": "notification",
            "timestamp": datetime.utcnow().isoformat(),
            **notification
        }
        await self.broadcast(message)


# Global connection manager instance
manager = ConnectionManager()