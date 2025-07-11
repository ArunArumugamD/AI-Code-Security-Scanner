# src/api/websocket/live_scanner.py
"""
Live scanning module - scans code as user types
Debounced to avoid excessive API calls
"""
import asyncio
from typing import Dict, Set, Optional
from datetime import datetime
import difflib
import hashlib

from src.core.scanner_engine import quick_scan
from src.api.websocket.connection_manager import manager

class LiveScanManager:
    """Manages live scanning sessions with incremental updates"""
    
    def __init__(self):
        # Cache previous scan results by file
        self.scan_cache: Dict[str, Dict] = {}
        # Track scanning tasks
        self.scan_tasks: Dict[str, asyncio.Task] = {}
        # Scan delay for debouncing
        self.scan_delay = 0.3  # 300ms - faster response
        
    async def handle_live_code(self, client_id: str, file_path: str, 
                              code: str, language: str):
        """Handle live code updates with smart diffing"""
        
        # Cancel existing scan task if any
        task_key = f"{client_id}:{file_path}"
        if task_key in self.scan_tasks:
            self.scan_tasks[task_key].cancel()
        
        # Schedule new scan
        task = asyncio.create_task(
            self._perform_incremental_scan(client_id, file_path, code, language)
        )
        self.scan_tasks[task_key] = task
    
    async def _perform_incremental_scan(self, client_id: str, file_path: str,
                                      code: str, language: str):
        """Perform incremental scan with caching"""
        try:
            # Wait for debounce delay
            await asyncio.sleep(self.scan_delay)
            
            # Get code hash
            code_hash = hashlib.md5(code.encode()).hexdigest()
            
            # Check cache
            cache_key = f"{client_id}:{file_path}"
            cached = self.scan_cache.get(cache_key, {})
            
            # If code hasn't changed, return cached results
            if cached.get('hash') == code_hash:
                await self._send_cached_results(client_id, cached)
                return
            
            # Get previous code for diff
            old_code = cached.get('code', '')
            
            # Calculate diff
            diff_lines = self._calculate_diff(old_code, code)
            
            # Notify scan started
            await manager.send_personal_message({
                "type": "scan_started",
                "file_path": file_path,
                "incremental": len(old_code) > 0,
                "changed_lines": len(diff_lines)
            }, client_id)
            
            # Perform scan
            start_time = datetime.utcnow()
            vulnerabilities = await quick_scan(code, language)
            scan_time = (datetime.utcnow() - start_time).total_seconds()
            
            # Filter vulnerabilities to only changed areas (if incremental)
            if diff_lines and len(old_code) > 0:
                vulnerabilities = self._filter_vulnerabilities_by_diff(
                    vulnerabilities, diff_lines
                )
            
            # Update cache
            self.scan_cache[cache_key] = {
                'hash': code_hash,
                'code': code,
                'vulnerabilities': vulnerabilities,
                'scan_time': scan_time,
                'timestamp': datetime.utcnow()
            }
            
            # Send results
            await self._send_scan_results(client_id, file_path, 
                                        vulnerabilities, scan_time, 
                                        incremental=len(old_code) > 0)
            
        except asyncio.CancelledError:
            # Task was cancelled, ignore
            pass
        except Exception as e:
            await manager.send_personal_message({
                "type": "scan_error",
                "error": str(e),
                "file_path": file_path
            }, client_id)
    
    def _calculate_diff(self, old_code: str, new_code: str) -> Set[int]:
        """Calculate which lines changed"""
        old_lines = old_code.split('\n')
        new_lines = new_code.split('\n')
        
        differ = difflib.unified_diff(old_lines, new_lines, lineterm='')
        changed_lines = set()
        
        line_num = 0
        for line in differ:
            if line.startswith('@@'):
                # Parse line numbers from diff header
                import re
                match = re.search(r'\+(\d+)', line)
                if match:
                    line_num = int(match.group(1))
            elif line.startswith('+') and not line.startswith('+++'):
                changed_lines.add(line_num)
                line_num += 1
            elif not line.startswith('-'):
                line_num += 1
        
        return changed_lines
    
    def _filter_vulnerabilities_by_diff(self, vulnerabilities, changed_lines):
        """Only keep vulnerabilities in changed lines"""
        filtered = []
        
        for vuln in vulnerabilities:
            # Check if vulnerability overlaps with changed lines
            vuln_lines = set(range(vuln.line_start, vuln.line_end + 1))
            if vuln_lines.intersection(changed_lines):
                filtered.append(vuln)
        
        return filtered
    
    async def _send_scan_results(self, client_id: str, file_path: str,
                                vulnerabilities, scan_time: float,
                                incremental: bool = False):
        """Send scan results to client"""
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
                "code_snippet": vuln.code_snippet[:100],
                "fix_suggestion": vuln.fix_suggestion,
                "ai_explanation": vuln.ai_explanation[:200] if vuln.ai_explanation else None
            })
        
        await manager.send_personal_message({
            "type": "scan_completed",
            "file_path": file_path,
            "scan_time": scan_time,
            "incremental": incremental,
            "vulnerabilities": vuln_data,
            "summary": {
                "total": len(vulnerabilities),
                "critical": sum(1 for v in vulnerabilities if v.severity.value == "critical"),
                "high": sum(1 for v in vulnerabilities if v.severity.value == "high"),
                "medium": sum(1 for v in vulnerabilities if v.severity.value == "medium"),
                "low": sum(1 for v in vulnerabilities if v.severity.value == "low")
            }
        }, client_id)
    
    async def _send_cached_results(self, client_id: str, cached: Dict):
        """Send cached results"""
        await manager.send_personal_message({
            "type": "scan_completed",
            "cached": True,
            "vulnerabilities": [v.__dict__ for v in cached['vulnerabilities']],
            "scan_time": 0.001  # Almost instant
        }, client_id)

# Global live scanner instance
live_scanner = LiveScanManager()

# Update connection_manager.py to use live scanner
async def enhanced_handle_code_update(self, client_id: str, data: dict):
    """Enhanced code update handler with live scanning"""
    code = data.get("code", "")
    file_path = data.get("file_path", "untitled")
    language = data.get("language", "python")
    
    # Use live scanner instead of basic scanning
    from src.api.websocket.live_scanner import live_scanner
    await live_scanner.handle_live_code(client_id, file_path, code, language)