# scan.py
import asyncio
import sys
import os
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))


from src.core.scanner_engine_groq import GroqEnhancedScannerEngine as EnhancedScannerEngine
from src.analyzers.groq_enhanced_analyzer import GroqEnhancedAnalyzer
from src.database.models.base import SessionLocal
from src.database.operations import VulnerabilityDB
from src.core.base_scanner import Severity

async def main():
    print("🛡️  AISec Scanner - Advanced Code Security Analysis\n")
    
    if len(sys.argv) < 2:
        print("Usage: python scan.py <file_or_directory> [project_name]")
        sys.exit(1)
    
    target = sys.argv[1]
    project_name = sys.argv[2] if len(sys.argv) > 2 else "CLI Scan Project"
    
    # Create or get project
    db = SessionLocal()
    try:
        # Try to get existing project
        from src.database.models.vulnerability import Project
        project = db.query(Project).filter(Project.name == project_name).first()
        
        if not project:
            project = VulnerabilityDB.create_project(
                db, 
                name=project_name,
                description=f"Scanning {target}"
            )
            print(f"✓ Created project: {project.name}")
        else:
            print(f"✓ Using existing project: {project.name}")
        
        # Initialize scanner
        scanner = EnhancedScannerEngine(project_id=project.id)
        await scanner.start_scan()
        
        # Scan target
        if os.path.isfile(target):
            print(f"\n📄 Scanning file: {target}")
            vulnerabilities = await scanner.scan_file(target)
            display_results({target: vulnerabilities})
        
        elif os.path.isdir(target):
            print(f"\n📁 Scanning directory: {target}")
            results = await scanner.scan_directory(target)
            display_results(results)
        
        else:
            print(f"❌ Error: {target} not found")
            sys.exit(1)
        
        # Show summary
        print("\n📊 Scan Summary:")
        summary = scanner.get_scan_summary()
        print(f"   Total: {summary.get('total', 0)}")
        print(f"   Critical: {summary.get('critical', 0)}")
        print(f"   High: {summary.get('high', 0)}")
        print(f"   Medium: {summary.get('medium', 0)}")
        print(f"   Low: {summary.get('low', 0)}")
        
    finally:
        db.close()

def display_results(results: dict):
    """Display scan results"""
    if not results:
        print("\n✅ No vulnerabilities found!")
        return
    
    total_vulns = sum(len(vulns) for vulns in results.values())
    print(f"\n⚠️  Found {total_vulns} vulnerabilities:\n")
    
    for file_path, vulnerabilities in results.items():
        print(f"📄 {file_path}:")
        
        # Sort by severity and line number
        sorted_vulns = sorted(vulnerabilities, 
                            key=lambda v: (severity_order(v.severity), v.line_start))
        
        for vuln in sorted_vulns:
            severity_icon = get_severity_icon(vuln.severity)
            print(f"   {severity_icon} Line {vuln.line_start}: {vuln.name}")
            print(f"      Severity: {vuln.severity.value} | Confidence: {vuln.confidence:.0%}")
            print(f"      Code: {vuln.code_snippet[:60]}...")
            if vuln.cwe_id:
                print(f"      CWE: {vuln.cwe_id}")
            # Fixed: Extract the newline split outside the f-string
            fix_lines = vuln.fix_suggestion.split('\n')
            fix_first_line = fix_lines[0][:80] if fix_lines else ""
            print(f"      Fix: {fix_first_line}...")
            print()

def severity_order(severity: Severity) -> int:
    """Get numeric order for severity"""
    order = {
        Severity.CRITICAL: 0,
        Severity.HIGH: 1,
        Severity.MEDIUM: 2,
        Severity.LOW: 3,
        Severity.INFO: 4
    }
    return order.get(severity, 5)

def get_severity_icon(severity: Severity) -> str:
    """Get icon for severity level"""
    icons = {
        Severity.CRITICAL: "🔴",
        Severity.HIGH: "🟠",
        Severity.MEDIUM: "🟡",
        Severity.LOW: "🔵",
        Severity.INFO: "⚪"
    }
    return icons.get(severity, "❓")

if __name__ == "__main__":
    asyncio.run(main())
