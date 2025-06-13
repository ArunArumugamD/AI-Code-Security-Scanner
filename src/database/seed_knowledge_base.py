# src/database/seed_knowledge_base.py
from src.database.models.base import SessionLocal, init_db
from src.database.models.vulnerability import VulnerabilityPattern
import json

# OWASP Top 10 and CWE Top 25 patterns
VULNERABILITY_PATTERNS = [
    {
        "pattern_id": "SQL-001",
        "name": "SQL Injection",
        "description": "User input directly concatenated into SQL queries without parameterization",
        "severity": "critical",
        "cwe_id": "CWE-89",
        "owasp_category": "A03:2021",
        "languages": ["python", "javascript", "java", "php"],
        "detection_patterns": {
            "python": ["execute\\(.*\\+.*\\)", "execute\\(.*%.*\\)", "execute\\(.*format\\("],
            "javascript": ["query\\(.*\\+.*\\)", "raw\\(.*\\$\\{"],
            "java": ["createQuery\\(.*\\+.*\\)", "executeQuery\\(.*\\+.*\\)"],
            "php": ["mysql_query\\(.*\\..*\\$", "mysqli_query\\(.*\\..*\\$"]
        },
        "fix_guidance": "Use parameterized queries or prepared statements. Never concatenate user input into SQL.",
        "secure_alternatives": {
            "python": "cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))",
            "javascript": "db.query('SELECT * FROM users WHERE id = ?', [userId])",
            "java": "PreparedStatement ps = conn.prepareStatement('SELECT * FROM users WHERE id = ?')"
        }
    },
    {
        "pattern_id": "XSS-001", 
        "name": "Cross-Site Scripting (XSS)",
        "description": "User input rendered in HTML without proper escaping",
        "severity": "high",
        "cwe_id": "CWE-79",
        "owasp_category": "A03:2021",
        "languages": ["javascript", "php", "python"],
        "detection_patterns": {
            "javascript": ["innerHTML.*=", "document\\.write\\(", "dangerouslySetInnerHTML"],
            "php": ["echo.*\\", "echo.*\\", "print.*\\"],
            "python": ["render_template_string\\(.*request\\.", "Markup\\(.*request\\."]
        },
        "fix_guidance": "Always escape user input before rendering. Use textContent instead of innerHTML.",
        "secure_alternatives": {
            "javascript": "element.textContent = userInput;",
            "php": "echo htmlspecialchars(['input'], ENT_QUOTES, 'UTF-8');",
            "python": "{{ user_input | e }} in Jinja2 templates"
        }
    },
    {
        "pattern_id": "CMD-001",
        "name": "Command Injection", 
        "description": "System commands executed with user-controlled input",
        "severity": "critical",
        "cwe_id": "CWE-78",
        "owasp_category": "A03:2021",
        "languages": ["python", "javascript", "java", "php", "c"],
        "detection_patterns": {
            "python": ["os\\.system\\(", "subprocess\\.call\\(.*shell=True", "eval\\(", "exec\\("],
            "javascript": ["exec\\(", "execSync\\(", "spawn\\(.*shell.*true"],
            "java": ["Runtime\\.getRuntime\\(\\)\\.exec\\(", "ProcessBuilder\\("],
            "php": ["system\\(", "exec\\(", "shell_exec\\(", "passthru\\("],
            "c": ["system\\(", "popen\\("]
        },
        "fix_guidance": "Avoid system calls with user input. Use language-specific libraries instead of shell commands.",
        "secure_alternatives": {
            "python": "subprocess.run(['command', 'arg'], shell=False, check=True)",
            "javascript": "const { spawn } = require('child_process'); spawn('command', ['arg']);",
            "java": "ProcessBuilder pb = new ProcessBuilder('command', 'arg');"
        }
    },
    {
        "pattern_id": "DESER-001",
        "name": "Insecure Deserialization",
        "description": "Deserializing untrusted data can lead to remote code execution",
        "severity": "critical", 
        "cwe_id": "CWE-502",
        "owasp_category": "A08:2021",
        "languages": ["python", "java", "php"],
        "detection_patterns": {
            "python": ["pickle\\.loads\\(", "yaml\\.load\\(", "eval\\(", "exec\\("],
            "java": ["ObjectInputStream", "readObject\\(", "XMLDecoder"],
            "php": ["unserialize\\(", "eval\\("]
        },
        "fix_guidance": "Never deserialize untrusted data. Use JSON or other safe formats.",
        "secure_alternatives": {
            "python": "json.loads(data) # Use JSON instead of pickle",
            "java": "Use JSON with Jackson or Gson instead of Java serialization",
            "php": "json_decode() // Use JSON instead of unserialize"
        }
    },
    {
        "pattern_id": "PATH-001",
        "name": "Path Traversal",
        "description": "File access with user-controlled paths enabling directory traversal",
        "severity": "high",
        "cwe_id": "CWE-22", 
        "owasp_category": "A01:2021",
        "languages": ["python", "javascript", "java", "php"],
        "detection_patterns": {
            "python": ["open\\(.*request\\.", "os\\.path\\.join\\(.*request\\."],
            "javascript": ["readFile\\(.*req\\.", "createReadStream\\(.*req\\."],
            "java": ["new File\\(.*request\\.get", "Paths\\.get\\(.*request\\.get"],
            "php": ["include.*\\", "require.*\\", "file_get_contents\\(.*\\"]
        },
        "fix_guidance": "Validate and sanitize file paths. Use allow-lists for accessible directories.",
        "secure_alternatives": {
            "python": "safe_path = os.path.join(SAFE_DIR, os.path.basename(user_input))",
            "javascript": "const safePath = path.join(SAFE_DIR, path.basename(userInput));",
            "java": "Path safe = Paths.get(SAFE_DIR).resolve(Paths.get(userInput).getFileName());"
        }
    }
]

def seed_vulnerability_patterns():
    """Seed the database with vulnerability patterns"""
    print("🌱 Seeding vulnerability knowledge base...")
    
    db = SessionLocal()
    try:
        # Initialize tables
        init_db()
        
        # Check if already seeded
        existing = db.query(VulnerabilityPattern).count()
        if existing > 0:
            print(f"ℹ️  Database already contains {existing} patterns")
            return
        
        # Insert patterns
        for pattern_data in VULNERABILITY_PATTERNS:
            pattern = VulnerabilityPattern(**pattern_data)
            db.add(pattern)
            print(f"✓ Added pattern: {pattern_data['name']} ({pattern_data['pattern_id']})")
        
        db.commit()
        print(f"✅ Successfully seeded {len(VULNERABILITY_PATTERNS)} vulnerability patterns")
        
    except Exception as e:
        print(f"❌ Error seeding database: {e}")
        db.rollback()
    finally:
        db.close()

if __name__ == "__main__":
    seed_vulnerability_patterns()
