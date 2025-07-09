# src/database/seed_knowledge_base.py
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.dirname(os.path.dirname(os.path.dirname(__file__)))))

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
            "python": [
                r'query\s*=\s*["\'][^"\']*\+',                    # query = "..." +
                r'sql\s*=\s*["\'][^"\']*\+',                      # sql = "..." +
                r'execute\s*\(["\'][^"\']*\+',                    # execute("..." +
                r'execute\s*\(.*?\+.*?\)',                        # execute(anything + anything)
                r'execute\s*\(f["\']',                            # execute(f"
                r'(SELECT|INSERT|UPDATE|DELETE)[^"\']*["\'\s]\s*\+',  # SQL + concat
                r'["\']SELECT.*WHERE.*["\'\s]\s*\+',              # "SELECT...WHERE..." +
            ],
            "javascript": [
                r'query\s*\(["\'][^"\']*\+',                      # query("..." +
                r'execute\s*\(["\'][^"\']*\$\{',                  # execute("...${
                r'raw\s*\(["\'][^"\']*\$\{',                      # raw("...${
            ],
            "java": [
                r'createQuery\s*\(["\'][^"\']*\+',
                r'executeQuery\s*\(["\'][^"\']*\+'
            ],
            "php": [
                r'mysql_query\s*\(["\'][^"\']*\.\s*\$',
                r'mysqli_query\s*\([^,]*,\s*["\'][^"\']*\.\s*\$'
            ]
        },
        "ai_features": {},
        "fix_guidance": "Use parameterized queries or prepared statements. Never concatenate user input into SQL.",
        "secure_alternatives": {
            "python": "cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))",
            "javascript": "db.query('SELECT * FROM users WHERE id = ?', [userId])",
            "java": "PreparedStatement ps = conn.prepareStatement('SELECT * FROM users WHERE id = ?')"
        },
        "references": ["https://owasp.org/www-community/attacks/SQL_Injection"],
        "confidence_threshold": 0.7,
        "false_positive_rate": 0.1
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
            "javascript": [
                r"innerHTML\s*=",                                  # innerHTML =
                r"outerHTML\s*=",                                  # outerHTML =
                r"document\.write\s*\(",                           # document.write(
                r"document\.writeln\s*\(",                         # document.writeln(
                r"insertAdjacentHTML\s*\(",                        # insertAdjacentHTML(
                r"dangerouslySetInnerHTML"                         # React dangerous HTML
            ],
            "php": [
                r"echo\s+.*\$_(?:GET|POST|REQUEST)",               # echo $_GET/$_POST
                r"print\s+.*\$_(?:GET|POST|REQUEST)",              # print $_GET/$_POST
            ],
            "python": [
                r"render_template_string\s*\(.*request\.",         # Flask template injection
                r"Markup\s*\(.*request\."                          # Flask Markup with user input
            ]
        },
        "ai_features": {},
        "fix_guidance": "Always escape user input before rendering. Use textContent instead of innerHTML.",
        "secure_alternatives": {
            "javascript": "element.textContent = userInput;",
            "php": "echo htmlspecialchars($_GET['input'], ENT_QUOTES, 'UTF-8');",
            "python": "{{ user_input | e }} in Jinja2 templates"
        },
        "references": ["https://owasp.org/www-community/attacks/xss/"],
        "confidence_threshold": 0.7,
        "false_positive_rate": 0.15
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
            "python": [
                r"os\.system\s*\([^)]*\+",                        # os.system(...+...)
                r"os\.system\s*\(f['\"]",                         # os.system(f"...")
                r"os\.system\s*\([^)]*%",                         # os.system(...%...)
                r"subprocess\.call\s*\([^)]*shell\s*=\s*True",    # subprocess.call(...shell=True)
                r"subprocess\.run\s*\([^)]*shell\s*=\s*True",     # subprocess.run(...shell=True)
                r"os\.popen\s*\(",                                # os.popen(
            ],
            "javascript": [
                r"child_process\.exec\s*\(",                      # exec(
                r"child_process\.execSync\s*\(",                  # execSync(
                r"child_process\.spawn\s*\([^)]*shell.*true"      # spawn(...shell: true)
            ],
            "java": [
                r"Runtime\.getRuntime\(\)\.exec\s*\(",            # Runtime.exec(
                r"ProcessBuilder\s*\([^)]*\+"                     # ProcessBuilder with concat
            ],
            "php": [
                r"system\s*\(",                                   # system(
                r"exec\s*\(",                                     # exec(
                r"shell_exec\s*\(",                               # shell_exec(
                r"passthru\s*\(",                                 # passthru(
                r"`[^`]*\$"                                       # Backticks with $
            ],
            "c": [
                r"system\s*\(",                                   # system(
                r"popen\s*\("                                     # popen(
            ]
        },
        "ai_features": {},
        "fix_guidance": "Avoid system calls with user input. Use language-specific libraries instead of shell commands.",
        "secure_alternatives": {
            "python": "subprocess.run(['command', 'arg'], shell=False, check=True)",
            "javascript": "const { spawn } = require('child_process'); spawn('command', ['arg']);",
            "java": "ProcessBuilder pb = new ProcessBuilder('command', 'arg');"
        },
        "references": ["https://owasp.org/www-community/attacks/Command_Injection"],
        "confidence_threshold": 0.7,
        "false_positive_rate": 0.1
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
            "python": [
                r"pickle\.loads\s*\(",                            # pickle.loads(
                r"pickle\.load\s*\(",                             # pickle.load(
                r"yaml\.load\s*\([^)]*Loader\s*=\s*yaml\.Loader", # yaml.load with unsafe loader
                r"yaml\.load\s*\([^)]*[^)]$",                    # yaml.load without safe loader
                r"\beval\s*\(",                                   # eval( - word boundary
                r"\bexec\s*\("                                    # exec( - word boundary
            ],
            "java": [
                r"ObjectInputStream",                              # Java deserialization
                r"readObject\s*\(",                               # readObject()
                r"XMLDecoder"                                      # XML deserialization
            ],
            "php": [
                r"unserialize\s*\(",                              # PHP unserialize
                r"\beval\s*\("                                    # PHP eval
            ]
        },
        "ai_features": {},
        "fix_guidance": "Never deserialize untrusted data. Use JSON or other safe formats.",
        "secure_alternatives": {
            "python": "json.loads(data) # Use JSON instead of pickle",
            "java": "Use JSON with Jackson or Gson instead of Java serialization",
            "php": "json_decode($data) // Use JSON instead of unserialize"
        },
        "references": ["https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data"],
        "confidence_threshold": 0.7,
        "false_positive_rate": 0.05
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
            "python": [
                r"open\s*\([^)]*request\.",                       # open(...request.
                r"open\s*\([^)]*\+",                              # open(...+...)
                r"os\.path\.join\s*\([^)]*request\.",             # os.path.join(...request.
                r"pathlib\.Path\s*\([^)]*\+"                      # Path(...+...)
            ],
            "javascript": [
                r"readFile\s*\([^)]*req\.",                       # readFile(...req.
                r"createReadStream\s*\([^)]*req\.",               # createReadStream(...req.
                r"readFileSync\s*\([^)]*\+"                       # readFileSync(...+...)
            ],
            "java": [
                r"new\s+File\s*\([^)]*request\.get",              # new File(...request.get
                r"Paths\.get\s*\([^)]*request\.get"               # Paths.get(...request.get
            ],
            "php": [
                r"include\s*\([^)]*\$_(?:GET|POST)",              # include($_GET
                r"require\s*\([^)]*\$_(?:GET|POST)",              # require($_POST
                r"file_get_contents\s*\([^)]*\$_"                 # file_get_contents($_
            ]
        },
        "ai_features": {},
        "fix_guidance": "Validate and sanitize file paths. Use allow-lists for accessible directories.",
        "secure_alternatives": {
            "python": "safe_path = os.path.join(SAFE_DIR, os.path.basename(user_input))",
            "javascript": "const safePath = path.join(SAFE_DIR, path.basename(userInput));",
            "java": "Path safe = Paths.get(SAFE_DIR).resolve(Paths.get(userInput).getFileName());"
        },
        "references": ["https://owasp.org/www-community/attacks/Path_Traversal"],
        "confidence_threshold": 0.7,
        "false_positive_rate": 0.2
    },
    {
        "pattern_id": "OSYS-001",
        "name": "Unsafe os.system usage",
        "description": "os.system is unsafe for executing system commands",
        "severity": "high",
        "cwe_id": "CWE-78",
        "owasp_category": "A03:2021",
        "languages": ["python"],
        "detection_patterns": {
            "python": [
                r"os\.system\s*\("                                # Any os.system usage
            ]
        },
        "ai_features": {},
        "fix_guidance": "Use the subprocess module instead of os.system, and ensure that user-input is properly sanitized and escaped.",
        "secure_alternatives": {
            "python": "subprocess.run(['command', 'arg'], shell=False, check=True)"
        },
        "references": ["https://docs.python.org/3/library/subprocess.html#security-considerations"],
        "confidence_threshold": 0.6,
        "false_positive_rate": 0.1
    },
    {
        "pattern_id": "EXEC-001",
        "name": "Unsafe exec usage",
        "description": "exec() can execute arbitrary Python code",
        "severity": "high",
        "cwe_id": "CWE-94",
        "owasp_category": "A03:2021",
        "languages": ["python"],
        "detection_patterns": {
            "python": [
                r"\bexec\s*\("                                    # exec( with word boundary
            ]
        },
        "ai_features": {},
        "fix_guidance": "Avoid using exec(). If necessary, strictly validate input or use ast.literal_eval for safe evaluation.",
        "secure_alternatives": {
            "python": "# Avoid exec() entirely, or use ast.literal_eval() for data"
        },
        "references": ["https://docs.python.org/3/library/functions.html#exec"],
        "confidence_threshold": 0.8,
        "false_positive_rate": 0.05
    },
    {
        "pattern_id": "EVAL-001",
        "name": "Unsafe eval usage",
        "description": "eval() can execute arbitrary code",
        "severity": "high",
        "cwe_id": "CWE-94",
        "owasp_category": "A03:2021",
        "languages": ["python", "javascript"],
        "detection_patterns": {
            "python": [
                r"\beval\s*\("                                    # eval( with word boundary
            ],
            "javascript": [
                r"\beval\s*\("                                    # eval( with word boundary
            ]
        },
        "ai_features": {},
        "fix_guidance": "Use ast.literal_eval() for Python or JSON.parse() for JavaScript",
        "secure_alternatives": {
            "python": "ast.literal_eval(data) # Safe evaluation of literals",
            "javascript": "JSON.parse(data) // Safe JSON parsing"
        },
        "references": ["https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/eval#never_use_eval!"],
        "confidence_threshold": 0.8,
        "false_positive_rate": 0.05
    }
]

def seed_vulnerability_patterns():
    """Seed the database with vulnerability patterns"""
    print("🌱 Seeding vulnerability knowledge base...")
    
    db = SessionLocal()
    try:
        # Initialize tables
        init_db()
        
        # Clear existing patterns
        existing = db.query(VulnerabilityPattern).count()
        if existing > 0:
            print(f"🧹 Clearing {existing} existing patterns...")
            db.query(VulnerabilityPattern).delete()
            db.commit()
        
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