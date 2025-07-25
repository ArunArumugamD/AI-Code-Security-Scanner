# Add to src/ml/training/collect_samples.py
def collect_public_vulnerable_code():
    """Collect vulnerable code from public sources"""
    vulnerable_samples = {
        'SQL Injection': [
            """
def authenticate(username, password):
    sql = "SELECT * FROM users WHERE username='" + username + "' AND password='" + password + "'"
    cursor.execute(sql)
""",
            """
def get_product(prod_id):
    query = f"SELECT * FROM products WHERE id = {prod_id}"
    return db.execute(query)
""",
        ],
        'Command Injection': [
            """
def ping_host(hostname):
    import os
    os.system('ping -c 4 ' + hostname)
""",
            """
def process_file(filename):
    import subprocess
    subprocess.call('cat ' + filename, shell=True)
""",
        ],
        # Add more examples
    }
    
    safe_samples = [
        """
def authenticate(username, password):
    sql = "SELECT * FROM users WHERE username=? AND password=?"
    cursor.execute(sql, (username, password))
""",
        """
def ping_host(hostname):
    import subprocess
    if validate_hostname(hostname):
        subprocess.run(['ping', '-c', '4', hostname], check=True)
""",
    ]
    
    return vulnerable_samples, safe_samples