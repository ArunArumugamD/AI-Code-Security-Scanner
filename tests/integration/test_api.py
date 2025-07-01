# test_api.py
import requests
import json
import time

BASE_URL = "http://localhost:8000"

def test_api():
    print("🧪 Testing AISec Scanner API\n")
    
    # Test 1: Health check
    print("1️⃣ Testing health endpoint...")
    response = requests.get(f"{BASE_URL}/health")
    print(f"   Status: {response.status_code}")
    print(f"   Response: {response.json()}")
    
    # Test 2: Create project
    print("\n2️⃣ Creating test project...")
    project_data = {
        "name": f"API Test Project {int(time.time())}",
        "description": "Testing API endpoints",
        "languages": ["python", "javascript"]
    }
    response = requests.post(f"{BASE_URL}/api/projects", json=project_data)
    print(f"   Status: {response.status_code}")
    project = response.json()
    print(f"   Created: {project['name']} (ID: {project['id']})")
    
    # Test 3: Quick scan
    print("\n3️⃣ Testing quick scan...")
    scan_data = {
        "code": '''
import os
def unsafe(user_input):
    os.system("echo " + user_input)  # Command injection
    eval(user_input)  # Code injection
''',
        "language": "python"
    }
    response = requests.post(f"{BASE_URL}/api/scan/quick", json=scan_data)
    print(f"   Status: {response.status_code}")
    result = response.json()
    print(f"   Found: {result['summary']['total']} vulnerabilities")
    print(f"   Scan time: {result['scan_time']:.2f}s")
    
    # Test 4: List projects
    print("\n4️⃣ Listing projects...")
    response = requests.get(f"{BASE_URL}/api/projects")
    print(f"   Status: {response.status_code}")
    projects = response.json()
    print(f"   Total projects: {len(projects)}")
    
    print("\n✅ API tests completed!")

if __name__ == "__main__":
    test_api()
