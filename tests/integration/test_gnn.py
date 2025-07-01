# test_gnn.py
import asyncio
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.ml.code_graph import CodeGraphBuilder
from src.ml.gnn_model import GNNVulnerabilityDetector
from src.analyzers.gnn_analyzer import GNNStructuralAnalyzer

async def test_gnn():
    print("🧪 Testing Graph Neural Network Integration\n")
    
    # Test 1: Code Graph Building
    print("1️⃣ Testing code graph construction...")
    
    test_code = '''
def process_payment(user_id, amount):
    # Get user from database
    query = "SELECT * FROM users WHERE id = " + str(user_id)
    user = db.execute(query)
    
    # Process payment
    if user and user.balance >= amount:
        new_balance = user.balance - amount
        update_query = f"UPDATE users SET balance = {new_balance} WHERE id = {user_id}"
        db.execute(update_query)
        
        # Log transaction
        os.system(f"echo Transaction: {user_id} paid {amount} >> /tmp/transactions.log")
        
        return True
    return False
'''
    
    try:
        builder = CodeGraphBuilder()
        graph = builder.build_graph(test_code, "python")
        
        print(f"   ✓ Built graph with {len(graph.nodes())} nodes and {len(graph.edges())} edges")
        
        # Show node types
        node_types = {}
        for node in graph.nodes():
            node_type = graph.nodes[node]['type']
            node_types[node_type] = node_types.get(node_type, 0) + 1
        
        print("   Node types found:")
        for node_type, count in node_types.items():
            print(f"     • {node_type}: {count}")
        
        # Visualize if possible
        try:
            builder.visualize_graph(graph, "test_code_graph.png")
        except:
            print("   ℹ Visualization skipped (matplotlib not configured)")
            
    except Exception as e:
        print(f"   ❌ Graph building failed: {e}")
        return
    
    # Test 2: PyTorch Geometric Conversion
    print("\n2️⃣ Testing PyTorch Geometric conversion...")
    
    try:
        graph_data = builder.to_pytorch_geometric(graph)
        print(f"   ✓ Converted to PyTorch format")
        print(f"   ✓ Node features shape: {graph_data.x.shape}")
        print(f"   ✓ Edge index shape: {graph_data.edge_index.shape}")
    except Exception as e:
        print(f"   ❌ Conversion failed: {e}")
        
    # Test 3: GNN Model
    print("\n3️⃣ Testing GNN vulnerability detection...")
    
    try:
        detector = GNNVulnerabilityDetector()
        vuln_prob, vuln_type, confidence = detector.predict(graph_data)
        
        print(f"   ✓ Vulnerability probability: {vuln_prob:.2%}")
        print(f"   ✓ Detected type: {vuln_type} (confidence: {confidence:.2%})")
        
        # Structure analysis
        analysis = detector.analyze_code_structure(graph_data)
        print(f"   ✓ Structure analysis:")
        print(f"     • Nodes: {analysis['num_nodes']}")
        print(f"     • Edges: {analysis['num_edges']}")
        print(f"     • Density: {analysis['graph_density']:.3f}")
        print(f"     • Suspicious nodes: {analysis['suspicious_nodes']}")
        
    except Exception as e:
        print(f"   ❌ GNN detection failed: {e}")
    
    # Test 4: Full GNN Analyzer
    print("\n4️⃣ Testing complete GNN analyzer...")
    
    try:
        analyzer = GNNStructuralAnalyzer()
        vulnerabilities = await analyzer.analyze(test_code, "python", "test.py")
        
        print(f"   ✓ Found {len(vulnerabilities)} vulnerabilities")
        
        for vuln in vulnerabilities:
            print(f"\n   🔍 {vuln.name}")
            print(f"      Severity: {vuln.severity.value}")
            print(f"      Confidence: {vuln.confidence:.2%}")
            print(f"      Lines: {vuln.line_start}-{vuln.line_end}")
            if vuln.ai_explanation:
                print(f"      GNN: {vuln.ai_explanation[:100]}...")
                
    except Exception as e:
        print(f"   ❌ GNN analyzer failed: {e}")
    
    print("\n✅ GNN integration test completed!")

if __name__ == "__main__":
    print("Note: This test requires PyTorch Geometric to be installed")
    print("If you get errors, install with:")
    print("pip install torch-scatter torch-sparse torch-geometric -f https://data.pyg.org/whl/torch-2.1.0+cpu.html\n")
    
    asyncio.run(test_gnn())
