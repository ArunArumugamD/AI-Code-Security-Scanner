# src/ml/gnn_model_improved.py
"""
Improved GNN model with better feature extraction and architecture
"""
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch_geometric.nn import GCNConv, GATConv, global_mean_pool, global_max_pool, global_add_pool
from torch_geometric.data import Data, DataLoader, Batch
import numpy as np
from typing import List, Tuple, Optional, Dict, Any
from pathlib import Path
import json

class VulnerabilityFeatureExtractor:
    """Enhanced feature extraction for vulnerability detection"""
    
    def __init__(self):
        # Vulnerability-specific patterns
        self.vuln_patterns = {
            'buffer_overflow': ['strcpy', 'sprintf', 'gets', 'strcat', 'scanf'],
            'sql_injection': ['mysql_query', 'executeQuery', 'SELECT.*\\+', 'INSERT.*\\+'],
            'command_injection': ['system', 'exec', 'popen', 'Runtime.exec'],
            'format_string': ['printf.*%', 'sprintf.*%', 'fprintf.*%'],
            'null_pointer': ['malloc', 'calloc', 'free', 'NULL'],
            'double_free': ['free', 'delete'],
            'memory_leak': ['malloc', 'new', 'calloc'],
            'integer_overflow': ['\\+\\+', '--', '\\*', '\\+', 'unsigned', 'int']
        }
        
        # Semantic keywords
        self.semantic_keywords = {
            'security': ['password', 'secret', 'token', 'auth', 'login', 'admin'],
            'network': ['socket', 'connect', 'send', 'recv', 'http', 'url'],
            'file_ops': ['fopen', 'fread', 'fwrite', 'open', 'read', 'write'],
            'crypto': ['encrypt', 'decrypt', 'hash', 'cipher', 'key', 'random'],
            'validation': ['check', 'validate', 'verify', 'sanitize', 'escape'],
            'dangerous': ['eval', 'exec', 'system', 'unsafe', 'temp', 'debug']
        }
    
    def extract_node_features(self, node_text: str, node_type: str, context: Dict) -> List[float]:
        """Extract comprehensive node features"""
        features = []
        
        # 1. Node type one-hot encoding (20 dimensions)
        node_types = [
            'function_def', 'class_def', 'var_assign', 'function_call', 'control_flow',
            'parameter', 'return', 'import', 'literal', 'identifier', 'operator',
            'condition', 'loop', 'exception', 'comment', 'declaration', 'pointer',
            'array_access', 'struct_access', 'other'
        ]
        node_type_features = [1.0 if node_type == nt else 0.0 for nt in node_types]
        features.extend(node_type_features)
        
        # 2. Vulnerability pattern features (8 dimensions)
        vuln_features = []
        for pattern_type, patterns in self.vuln_patterns.items():
            has_pattern = any(pattern.lower() in node_text.lower() for pattern in patterns)
            vuln_features.append(float(has_pattern))
        features.extend(vuln_features)
        
        # 3. Semantic category features (6 dimensions)
        semantic_features = []
        for category, keywords in self.semantic_keywords.items():
            has_keyword = any(keyword.lower() in node_text.lower() for keyword in keywords)
            semantic_features.append(float(has_keyword))
        features.extend(semantic_features)
        
        # 4. Structural features (10 dimensions)
        structural_features = [
            len(node_text),  # Text length
            node_text.count('\n'),  # Lines
            node_text.count('('),  # Parentheses
            node_text.count('['),  # Brackets
            node_text.count('{'),  # Braces
            node_text.count(';'),  # Semicolons
            len(node_text.split()),  # Word count
            float('*' in node_text),  # Has pointer
            float('[]' in node_text),  # Has array
            float('->' in node_text or '.' in node_text)  # Has member access
        ]
        features.extend(structural_features)
        
        # 5. Security-specific features (12 dimensions)
        security_features = [
            float('malloc' in node_text or 'calloc' in node_text),  # Dynamic allocation
            float('free' in node_text or 'delete' in node_text),  # Deallocation
            float('strcpy' in node_text or 'strcat' in node_text),  # Unsafe string ops
            float('gets' in node_text or 'scanf' in node_text),  # Unsafe input
            float('system' in node_text or 'exec' in node_text),  # System calls
            float(any(op in node_text for op in ['++', '--', '+=', '-='])),  # Arithmetic ops
            float('if' in node_text or 'while' in node_text),  # Control flow
            float('NULL' in node_text or 'null' in node_text),  # Null references
            float(len(node_text) > 100),  # Long statements (complexity)
            float(node_text.count('*') > 1),  # Multiple pointers
            float('unsigned' in node_text or 'signed' in node_text),  # Type modifiers
            float(any(char in node_text for char in ['%d', '%s', '%x']))  # Format strings
        ]
        features.extend(security_features)
        
        # 6. Data flow features (6 dimensions)
        dataflow_features = [
            float('input' in node_text.lower() or 'user' in node_text.lower()),  # User input
            float('output' in node_text.lower() or 'print' in node_text.lower()),  # Output
            float('=' in node_text and '==' not in node_text),  # Assignment
            float('return' in node_text),  # Return statement
            float(any(param in node_text for param in ['argc', 'argv', 'param'])),  # Parameters
            float('global' in node_text or 'static' in node_text)  # Global variables
        ]
        features.extend(dataflow_features)
        
        # Ensure we have exactly 62 features
        assert len(features) == 62, f"Expected 62 features, got {len(features)}"
        
        return features

class ImprovedVulnerabilityGNN(nn.Module):
    """Improved GNN architecture with attention and better pooling"""
    
    def __init__(self, num_node_features: int = 62, num_edge_features: int = 8, 
                 hidden_dim: int = 256, num_classes: int = 2, num_vuln_types: int = 10):
        super(ImprovedVulnerabilityGNN, self).__init__()
        
        self.hidden_dim = hidden_dim
        
        # Input projection
        self.input_projection = nn.Linear(num_node_features, hidden_dim)
        
        # Graph attention layers for better feature learning
        self.gat1 = GATConv(hidden_dim, hidden_dim // 2, heads=8, dropout=0.2, concat=True)
        self.gat2 = GATConv(hidden_dim * 4, hidden_dim // 2, heads=8, dropout=0.2, concat=True)
        self.gat3 = GATConv(hidden_dim * 4, hidden_dim, heads=4, dropout=0.2, concat=False)
        
        # Batch normalization
        self.bn1 = nn.BatchNorm1d(hidden_dim * 4)
        self.bn2 = nn.BatchNorm1d(hidden_dim * 4)
        self.bn3 = nn.BatchNorm1d(hidden_dim)
        
        # Dropout
        self.dropout = nn.Dropout(0.3)
        
        # Multi-level pooling
        self.pool_projection = nn.Linear(hidden_dim * 3, hidden_dim)
        
        # Classification heads
        self.vulnerability_classifier = nn.Sequential(
            nn.Linear(hidden_dim, hidden_dim // 2),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(hidden_dim // 2, hidden_dim // 4),
            nn.ReLU(), 
            nn.Dropout(0.2),
            nn.Linear(hidden_dim // 4, num_classes)
        )
        
        self.vulnerability_type_classifier = nn.Sequential(
            nn.Linear(hidden_dim, hidden_dim // 2),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(hidden_dim // 2, hidden_dim // 4),
            nn.ReLU(),
            nn.Dropout(0.2), 
            nn.Linear(hidden_dim // 4, num_vuln_types)
        )
        
        # Confidence estimator
        self.confidence_estimator = nn.Sequential(
            nn.Linear(hidden_dim, hidden_dim // 4),
            nn.ReLU(),
            nn.Linear(hidden_dim // 4, 1),
            nn.Sigmoid()
        )
    
    def forward(self, x, edge_index, batch=None):
        # Input projection
        x = self.input_projection(x)
        x = F.relu(x)
        
        # GAT layers with residual connections
        x1 = self.gat1(x, edge_index)
        x1 = self.bn1(x1)
        x1 = F.relu(x1)
        x1 = self.dropout(x1)
        
        x2 = self.gat2(x1, edge_index)
        x2 = self.bn2(x2)
        x2 = F.relu(x2)
        x2 = self.dropout(x2)
        
        x3 = self.gat3(x2, edge_index)
        x3 = self.bn3(x3)
        x3 = F.relu(x3)
        
        # Multi-level global pooling
        if batch is None:
            batch = torch.zeros(x.size(0), dtype=torch.long, device=x.device)
        
        # Combine different pooling strategies
        mean_pool = global_mean_pool(x3, batch)
        max_pool = global_max_pool(x3, batch)
        add_pool = global_add_pool(x3, batch)
        
        # Concatenate pooled features
        pooled = torch.cat([mean_pool, max_pool, add_pool], dim=1)
        graph_embedding = self.pool_projection(pooled)
        graph_embedding = F.relu(graph_embedding)
        
        # Classification
        vuln_prediction = self.vulnerability_classifier(graph_embedding)
        vuln_type_prediction = self.vulnerability_type_classifier(graph_embedding)
        confidence = self.confidence_estimator(graph_embedding)
        
        return vuln_prediction, vuln_type_prediction, confidence

class ImprovedCodeGraphBuilder:
    """Enhanced code graph builder with better relationship modeling"""
    
    def __init__(self):
        self.feature_extractor = VulnerabilityFeatureExtractor()
        
        # Edge types for better relationship modeling
        self.edge_types = {
            'ast_child': 0,      # AST parent-child
            'data_flow': 1,      # Variable definition -> use
            'control_flow': 2,   # Sequential execution
            'call_flow': 3,      # Function calls
            'memory_flow': 4,    # Memory allocation/deallocation
            'pointer_flow': 5,   # Pointer relationships
            'semantic': 6,       # Semantic relationships
            'vulnerability': 7   # Potential vulnerability relationships
        }
    
    def build_enhanced_graph(self, code: str, language: str) -> Data:
        """Build enhanced graph with vulnerability-specific features"""
        # Parse code into nodes (simplified AST)
        nodes = self._parse_code_to_nodes(code, language)
        
        if len(nodes) < 2:
            # Return minimal graph
            x = torch.tensor([[0.0] * 62], dtype=torch.float)
            edge_index = torch.tensor([[], []], dtype=torch.long)
            edge_attr = torch.tensor([], dtype=torch.float).reshape(0, 8)
            return Data(x=x, edge_index=edge_index, edge_attr=edge_attr)
        
        # Extract node features
        node_features = []
        node_contexts = []
        
        for node in nodes:
            context = self._build_node_context(node, nodes)
            features = self.feature_extractor.extract_node_features(
                node['text'], node['type'], context
            )
            node_features.append(features)
            node_contexts.append(context)
        
        # Build edges with multiple relationship types
        edges, edge_attributes = self._build_enhanced_edges(nodes, node_contexts)
        
        # Convert to tensors
        x = torch.tensor(node_features, dtype=torch.float)
        edge_index = torch.tensor(edges, dtype=torch.long).t().contiguous()
        edge_attr = torch.tensor(edge_attributes, dtype=torch.float)
        
        return Data(x=x, edge_index=edge_index, edge_attr=edge_attr)
    
    def _parse_code_to_nodes(self, code: str, language: str) -> List[Dict]:
        """Parse code into meaningful nodes"""
        nodes = []
        lines = code.split('\n')
        
        current_function = None
        
        for i, line in enumerate(lines):
            line = line.strip()
            if not line or line.startswith('//') or line.startswith('#'):
                continue
            
            node = {
                'id': len(nodes),
                'text': line,
                'line': i + 1,
                'type': self._classify_line_type(line, language),
                'function': current_function
            }
            
            # Track function context
            if 'function' in node['type'] or 'int main' in line:
                current_function = self._extract_function_name(line)
                node['function'] = current_function
            
            nodes.append(node)
        
        return nodes
    
    def _classify_line_type(self, line: str, language: str) -> str:
        """Classify line type for better features"""
        line_lower = line.lower()
        
        if any(keyword in line for keyword in ['int ', 'char ', 'void ', 'float ', 'double ']):
            if '(' in line and ')' in line:
                return 'function_def'
            else:
                return 'var_declaration'
        elif any(keyword in line for keyword in ['if', 'while', 'for', 'switch']):
            return 'control_flow'
        elif 'return' in line:
            return 'return'
        elif '=' in line and '==' not in line:
            return 'assignment'
        elif any(func in line for func in ['printf', 'scanf', 'malloc', 'free', 'strcpy']):
            return 'function_call'
        elif any(vuln in line for vuln in ['strcpy', 'gets', 'sprintf', 'system']):
            return 'potential_vulnerability'
        elif '#include' in line or 'import' in line:
            return 'import'
        else:
            return 'statement'
    
    def _extract_function_name(self, line: str) -> str:
        """Extract function name from definition"""
        if 'main' in line:
            return 'main'
        
        # Simple extraction - can be improved
        parts = line.split('(')[0].split()
        if len(parts) >= 2:
            return parts[-1]
        
        return 'unknown'
    
    def _build_node_context(self, node: Dict, all_nodes: List[Dict]) -> Dict:
        """Build context for each node"""
        context = {
            'function': node['function'],
            'line_number': node['line'],
            'nearby_nodes': [],
            'has_memory_ops': False,
            'has_user_input': False,
            'has_output': False
        }
        
        # Check nearby nodes (±2 lines)
        for other_node in all_nodes:
            if abs(other_node['line'] - node['line']) <= 2 and other_node['id'] != node['id']:
                context['nearby_nodes'].append(other_node['type'])
        
        # Check for security-relevant patterns
        text_lower = node['text'].lower()
        context['has_memory_ops'] = any(op in text_lower for op in ['malloc', 'free', 'new', 'delete'])
        context['has_user_input'] = any(inp in text_lower for inp in ['scanf', 'gets', 'input', 'argv'])
        context['has_output'] = any(out in text_lower for out in ['printf', 'cout', 'print'])
        
        return context
    
    def _build_enhanced_edges(self, nodes: List[Dict], contexts: List[Dict]) -> Tuple[List[List[int]], List[List[float]]]:
        """Build edges with multiple relationship types"""
        edges = []
        edge_attributes = []
        
        for i, node in enumerate(nodes):
            for j, other_node in enumerate(nodes):
                if i == j:
                    continue
                
                # Calculate edge relationships
                edge_types_present = []
                
                # 1. Sequential (control flow)
                if abs(node['line'] - other_node['line']) == 1:
                    edge_types_present.append('control_flow')
                
                # 2. Same function (AST relationship)
                if node['function'] == other_node['function'] and node['function']:
                    edge_types_present.append('ast_child')
                
                # 3. Data flow (variable usage)
                if self._has_data_flow(node['text'], other_node['text']):
                    edge_types_present.append('data_flow')
                
                # 4. Function calls
                if self._has_function_call(node['text'], other_node['text']):
                    edge_types_present.append('call_flow')
                
                # 5. Memory relationships
                if self._has_memory_relationship(node['text'], other_node['text']):
                    edge_types_present.append('memory_flow')
                
                # 6. Vulnerability patterns
                if self._has_vulnerability_relationship(node, other_node):
                    edge_types_present.append('vulnerability')
                
                # Create edge if any relationship exists
                if edge_types_present:
                    edges.append([i, j])
                    
                    # Create edge attribute vector (8 dimensions)
                    edge_attr = [0.0] * 8
                    for edge_type in edge_types_present:
                        if edge_type in self.edge_types:
                            edge_attr[self.edge_types[edge_type]] = 1.0
                    
                    edge_attributes.append(edge_attr)
        
        return edges, edge_attributes
    
    def _has_data_flow(self, node1_text: str, node2_text: str) -> bool:
        """Check for data flow relationship"""
        # Simple variable name extraction and matching
        import re
        
        # Extract variable names from assignments
        var_pattern = r'(\w+)\s*='
        vars1 = re.findall(var_pattern, node1_text)
        
        # Check if any variable is used in second node
        for var in vars1:
            if var in node2_text and f'{var}=' not in node2_text:
                return True
        
        return False
    
    def _has_function_call(self, node1_text: str, node2_text: str) -> bool:
        """Check for function call relationship"""
        # Extract function names and check for calls
        import re
        
        func_def_pattern = r'(\w+)\s*\('
        func_calls1 = re.findall(func_def_pattern, node1_text)
        
        for func in func_calls1:
            if f'{func}(' in node2_text:
                return True
        
        return False
    
    def _has_memory_relationship(self, node1_text: str, node2_text: str) -> bool:
        """Check for memory allocation/deallocation relationship"""
        memory_ops = ['malloc', 'calloc', 'free', 'new', 'delete']
        
        has_alloc1 = any(op in node1_text for op in ['malloc', 'calloc', 'new'])
        has_free2 = any(op in node2_text for op in ['free', 'delete'])
        
        return has_alloc1 and has_free2
    
    def _has_vulnerability_relationship(self, node1: Dict, node2: Dict) -> bool:
        """Check for potential vulnerability relationship"""
        vuln_patterns = [
            ('malloc', 'strcpy'),  # Allocation followed by unsafe copy
            ('gets', 'printf'),    # Unsafe input followed by output
            ('scanf', 'system'),   # Input followed by system call
            ('user', 'system'),    # User input to system command
        ]
        
        text1_lower = node1['text'].lower()
        text2_lower = node2['text'].lower()
        
        for pattern1, pattern2 in vuln_patterns:
            if pattern1 in text1_lower and pattern2 in text2_lower:
                return True
        
        return False

class ImprovedGNNVulnerabilityDetector:
    """Improved GNN detector with enhanced training and inference"""
    
    def __init__(self, model_path: Optional[str] = None):
        self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        
        # Initialize improved model
        self.model = ImprovedVulnerabilityGNN(
            num_node_features=62,
            num_edge_features=8,
            hidden_dim=256,
            num_classes=2,
            num_vuln_types=10
        )
        self.model.to(self.device)
        
        # Graph builder
        self.graph_builder = ImprovedCodeGraphBuilder()
        
        # Load model if path provided
        if model_path and Path(model_path).exists():
            try:
                checkpoint = torch.load(model_path, map_location=self.device)
                self.model.load_state_dict(checkpoint['model_state_dict'])
                self.model.eval()
                print(f"✓ Loaded improved GNN model from {model_path}")
            except Exception as e:
                print(f"⚠ Failed to load model: {e}")
        
        # Vulnerability type mapping
        self.vuln_types = {
            0: "Buffer Overflow",
            1: "SQL Injection", 
            2: "Command Injection",
            3: "Format String",
            4: "NULL Pointer Dereference",
            5: "Double Free",
            6: "Memory Leak",
            7: "Integer Overflow",
            8: "Path Traversal",
            9: "Other"
        }
    
    def predict(self, code: str, language: str) -> Tuple[float, str, float, Dict]:
        """Predict vulnerability with detailed analysis"""
        self.model.eval()
        
        with torch.no_grad():
            # Build enhanced graph
            graph_data = self.graph_builder.build_enhanced_graph(code, language)
            graph_data = graph_data.to(self.device)
            
            # Forward pass
            vuln_pred, type_pred, confidence = self.model(
                graph_data.x,
                graph_data.edge_index
            )
            
            # Process predictions
            vuln_prob = torch.softmax(vuln_pred, dim=1)[0, 1].item()
            type_probs = torch.softmax(type_pred, dim=1)[0]
            
            type_idx = torch.argmax(type_probs).item()
            vuln_type = self.vuln_types.get(type_idx, "Unknown")
            type_confidence = type_probs[type_idx].item()
            
            model_confidence = confidence[0].item()
            
            # Enhanced analysis
            analysis = self._analyze_graph_structure(graph_data, code)
            
            return vuln_prob, vuln_type, type_confidence * model_confidence, analysis
    
    def _analyze_graph_structure(self, graph_data: Data, code: str) -> Dict:
        """Analyze graph structure for additional insights"""
        analysis = {
            'num_nodes': graph_data.x.size(0),
            'num_edges': graph_data.edge_index.size(1),
            'avg_node_degree': graph_data.edge_index.size(1) / graph_data.x.size(0) if graph_data.x.size(0) > 0 else 0,
            'has_vulnerabilities': False,
            'vulnerability_indicators': [],
            'complexity_score': 0.0,
            'risk_factors': []
        }
        
        # Check for vulnerability indicators in code
        vuln_indicators = [
            'strcpy', 'gets', 'sprintf', 'scanf', 'system', 'exec',
            'malloc', 'free', 'printf.*%', 'NULL'
        ]
        
        for indicator in vuln_indicators:
            if indicator in code:
                analysis['vulnerability_indicators'].append(indicator)
                analysis['has_vulnerabilities'] = True
        
        # Calculate complexity
        analysis['complexity_score'] = len(code.split('\n')) / 10.0  # Normalized
        
        # Risk factors
        if 'malloc' in code and 'free' not in code:
            analysis['risk_factors'].append('Memory leak potential')
        if 'strcpy' in code or 'gets' in code:
            analysis['risk_factors'].append('Buffer overflow risk')
        if 'system' in code or 'exec' in code:
            analysis['risk_factors'].append('Command injection risk')
        
        return analysis

if __name__ == "__main__":
    # Test the improved model
    detector = ImprovedGNNVulnerabilityDetector()
    
    test_code = '''
    #include <stdio.h>
    #include <string.h>
    
    void vulnerable_function(char* user_input) {
        char buffer[64];
        strcpy(buffer, user_input);  // Buffer overflow vulnerability
        printf("Input: %s", buffer);
    }
    
    int main(int argc, char* argv[]) {
        if (argc > 1) {
            vulnerable_function(argv[1]);
        }
        return 0;
    }
    '''
    
    vuln_prob, vuln_type, confidence, analysis = detector.predict(test_code, "c")
    
    print(f"Vulnerability Probability: {vuln_prob:.2%}")
    print(f"Type: {vuln_type}")
    print(f"Confidence: {confidence:.2%}")
    print(f"Analysis: {analysis}")