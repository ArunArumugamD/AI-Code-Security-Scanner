# src/ml/code_graph.py
import networkx as nx
import numpy as np
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass
import ast
import torch
from torch_geometric.data import Data
from src.core.code_parser import UniversalCodeParser, CodeNode

@dataclass
class GraphNode:
    """Represents a node in the code graph"""
    id: int
    type: str  # function, variable, call, etc.
    name: str
    line: int
    features: List[float]
    
@dataclass
class GraphEdge:
    """Represents an edge in the code graph"""
    source: int
    target: int
    edge_type: str  # calls, uses, defines, etc.

class CodeGraphBuilder:
    """Converts code into graph representation for GNN analysis"""
    
    def __init__(self):
        self.parser = UniversalCodeParser()
        self.node_types = {
            'function_definition': 0,
            'class_definition': 1,
            'variable_assignment': 2,
            'function_call': 3,
            'control_flow': 4,
            'parameter': 5,
            'return': 6,
            'import': 7
        }
        
        self.edge_types = {
            'calls': 0,
            'uses': 1,
            'defines': 2,
            'contains': 3,
            'follows': 4,
            'depends_on': 5
        }
    
    def build_graph(self, code: str, language: str) -> nx.DiGraph:
        """Build a directed graph from code"""
        # Parse code to AST
        ast_root = self.parser.parse(code, language)
        if not ast_root:
            return nx.DiGraph()
        
        # Initialize graph
        graph = nx.DiGraph()
        self.node_counter = 0
        self.nodes_map = {}
        
        # Build graph from AST
        self._process_ast_node(ast_root, graph, parent_id=None)
        
        # Add control flow edges
        self._add_control_flow_edges(graph, code)
        
        # Add data flow edges
        self._add_data_flow_edges(graph)
        
        return graph
    
    def _process_ast_node(self, node: CodeNode, graph: nx.DiGraph, 
                         parent_id: Optional[int]) -> int:
        """Process AST node and add to graph"""
        # Create graph node
        node_id = self.node_counter
        self.node_counter += 1
        
        # Determine node type
        node_type = self._get_node_type(node)
        
        # Extract features
        features = self._extract_node_features(node)
        
        # Add node to graph
        graph.add_node(
            node_id,
            type=node_type,
            name=node.text[:50],  # Truncate long text
            line=node.start_line,
            features=features,
            ast_type=node.type
        )
        
        # Add edge from parent
        if parent_id is not None:
            graph.add_edge(parent_id, node_id, type='contains')
        
        # Store mapping
        self.nodes_map[node.get_hash()] = node_id
        
        # Process children
        for child in node.children:
            child_id = self._process_ast_node(child, graph, node_id)
            
            # Add specific edges based on relationship
            if self._is_function_call(child):
                graph.add_edge(node_id, child_id, type='calls')
            elif self._is_variable_use(child):
                graph.add_edge(child_id, node_id, type='uses')
        
        return node_id
    
    def _get_node_type(self, node: CodeNode) -> str:
        """Determine the semantic type of a node"""
        type_mapping = {
            'function_definition': 'function_definition',
            'method_declaration': 'function_definition',
            'class_definition': 'class_definition',
            'assignment': 'variable_assignment',
            'call_expression': 'function_call',
            'if_statement': 'control_flow',
            'while_statement': 'control_flow',
            'for_statement': 'control_flow',
            'return_statement': 'return',
            'import_statement': 'import'
        }
        
        for ast_type, node_type in type_mapping.items():
            if ast_type in node.type:
                return node_type
        
        return 'other'
    
    def _extract_node_features(self, node: CodeNode) -> List[float]:
        """Extract numerical features from a node"""
        features = []
        
        # Node type encoding (one-hot)
        node_type = self._get_node_type(node)
        type_vector = [0.0] * len(self.node_types)
        if node_type in self.node_types:
            type_vector[self.node_types[node_type]] = 1.0
        features.extend(type_vector)
        
        # Structural features
        features.append(float(len(node.children)))  # Number of children
        features.append(float(node.end_line - node.start_line + 1))  # Lines of code
        features.append(float(len(node.text)))  # Character count
        features.append(float(node.text.count('\n')))  # Newline count
        
        # Complexity indicators
        features.append(float(node.text.count('if ')))
        features.append(float(node.text.count('for ')))
        features.append(float(node.text.count('while ')))
        features.append(float(node.text.count('return ')))
        
        # Security-relevant patterns
        features.append(float('eval' in node.text))
        features.append(float('exec' in node.text))
        features.append(float('system' in node.text))
        features.append(float('sql' in node.text.lower()))
        
        # Additional features to reach 24 total
        features.append(float('SELECT' in node.text.upper()))  # SQL keywords
        features.append(float('INSERT' in node.text.upper()))
        features.append(float('UPDATE' in node.text.upper()))
        features.append(float('DELETE' in node.text.upper()))
        
        return features
    
    def _is_function_call(self, node: CodeNode) -> bool:
        """Check if node is a function call"""
        return 'call' in node.type.lower() or 'invocation' in node.type.lower()
    
    def _is_variable_use(self, node: CodeNode) -> bool:
        """Check if node uses a variable"""
        return 'identifier' in node.type and node.parent_type not in ['function_definition', 'class_definition']
    
    def _add_control_flow_edges(self, graph: nx.DiGraph, code: str):
        """Add control flow edges between sequential statements"""
        lines = code.split('\n')
        nodes_by_line = {}
        
        # Group nodes by line
        for node_id in graph.nodes():
            line = graph.nodes[node_id]['line']
            if line not in nodes_by_line:
                nodes_by_line[line] = []
            nodes_by_line[line].append(node_id)
        
        # Add edges between sequential lines
        sorted_lines = sorted(nodes_by_line.keys())
        for i in range(len(sorted_lines) - 1):
            curr_line = sorted_lines[i]
            next_line = sorted_lines[i + 1]
            
            # Connect nodes from current line to next line
            for curr_node in nodes_by_line[curr_line]:
                for next_node in nodes_by_line[next_line]:
                    if not graph.has_edge(curr_node, next_node):
                        graph.add_edge(curr_node, next_node, type='follows')
    
    def _add_data_flow_edges(self, graph: nx.DiGraph):
        """Add data flow edges (simplified version)"""
        # Track variable definitions and uses
        definitions = {}  # variable -> node_id
        
        for node_id in graph.nodes():
            node_data = graph.nodes[node_id]
            
            # Track variable definitions
            if node_data['type'] == 'variable_assignment':
                var_name = self._extract_variable_name(node_data['name'])
                if var_name:
                    definitions[var_name] = node_id
            
            # Track variable uses
            elif node_data['type'] in ['function_call', 'return']:
                # Check for variable references
                for var_name, def_node in definitions.items():
                    if var_name in node_data['name']:
                        graph.add_edge(def_node, node_id, type='defines')
    
    def _extract_variable_name(self, assignment_text: str) -> Optional[str]:
        """Extract variable name from assignment"""
        if '=' in assignment_text:
            parts = assignment_text.split('=')
            if parts:
                return parts[0].strip()
        return None
    
    def to_pytorch_geometric(self, graph: nx.DiGraph) -> Data:
        """Convert NetworkX graph to PyTorch Geometric format"""
        # Map nodes to indices
        node_mapping = {node: i for i, node in enumerate(graph.nodes())}
        
        # Extract node features
        x = []
        for node in graph.nodes():
            features = graph.nodes[node]['features']
            x.append(features)
        x = torch.tensor(x, dtype=torch.float)
        
        # Extract edges
        edge_index = []
        edge_attr = []
        
        for source, target, data in graph.edges(data=True):
            edge_index.append([node_mapping[source], node_mapping[target]])
            
            # Edge type encoding
            edge_type = data.get('type', 'other')
            edge_features = [0.0] * len(self.edge_types)
            if edge_type in self.edge_types:
                edge_features[self.edge_types[edge_type]] = 1.0
            edge_attr.append(edge_features)
        
        edge_index = torch.tensor(edge_index, dtype=torch.long).t().contiguous()
        edge_attr = torch.tensor(edge_attr, dtype=torch.float)
        
        # Create PyTorch Geometric data object
        data = Data(x=x, edge_index=edge_index, edge_attr=edge_attr)
        
        # Add metadata
        data.num_nodes = len(graph.nodes())
        data.node_labels = [graph.nodes[node]['type'] for node in graph.nodes()]
        
        return data
    
    def visualize_graph(self, graph: nx.DiGraph, output_path: str = "code_graph.png"):
        """Visualize the code graph"""
        import matplotlib.pyplot as plt
        
        plt.figure(figsize=(12, 8))
        
        # Color nodes by type
        node_colors = []
        for node in graph.nodes():
            node_type = graph.nodes[node]['type']
            if node_type == 'function_definition':
                node_colors.append('lightblue')
            elif node_type == 'class_definition':
                node_colors.append('lightgreen')
            elif node_type == 'control_flow':
                node_colors.append('yellow')
            elif node_type == 'function_call':
                node_colors.append('orange')
            else:
                node_colors.append('lightgray')
        
        # Layout
        pos = nx.spring_layout(graph, k=1, iterations=50)
        
        # Draw nodes
        nx.draw_networkx_nodes(graph, pos, node_color=node_colors, node_size=500)
        
        # Draw edges with different styles
        edge_types = set(data['type'] for _, _, data in graph.edges(data=True))
        colors = ['red', 'blue', 'green', 'purple', 'orange']
        
        for i, edge_type in enumerate(edge_types):
            edges = [(u, v) for u, v, d in graph.edges(data=True) if d['type'] == edge_type]
            nx.draw_networkx_edges(graph, pos, edgelist=edges, 
                                 edge_color=colors[i % len(colors)],
                                 label=edge_type, alpha=0.6)
        
        # Labels
        labels = {node: f"{graph.nodes[node]['type'][:4]}\nL{graph.nodes[node]['line']}" 
                 for node in graph.nodes()}
        nx.draw_networkx_labels(graph, pos, labels, font_size=8)
        
        plt.title("Code Structure Graph")
        plt.legend()
        plt.axis('off')
        plt.tight_layout()
        plt.savefig(output_path, dpi=150, bbox_inches='tight')
        plt.close()
        
        print(f"✓ Graph visualization saved to {output_path}")

