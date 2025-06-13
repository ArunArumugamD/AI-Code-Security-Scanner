# src/core/code_parser.py
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
import tree_sitter_languages as tsl
from tree_sitter import Node
import hashlib

@dataclass
class CodeNode:
    """Represents a node in the code AST"""
    type: str
    start_line: int
    end_line: int
    start_col: int
    end_col: int
    text: str
    children: List['CodeNode']
    parent_type: Optional[str] = None
    
    def get_hash(self) -> str:
        """Generate unique hash for this node"""
        content = f"{self.type}:{self.start_line}:{self.text[:50]}"
        return hashlib.md5(content.encode()).hexdigest()[:8]

@dataclass 
class ParsedFunction:
    """Extracted function information"""
    name: str
    start_line: int
    end_line: int
    parameters: List[str]
    body: str
    complexity: int  # Cyclomatic complexity
    
@dataclass
class ParsedClass:
    """Extracted class information"""
    name: str
    start_line: int
    end_line: int
    methods: List[ParsedFunction]
    attributes: List[str]

class UniversalCodeParser:
    """Universal parser for all supported languages using Tree-sitter"""
    
    def __init__(self):
        self.parsers = {}
        self._initialize_parsers()
        
    def _initialize_parsers(self):
        """Initialize Tree-sitter parsers for all languages"""
        languages = ['python', 'javascript', 'java', 'php', 'c', 'cpp']
        
        for lang in languages:
            try:
                # Get parser from tree-sitter-languages
                self.parsers[lang] = tsl.get_parser(lang)
                print(f"✓ Initialized {lang} parser")
            except Exception as e:
                print(f"✗ Failed to initialize {lang} parser: {e}")
    
    def parse(self, code: str, language: str) -> Optional[CodeNode]:
        """Parse code and return AST as CodeNode tree"""
        if language not in self.parsers:
            raise ValueError(f"Unsupported language: {language}")
        
        parser = self.parsers[language]
        tree = parser.parse(bytes(code, 'utf8'))
        
        # Convert to our CodeNode structure
        return self._convert_node(tree.root_node, code)
    
    def _convert_node(self, node: Node, source: str, parent_type: str = None) -> CodeNode:
        """Convert Tree-sitter node to CodeNode"""
        start_line = node.start_point[0] + 1
        end_line = node.end_point[0] + 1
        
        # Get node text
        text = source[node.start_byte:node.end_byte]
        
        # Recursively convert children
        children = [
            self._convert_node(child, source, node.type) 
            for child in node.children
        ]
        
        return CodeNode(
            type=node.type,
            start_line=start_line,
            end_line=end_line,
            start_col=node.start_point[1],
            end_col=node.end_point[1],
            text=text,
            children=children,
            parent_type=parent_type
        )
    
    def extract_functions(self, code: str, language: str) -> List[ParsedFunction]:
        """Extract all functions from code"""
        ast = self.parse(code, language)
        if not ast:
            return []
        
        functions = []
        self._extract_functions_recursive(ast, functions, language)
        return functions
    
    def _extract_functions_recursive(self, node: CodeNode, functions: List[ParsedFunction], language: str):
        """Recursively extract functions from AST"""
        # Language-specific function detection
        function_types = {
            'python': ['function_definition'],
            'javascript': ['function_declaration', 'arrow_function', 'function_expression'],
            'java': ['method_declaration'],
            'php': ['function_definition', 'method_declaration'],
            'c': ['function_definition'],
            'cpp': ['function_definition']
        }
        
        if node.type in function_types.get(language, []):
            func = self._parse_function(node, language)
            if func:
                functions.append(func)
        
        # Recurse into children
        for child in node.children:
            self._extract_functions_recursive(child, functions, language)
    
    def _parse_function(self, node: CodeNode, language: str) -> Optional[ParsedFunction]:
        """Parse function details from node"""
        name = "anonymous"
        parameters = []
        
        # Extract function name and parameters based on language
        if language == 'python':
            for child in node.children:
                if child.type == 'identifier':
                    name = child.text
                elif child.type == 'parameters':
                    parameters = [p.text for p in child.children if p.type == 'identifier']
        
        elif language in ['javascript', 'java', 'c', 'cpp']:
            for child in node.children:
                if child.type == 'identifier':
                    name = child.text
                elif child.type in ['formal_parameters', 'parameter_list']:
                    parameters = self._extract_parameters(child)
        
        # Calculate complexity (simplified)
        complexity = self._calculate_complexity(node)
        
        return ParsedFunction(
            name=name,
            start_line=node.start_line,
            end_line=node.end_line,
            parameters=parameters,
            body=node.text,
            complexity=complexity
        )
    
    def _extract_parameters(self, param_node: CodeNode) -> List[str]:
        """Extract parameter names from parameter node"""
        params = []
        for child in param_node.children:
            if child.type in ['identifier', 'formal_parameter', 'parameter']:
                # Look for identifier within parameter
                if child.type == 'identifier':
                    params.append(child.text)
                else:
                    for subchild in child.children:
                        if subchild.type == 'identifier':
                            params.append(subchild.text)
        return params
    
    def _calculate_complexity(self, node: CodeNode) -> int:
        """Calculate cyclomatic complexity of a function"""
        complexity = 1  # Base complexity
        
        # Increment for each decision point
        decision_types = [
            'if_statement', 'while_statement', 'for_statement',
            'switch_statement', 'case_statement', 'catch_clause',
            'conditional_expression', 'binary_expression'
        ]
        
        def count_decisions(n: CodeNode):
            nonlocal complexity
            if n.type in decision_types:
                complexity += 1
            for child in n.children:
                count_decisions(child)
        
        count_decisions(node)
        return complexity
    
    def find_security_patterns(self, code: str, language: str) -> List[Dict[str, Any]]:
        """Find potentially insecure code patterns"""
        ast = self.parse(code, language)
        if not ast:
            return []
        
        patterns = []
        
        # Language-specific unsafe patterns
        unsafe_patterns = {
            'python': {
                'eval': 'Code injection risk',
                'exec': 'Code injection risk', 
                'os.system': 'Command injection risk',
                'pickle.loads': 'Deserialization vulnerability',
                '__import__': 'Dynamic import security risk'
            },
            'javascript': {
                'eval': 'Code injection risk',
                'innerHTML': 'XSS vulnerability risk',
                'document.write': 'DOM XSS risk',
                'setTimeout': 'Potential code injection if string passed',
                'dangerouslySetInnerHTML': 'React XSS risk'
            },
            'java': {
                'Runtime.exec': 'Command injection risk',
                'ProcessBuilder': 'Command injection risk',
                'ObjectInputStream': 'Deserialization vulnerability',
                'ScriptEngine': 'Code injection risk'
            },
            'php': {
                'eval': 'Code injection risk',
                'system': 'Command injection risk',
                'exec': 'Command injection risk',
                'unserialize': 'Deserialization vulnerability',
                'include': 'File inclusion vulnerability if dynamic'
            },
            'c': {
                'gets': 'Buffer overflow risk',
                'strcpy': 'Buffer overflow risk',
                'sprintf': 'Format string vulnerability',
                'system': 'Command injection risk'
            },
            'cpp': {
                'gets': 'Buffer overflow risk',
                'strcpy': 'Buffer overflow risk',
                'sprintf': 'Format string vulnerability',
                'system': 'Command injection risk'
            }
        }
        
        # Search for patterns
        self._find_patterns_recursive(ast, patterns, unsafe_patterns.get(language, {}), language)
        
        return patterns
    
    def _find_patterns_recursive(self, node: CodeNode, patterns: List[Dict], 
                                unsafe_dict: Dict[str, str], language: str):
        """Recursively search for unsafe patterns"""
        # Check if node text contains any unsafe pattern
        for pattern, risk in unsafe_dict.items():
            if pattern in node.text and len(node.text) < 200:  # Avoid large blocks
                patterns.append({
                    'pattern': pattern,
                    'risk': risk,
                    'line': node.start_line,
                    'code': node.text.strip(),
                    'severity': 'high' if 'injection' in risk else 'medium'
                })
        
        # Recurse
        for child in node.children:
            self._find_patterns_recursive(child, patterns, unsafe_dict, language)
