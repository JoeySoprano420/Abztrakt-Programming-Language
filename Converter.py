import re

# Define the syntax for Abztrakt directives
directives = {
    'secure': r'<secure action="(\w+)" data="([^"]+)" key="([^"]+)" />',
    'validate': r'<validate action="(\w+)" data="([^"]+)" />',
    'assert': r'<assert action="(\w+)" user="([^"]+)" />',
    'lock': r'<lock action="(\w+)" resource="([^"]+)" policy="([^"]+)" />',
    'handle': r'<handle error="(\w+)" strategy="(\w+)" attempts="(\d+)" />',
    'recover': r'<recover error="(\w+)" action="([^"]+)" />',
    'protocol': r'<protocol name="([^"]+)" action="([^"]+)" on-error="([^"]+)">(.+?)</protocol>',
}

# Sample input Abztrakt code
code = '''
<secure action="encrypt" data="user-input" key="public-key" />
<handle error="FileNotFound" strategy="retry" attempts="3" />
<protocol name="network-recovery" action="attempt-fix" on-error="critical">
  <handle error="ConnectionLost" strategy="retry" attempts="5" />
</protocol>
'''

# Tokenize the Abztrakt code
def tokenize(code):
    tokens = []
    
    # Loop through each directive type and try matching regex patterns
    for directive, pattern in directives.items():
        for match in re.finditer(pattern, code, re.DOTALL):
            tokens.append({
                'directive': directive,
                'matches': match.groups()
            })
    return tokens

# Generate the Abstract Syntax Tree (AST)
def generate_ast(tokens):
    ast = []
    for token in tokens:
        directive = token['directive']
        matches = token['matches']
        
        if directive == 'secure':
            ast.append({
                'type': 'SecureActionNode',
                'action': matches[0],
                'data': matches[1],
                'key': matches[2]
            })
        elif directive == 'handle':
            ast.append({
                'type': 'HandleErrorNode',
                'error': matches[0],
                'strategy': matches[1],
                'attempts': int(matches[2])
            })
        elif directive == 'protocol':
            ast.append({
                'type': 'ProtocolNode',
                'name': matches[0],
                'action': matches[1],
                'on_error': matches[2],
                'sub_actions': generate_ast([{
                    'directive': 'handle', 'matches': match.groups()
                } for match in re.finditer(directives['handle'], matches[3])])
            })
    return ast

# Tokenize and generate the AST for the Abztrakt code
tokens = tokenize(code)
ast = generate_ast(tokens)

# Print the generated AST for inspection
from pprint import pprint
pprint(ast)

class AOTCompiler:
    def __init__(self):
        self.code = []
    
    def compile(self, ast):
        for node in ast:
            if node['type'] == 'SecureActionNode':
                self.compile_secure(node)
            elif node['type'] == 'ValidateActionNode':
                self.compile_validate(node)
            elif node['type'] == 'ProtocolNode':
                self.compile_protocol(node)
    
    def compile_secure(self, node):
        action = node['action']
        data = node['data']
        key = node['key']
        compiled_code = f"Secure: {action} with data {data} using key {key}"
        self.code.append(compiled_code)
    
    def compile_validate(self, node):
        action = node['action']
        data = node['data']
        compiled_code = f"Validate: {action} on data {data}"
        self.code.append(compiled_code)
    
    def compile_protocol(self, node):
        protocol_name = node['name']
        protocol_action = node['action']
        on_error = node['on_error']
        self.code.append(f"Protocol: {protocol_name} with action {protocol_action} on error {on_error}")
        
        for sub_action in node['sub_actions']:
            if sub_action['type'] == 'HandleErrorNode':
                self.compile_handle_error(sub_action)
    
    def compile_handle_error(self, node):
        error = node['error']
        strategy = node['strategy']
        attempts = node['attempts']
        self.code.append(f"HandleError: {error} with strategy {strategy} for {attempts} attempts")
    
    def get_compiled_code(self):
        return "\n".join(self.code)

# AOT Compilation
aot_compiler = AOTCompiler()
aot_compiler.compile(ast)
compiled_code = aot_compiler.get_compiled_code()
print("AOT Compiled Code:")
print(compiled_code)

class JITCompiler:
    def __init__(self):
        self.runtime_code = []
    
    def execute(self, ast):
        for node in ast:
            if node['type'] == 'HandleErrorNode':
                self.handle_error(node)
            elif node['type'] == 'ProtocolNode':
                self.handle_protocol(node)
    
    def handle_error(self, node):
        error = node['error']
        strategy = node['strategy']
        attempts = node['attempts']
        self.runtime_code.append(f"JIT Execution: Handling error {error} with strategy {strategy} for {attempts} attempts")
    
    def handle_protocol(self, node):
        protocol_name = node['name']
        protocol_action = node['action']
        self.runtime_code.append(f"JIT Execution: Executing protocol {protocol_name} with action {protocol_action}")
        
        for sub_action in node['sub_actions']:
            if sub_action['type'] == 'HandleErrorNode':
                self.handle_error(sub_action)
    
    def get_runtime_code(self):
        return "\n".join(self.runtime_code)

# JIT Execution
jit_compiler = JITCompiler()
jit_compiler.execute(ast)
runtime_code = jit_compiler.get_runtime_code()
print("JIT Executed Code:")
print(runtime_code)

class ExecutionPacket:
    def __init__(self, packet_type, action, data=None, params=None):
        self.packet_type = packet_type
        self.action = action
        self.data = data
        self.params = params

    def execute(self):
        # The execution logic will vary based on packet type
        if self.packet_type == "secure":
            print(f"Executing Secure Action: {self.action} with data {self.data}")
        elif self.packet_type == "validate":
            print(f"Validating Action: {self.action} on data {self.data}")
        elif self.packet_type == "handle":
            print(f"Handling error {self.data} with strategy {self.params['strategy']} for {self.params['attempts']} attempts")

# Packetized Execution Example
secure_packet = ExecutionPacket("secure", "encrypt", "user-input", {"key": "public-key"})
secure_packet.execute()

validate_packet = ExecutionPacket("validate", "checksum", "user-input")
validate_packet.execute()

handle_packet = ExecutionPacket("handle", "FileNotFound", {"strategy": "retry", "attempts": 3})
handle_packet.execute()

