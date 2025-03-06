import ast

DANGEROUS_FUNCTIONS = {"eval", "exec"}
DANGEROUS_METHODS = {"system", "popen", "Popen", "call", "run"}

class VulnerabilityDetector(ast.NodeVisitor):
    def __init__(self):
        self.issues = []

    def visit_Call(self, node):
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
            if func_name in DANGEROUS_FUNCTIONS:
                self.issues.append(f"[Line {node.lineno}] Dangerous function '{func_name}()' used. Consider alternatives.")
        elif isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name):
                module_name = node.func.value.id
                method_name = node.func.attr
                if module_name == "os" and method_name in {"system", "popen"}:
                    self.issues.append(f"[Line {node.lineno}] '{module_name}.{method_name}()' used. This can lead to RCE.")
                elif module_name == "subprocess" and method_name in {"Popen", "call", "run"}:
                    self.issues.append(f"[Line {node.lineno}] '{module_name}.{method_name}()' used. Validate inputs to prevent RCE.")
                elif module_name == "pickle" and method_name in {"loads", "load"}:
                    self.issues.append(f"[Line {node.lineno}] '{module_name}.{method_name}()' used on untrusted input. This is unsafe.")
                elif method_name == "execute":
                    if node.args:
                        if isinstance(node.args[0], ast.BinOp):
                            self.issues.append(f"[Line {node.lineno}] SQL execution with string concatenation detected. Use parameterized queries.")
                        elif isinstance(node.args[0], ast.JoinedStr):
                            self.issues.append(f"[Line {node.lineno}] SQL execution with f-string detected. Verify proper sanitization.")
        self.generic_visit(node)

    def visit_JoinedStr(self, node):
        self.issues.append(f"[Line {node.lineno}] f-string used. Verify that interpolated variables are properly sanitized.")
        self.generic_visit(node)

    def visit_Name(self, node):
        if node.id == "input":
            self.issues.append(f"[Line {node.lineno}] 'input()' function used. Ensure inputs are validated and sanitized.")
        self.generic_visit(node)

    def visit_Attribute(self, node):
        self.generic_visit(node)

def analyze_code(code):
    try:
        tree = ast.parse(code)
        detector = VulnerabilityDetector()
        detector.visit(tree)
        return detector.issues if detector.issues else ["No potential vulnerabilities detected."]
    except Exception as e:
        return [f"Error analyzing code: {e}"]

if __name__ == "__main__":
    sample_code = """
import os, subprocess, pickle
user_input = input("Enter command: ")
eval(user_input)
exec(user_input)
os.system(user_input)
subprocess.Popen(user_input)
query = "SELECT * FROM users WHERE id = " + user_input
cursor.execute(query)
data = pickle.loads(user_input)
message = f"User provided: {user_input}"
"""
    issues = analyze_code(sample_code)
    print("Vulnerability Analysis Report:")
    for issue in issues:
        print(issue)
