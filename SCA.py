
import ast
import sys

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

def main():
    if len(sys.argv) > 1:
        file_path = sys.argv[1]
        try:
            with open(file_path, "r") as f:
                user_code = f.read()
        except Exception as e:
            print(f"Error reading file {file_path}: {e}")
            return
    else:
        print("Enter your code below. End input with an empty line:")
        user_lines = []
        while True:
            try:
                line = input()
            except EOFError:
                break
            if line.strip() == "":
                break
            user_lines.append(line)
        user_code = "\n".join(user_lines)

    issues = analyze_code(user_code)
    if issues and issues[0] != "No potential vulnerabilities detected.":
        print("Vulnerability Analysis Report:")
        for issue in issues:
            print(issue)
    else:
        print("Your code is safe!")

if __name__ == "__main__":
    main()
