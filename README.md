
# Source Code Vulnerability Analyzer

## Overview
This project is a basic static analysis tool designed to scan Python source code for common web application security vulnerabilities. The analyzer focuses on detecting insecure function usage, unsanitized user inputs, SQL injection patterns, and potential Remote Code Execution (RCE) risks.

## Features
- **Detection of Dangerous Functions:** Flags the use of functions such as `eval` and `exec`.
- **Insecure Module Function Usage:** Identifies risky methods from modules like `os`, `subprocess`, and `pickle`.
- **SQL Injection Warning:** Checks for SQL execution patterns built using string concatenation or f-strings.
- **Input Sanitization Check:** Alerts when unsanitized input from the `input()` function is used.
- **AST-Based Analysis:** Utilizes Python’s `ast` module to parse and analyze code.

## Installation
1. Ensure you have Python 3 installed.
2. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/source-code-vuln-analyzer.git
## Usage
1. Navigate to the project directory: ```cd sourceCodeAnalyzer```
2. Run the script ```python3 SCA.py your_code.py```
3. If you want to enter the code manually ```python3 SCA.py```
   3a. Enter your code in the terminal. End your input by entering an empty line.
