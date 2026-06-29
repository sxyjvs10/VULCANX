import sys
import os
sys.path.insert(0, os.path.abspath('.'))
from core.vdb import VulnerabilityDB
from utils.component_checker import ComponentChecker

db = VulnerabilityDB()
checker = ComponentChecker(db)

content = """
    <!-- Test Vulnerable Components -->
    <script src="https://code.jquery.com/jquery-3.4.0.min.js"></script>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.1.1/css/bootstrap.min.css">
    <meta name="generator" content="WordPress 5.8.1">
"""

findings = checker.check("http://127.0.0.1:8081/", content)
print("Findings:")
for f in findings:
    print(f)
