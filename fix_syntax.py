import re

with open('core/engine.py', 'r') as f:
    content = f.read()

content = content.replace(r"r'\.innerHTML\s*=\s*[^'\"][^;]*'", r"r'\.innerHTML\s*=\s*[^\\'\"\\`][^;]*'")
content = content.replace(r"r'\.outerHTML\s*=\s*[^'\"][^;]*'", r"r'\.outerHTML\s*=\s*[^\\'\"\\`][^;]*'")
content = content.replace(r"r'document\.write(?:ln)?\s*\(\s*[^'\"][^)]*\)'", r"r'document\.write(?:ln)?\s*\(\s*[^\\'\"\\`][^)]*\)'")
content = content.replace(r"r'setTimeout\s*\(\s*[^'\"][^,]*\s*,'", r"r'setTimeout\s*\(\s*[^\\'\"\\`][^,]*\s*,'")
content = content.replace(r"r'setInterval\s*\(\s*[^'\"][^,]*\s*,'", r"r'setInterval\s*\(\s*[^\\'\"\\`][^,]*\s*,'")
content = content.replace(r"r'(?:executeSql|db\.transaction)\s*\(\s*['\"](?:SELECT|INSERT|UPDATE|DELETE)[^,]+['\"]\s*\+'", r"r'(?:executeSql|db\.transaction)\s*\(\s*[\'\"](?:SELECT|INSERT|UPDATE|DELETE)[^,]+[\'\"]\s*\+'")
content = content.replace(r"r'window\.addEventListener\s*\(\s*['\"]message['\"]\s*,\s*(?:function|\([^)]*\)\s*=>)\s*\{(?![^}]+origin)'", r"r'window\.addEventListener\s*\(\s*[\'\"]message[\'\"]\s*,\s*(?:function|\([^)]*\)\s*=>)\s*\{(?![^}]+origin)'")
content = content.replace(r"r'(?:localStorage|sessionStorage)\.setItem\s*\(\s*['\"](?:password|secret|token|auth|key|session)['\"]'", r"r'(?:localStorage|sessionStorage)\.setItem\s*\(\s*[\'\"](?:password|secret|token|auth|key|session)[\'\"]'")
content = content.replace(r"r'SELECT\s+.*?\s+FROM\s+.*?(?:WHERE\s+.*?=)?\s*['\"]?\s*\+'", r"r'SELECT\s+.*?\s+FROM\s+.*?(?:WHERE\s+.*?=)?\s*[\'\"]?\s*\+'")
content = content.replace(r"r'['\"](?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3})['\"]'", r"r'[\'\"](?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3})[\'\"]'")
content = content.replace(r"r'(?i)(?:password|passwd|pwd)\s*[:=]\s*['\"][^'\"]+['\"]'", r"r'(?i)(?:password|passwd|pwd)\s*[:=]\s*[\'\"][^\'\"]+[\'\"]'")

with open('core/engine.py', 'w') as f:
    f.write(content)
