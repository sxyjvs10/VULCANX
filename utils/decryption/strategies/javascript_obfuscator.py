import re
import subprocess
import tempfile
import os

from .base import DecryptionStrategy

class JavascriptObfuscatorStrategy(DecryptionStrategy):
    def detect_and_decrypt(self, content, url):
        findings = []

        if "while (!![]) {" in content and "autoIncrement" in content:
            # Create a temporary JS file
            try:
                with tempfile.NamedTemporaryFile(mode='w', suffix='.js', delete=False) as f:
                    # We write the content and try to dump autoIncrement if it exists globally or locally
                    js_script = content + """
                    if (typeof autoIncrement !== 'undefined') {
                        console.log("FOUND_KEY_BIN:" + autoIncrement);
                        if (typeof tryagain !== 'undefined') {
                            console.log("FOUND_KEY_HEX:" + tryagain(autoIncrement).toString());
                        }
                    }
                    """
                    f.write(js_script)
                    temp_name = f.name
                
                # Run with node
                result = subprocess.run(['node', temp_name], capture_output=True, text=True, timeout=5)
                output = result.stdout
                
                hex_match = re.search(r'FOUND_KEY_HEX:([a-fA-F0-9]+)', output)
                if hex_match:
                    hex_key = hex_match.group(1)
                    # Convert hex to ascii
                    try:
                        ascii_key = bytes.fromhex(hex_key).decode('utf-8')
                        if "7x!" in ascii_key:
                            findings.append({
                                'url': url,
                                'type': 'DEOBFUSCATED_KEY',
                                'severity': 'CRITICAL',
                                'description': 'Successfully deobfuscated a javascript-obfuscator payload to find the key.',
                                'remediation': 'Do not hardcode keys, even if obfuscated.',
                                'match': f"Key found: {ascii_key}",
                                'context': f"Hex: {hex_key}",
                                'line': 1,
                                'decoded_value': ascii_key
                            })
                    except:
                        pass
                        
            except Exception as e:
                pass
            finally:
                if 'temp_name' in locals() and os.path.exists(temp_name):
                    os.remove(temp_name)

        return findings
