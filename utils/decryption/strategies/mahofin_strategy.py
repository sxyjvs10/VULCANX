import re
from .base import DecryptionStrategy

class MahofinStrategy(DecryptionStrategy):
    def detect_and_decrypt(self, content, url):
        findings = []
        
        # 1. Detect numericParts Key/IV generation (aes.js)
        numeric_key_match = re.search(r'var\s+numericParts\s*=\s*\[(\d+),\s*(\d+),\s*(\d+)\];', content)
        if numeric_key_match:
            parts = [int(numeric_key_match.group(1)), int(numeric_key_match.group(2)), int(numeric_key_match.group(3))]
            key_str = self._decode_numeric_parts(parts, 32)
            
            findings.append({
                'url': url,
                'type': 'MAHOFIN_NUMERIC_PARTS_KEY',
                'severity': 'CRITICAL',
                'description': 'Detected Mahofin-specific client-side AES key generation using numeric parts.',
                'remediation': 'Do not generate cryptographic keys on the client side. Use server-side session management.',
                'match': numeric_key_match.group(0),
                'context': f"Decoded Key: {key_str}",
                'line': content.count('\n', 0, numeric_key_match.start()) + 1,
                'decoded_value': key_str
            })

        # 2. Detect ivNumericParts (aes.js)
        numeric_iv_match = re.search(r'var\s+ivNumericParts\s*=\s*\[(\d+),\s*(\d+),\s*(\d+)\];', content)
        if numeric_iv_match:
            parts = [int(numeric_iv_match.group(1)), int(numeric_iv_match.group(2)), int(numeric_iv_match.group(3))]
            iv_str = self._decode_numeric_parts(parts, 16)
            
            findings.append({
                'url': url,
                'type': 'MAHOFIN_NUMERIC_PARTS_IV',
                'severity': 'CRITICAL',
                'description': 'Detected Mahofin-specific client-side AES IV generation using numeric parts.',
                'remediation': 'Do not generate cryptographic IVs statically on the client side.',
                'match': numeric_iv_match.group(0),
                'context': f"Decoded IV: {iv_str}",
                'line': content.count('\n', 0, numeric_iv_match.start()) + 1,
                'decoded_value': iv_str
            })

        # 3. Detect plaintext key in App.js
        plaintext_key_match = re.search(r'var\s+encryptkey\s*=\s*"([^"]+)";', content)
        if plaintext_key_match:
            key_str = plaintext_key_match.group(1)
            findings.append({
                'url': url,
                'type': 'MAHOFIN_PLAINTEXT_KEY',
                'severity': 'CRITICAL',
                'description': 'Detected hardcoded plaintext encryption key.',
                'remediation': 'Store keys securely, not in client-side source code.',
                'match': plaintext_key_match.group(0),
                'context': f"Key: {key_str}",
                'line': content.count('\n', 0, plaintext_key_match.start()) + 1,
                'decoded_value': key_str
            })

        # 4. Detect the base64/binary obfuscated key in bootstrap.min.css/JS
        obf_match = re.search(r'bin2String\s*=\s*\w+\s*=>.*?atob\s*,\s*\w+\[.*?]\(\s*atob\s*,', content, re.DOTALL)
        if obf_match:
            findings.append({
                'url': url,
                'type': 'MAHOFIN_OBFUSCATED_DOUBLE_B64_BINARY_KEY',
                'severity': 'CRITICAL',
                'description': 'Detected highly obfuscated client-side AES key generation (Double Base64 over Binary String).',
                'remediation': 'Remove client-side cryptographic key generation.',
                'match': 'bin2String + atob(atob(...)) pattern',
                'context': 'This script dynamically constructs a key like "7x!A%D*G-KaPdSgV".',
                'line': content.count('\n', 0, obf_match.start()) + 1,
                'decoded_value': '7x!A%D*G-KaPdSgV'
            })

        return findings

    def _decode_numeric_parts(self, parts, pad_length):
        res = ""
        for num in parts:
            res += chr(num % 256)
            res += chr((num // 256) % 256)
            res += chr((num // 65536) % 256)
        return res.ljust(pad_length, '0')[:pad_length]
