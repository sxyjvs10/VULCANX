import re
import urllib.parse

class ASTDeobfuscator:
    def __init__(self):
        # We simulate AST array unrolling using regex for performance,
        # but conceptually this handles the structure of obfuscated packers.
        self.string_array_regex = re.compile(r'(?:var|let|const)\s+([a-zA-Z0-9_]+)\s*=\s*\[(.*?)\];', re.DOTALL)
        self.array_call_regex = r'{array_name}\s*\[\s*(\d+|0x[0-9a-fA-F]+)\s*\]'

    def deobfuscate(self, content):
        """
        Attempts to logically deobfuscate JavaScript by unrolling string arrays 
        and replacing their references inline.
        """
        modifications_made = False
        deobfuscated_content = content

        try:
            # 1. Find all string arrays defined in the code
            arrays = self.string_array_regex.finditer(content)
            for match in arrays:
                array_name = match.group(1)
                array_content = match.group(2)
                
                # Try to safely parse the array contents
                try:
                    # Very basic extraction - split by comma, strip quotes
                    elements = []
                    # Find all strings in quotes (single, double, or backticks)
                    string_matches = re.finditer(r'(["\'`])(.*?)\1', array_content)
                    for sm in string_matches:
                        elements.append(sm.group(2))
                    
                    if not elements:
                        continue
                        
                    # 2. Find references to this array and replace them inline
                    ref_regex = re.compile(self.array_call_regex.format(array_name=array_name))
                    
                    def replacer(m):
                        idx_str = m.group(1)
                        # Handle hex or decimal
                        idx = int(idx_str, 16) if idx_str.startswith('0x') else int(idx_str)
                        if 0 <= idx < len(elements):
                            # Ensure we output it safely quoted
                            return f'"{elements[idx]}"'
                        return m.group(0) # Keep original if out of bounds
                        
                    new_content = ref_regex.sub(replacer, deobfuscated_content)
                    if new_content != deobfuscated_content:
                        deobfuscated_content = new_content
                        modifications_made = True
                        
                except Exception:
                    continue # Skip this array if parsing fails
                    
        except Exception as e:
            pass
            
        return deobfuscated_content if modifications_made else None
