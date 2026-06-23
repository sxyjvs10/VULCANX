import re
import json
import os
import urllib.parse

class SourceMapExtractor:
    def __init__(self, session_manager):
        self.session_manager = session_manager
        self.map_regex = re.compile(r'//#\s*sourceMappingURL=(.+?\.map)(?:\s|$)')

    def extract(self, js_url, js_content, output_dir="crawled_data/reconstructed_source"):
        """
        Parses JS content for source maps, downloads them, and reconstructs the original source.
        """
        matches = self.map_regex.findall(js_content)
        map_urls = []
        
        # Also try appending .map to the URL as a fallback
        fallback_map = js_url + ".map"
        
        if matches:
            for match in matches:
                # Handle relative URLs in sourceMappingURL
                map_url = urllib.parse.urljoin(js_url, match)
                map_urls.append(map_url)
        else:
            # Try fallback
            map_urls.append(fallback_map)

        for map_url in map_urls:
            try:
                # print(f"[*] Attempting to fetch Source Map: {map_url}")
                resp = self.session_manager.get(map_url)
                if resp and resp.status_code == 200:
                    try:
                        map_data = json.loads(resp.text)
                        return self._reconstruct_source(js_url, map_data, output_dir)
                    except json.JSONDecodeError:
                        pass # Not a valid source map
            except Exception as e:
                pass
        
        return {}

    def _reconstruct_source(self, base_url, map_data, output_dir):
        sources = map_data.get('sources', [])
        sources_content = map_data.get('sourcesContent', [])
        
        if not sources or not sources_content:
            return
            
        print(f"[+] Reconstructing {len(sources)} original source files from {base_url} source map...")
        os.makedirs(output_dir, exist_ok=True)
        
        domain = urllib.parse.urlparse(base_url).netloc.replace(":", "_")
        base_dir = os.path.join(output_dir, domain)
        
        extracted_count = 0
        reconstructed_files = {}
        for i, source_path in enumerate(sources):
            try:
                content = sources_content[i] if i < len(sources_content) else None
                if not content:
                    continue
                
                # Clean up paths (remove webpack:/// prefix, clean traversing)
                clean_path = source_path.replace("webpack:///", "").replace("webpack://", "")
                clean_path = clean_path.lstrip("./").lstrip("/")
                
                # Prevent directory traversal in save path
                safe_path = os.path.abspath(os.path.join(base_dir, clean_path))
                if not safe_path.startswith(os.path.abspath(base_dir)):
                    continue
                    
                os.makedirs(os.path.dirname(safe_path), exist_ok=True)
                
                with open(safe_path, 'w', encoding='utf-8') as f:
                    f.write(content)
                
                # Save to dictionary for scanning
                virtual_url = f"webpack://{domain}/{clean_path}"
                reconstructed_files[virtual_url] = content
                
                extracted_count += 1
            except Exception as e:
                pass
                
        if extracted_count > 0:
            print(f"  -> Successfully extracted {extracted_count} original files to {base_dir}/")
            
        return reconstructed_files
