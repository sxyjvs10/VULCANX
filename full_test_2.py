import sys
import threading
import time
from vulcanx import *
from core.live_browser import LiveBrowserInterceptor

def run_test():
    analyzer = Analyzer(vuln_db=VulnerabilityDB())
    interceptor = LiveBrowserInterceptor(
        analyzer,
        scope_extra=[],
        har_out=None,
        dom_sinks=True
    )
    
    print("[Test] Starting interceptor without start_url...")
    t = threading.Thread(target=interceptor.start, args=(None,), daemon=True)
    t.start()
    
    # Wait for driver to initialize
    while not getattr(interceptor, 'running', False):
        time.sleep(1)
        
    print("[Test] Driver initialized. Navigating to http://example.com...")
    interceptor.driver.get("http://example.com")
    
    time.sleep(5)
    print(f"[Test] Current URL: {interceptor.driver.current_url}")
    print(f"[Test] Scope Root Host: {interceptor.scope.root_host}")
    
    print("[Test] Simulating HUD fetch('/api/report')...")
    res = interceptor.driver.execute_async_script("""
        var cb = arguments[arguments.length - 1];
        fetch('/api/report').then(r => r.text()).then(t => cb(t)).catch(e => cb('ERROR: ' + e));
    """)
    print("[Test] FETCH RESULT PREVIEW:")
    print(res[:200] if res else res)
    
    interceptor.running = False
    interceptor.driver.quit()

run_test()
