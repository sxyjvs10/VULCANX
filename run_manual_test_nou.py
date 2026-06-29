import sys
from vulcanx import *
import threading
import time

def run_test():
    analyzer = Analyzer(vuln_db=VulnerabilityDB())
    interceptor = LiveBrowserInterceptor(
        analyzer,
        scope_extra=[],
        har_out=None,
        dom_sinks=True
    )
    print("Starting interceptor without start_url...")
    t = threading.Thread(target=interceptor.start, args=(None,), daemon=True)
    t.start()
    
    # Wait for driver to initialize
    for _ in range(20):
        if hasattr(interceptor, 'driver') and interceptor.driver:
            break
        time.sleep(0.5)
        
    print("Driver initialized. Getting example.com...")
    interceptor.driver.get("http://example.com")
    
    time.sleep(3)
    print("Current URL:", interceptor.driver.current_url)
    print("Scope Root Host:", interceptor.scope.root_host)
    
    interceptor.running = False
    interceptor.driver.quit()

run_test()
