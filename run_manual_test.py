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
    print("Starting interceptor...")
    # Add a dummy finding to test the report
    analyzer.findings.append({
        'url': 'http://example.com/test',
        'type': 'TEST_FINDING',
        'severity': 'HIGH',
        'confidence': '100%',
        'description': 'This is a test finding.',
        'remediation': 'Fix it.',
        'match': 'test',
        'context': 'test',
        'line': 0,
        'source': 'TEST'
    })
    
    t = threading.Thread(target=interceptor.start, args=("http://example.com",), daemon=True)
    t.start()
    
    # Wait for driver to initialize
    for _ in range(20):
        if hasattr(interceptor, 'driver') and interceptor.driver:
            break
        time.sleep(0.5)
        
    print("Executing fetch...")
    res = interceptor.driver.execute_async_script("""
        var cb = arguments[arguments.length - 1];
        fetch('/api/report').then(r => r.text()).then(t => cb(t)).catch(e => cb('ERROR: ' + e));
    """)
    print("FETCH RESULT PREVIEW:")
    print(res[:200] if res else res)
    interceptor.running = False
    interceptor.driver.quit()

run_test()
