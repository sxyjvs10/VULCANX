import sys
from vulcanx import *

analyzer = Analyzer(vuln_db=VulnerabilityDB())
interceptor = LiveBrowserInterceptor(
    analyzer,
    scope_extra=[],
    har_out=None,
    dom_sinks=True
)
print("Starting...")
interceptor.start("http://example.com")
print("Finished.")
