import time
from seleniumwire import webdriver
from selenium.webdriver.firefox.options import Options as FirefoxOptions
from selenium.webdriver.firefox.service import Service as FirefoxService
from webdriver_manager.firefox import GeckoDriverManager

def interceptor(request):
    if '/api/test' in request.url:
        request.create_response(
            status_code=200,
            headers={'Content-Type': 'text/plain'},
            body=b"Hello from interceptor!"
        )

opts = FirefoxOptions()
opts.add_argument('-headless')
service = FirefoxService(GeckoDriverManager().install())
driver = webdriver.Firefox(service=service, options=opts)
driver.request_interceptor = interceptor

driver.get("http://example.com")
# use async script to fetch
res = driver.execute_async_script("""
    var cb = arguments[arguments.length - 1];
    fetch('/api/test').then(r => r.text()).then(t => cb(t)).catch(e => cb('ERROR: ' + e));
""")
print("FETCH RESULT:", res)
driver.quit()
