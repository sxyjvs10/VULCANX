from selenium import webdriver
from selenium.webdriver.firefox.options import Options
from selenium.webdriver.firefox.service import Service
from webdriver_manager.firefox import GeckoDriverManager
import base64
import time

opts = Options()
opts.add_argument('-headless')
service = Service(GeckoDriverManager().install())
driver = webdriver.Firefox(service=service, options=opts)

driver.get("data:text/html,<html><body><h1>Test</h1></body></html>")

list_html = "<details><summary>Test</summary><div>Test</div></details>"
list_html_b64 = base64.b64encode(list_html.encode('utf-8')).decode('utf-8')

js_code = f"""
try {{
    var w = document.getElementById('vulcanx-widget');
    if (!w) {{
        w = document.createElement('div');
        w.id = 'vulcanx-widget';
        w.style.position = 'fixed';
        w.style.bottom = '20px';
        w.style.right = '20px';
        w.style.width = '450px';
        w.style.height = '400px';
        w.style.backgroundColor = 'rgba(10, 10, 10, 0.95)';
        
        var header = document.createElement('div');
        var title = document.createElement('strong');
        title.innerText = 'VULCANX LIVE FEED';
        header.appendChild(title);
        w.appendChild(header);
        
        var list = document.createElement('div');
        list.id = 'vulcanx-list';
        w.appendChild(list);
        
        if (document.body) {{
            document.body.appendChild(w);
        }} else {{
            document.documentElement.appendChild(w);
        }}
    }}
    
    var listEl = document.getElementById('vulcanx-list');
    if (listEl) {{
        listEl.innerHTML = decodeURIComponent(escape(window.atob('{list_html_b64}')));
    }}
    return "SUCCESS";
}} catch(e) {{
    return "ERROR: " + e.toString();
}}
"""

res = driver.execute_script(js_code)
print("INJECTION RESULT:", res)

time.sleep(2)

# Verify if the widget is there
html = driver.page_source
if "VULCANX LIVE FEED" in html:
    print("WIDGET FOUND IN HTML")
else:
    print("WIDGET NOT FOUND")

driver.quit()
