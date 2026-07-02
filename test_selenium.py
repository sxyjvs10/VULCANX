from selenium import webdriver
from selenium.webdriver.chrome.options import Options
import time

opts = Options()
opts.add_argument('--headless=new')
opts.add_argument('--no-sandbox')
driver = webdriver.Chrome(options=opts)
driver.get("data:text/html,<html><body></body></html>")

driver.execute_script("window.__vulcanx_cmd = {action: 'clear_findings'};")
cmd = driver.execute_script("return window.__vulcanx_cmd || null;")
print("RETURNED CMD:", cmd, type(cmd))
if cmd:
    print("ACTION IS:", cmd.get('action'))
driver.quit()
