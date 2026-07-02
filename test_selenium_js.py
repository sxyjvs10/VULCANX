from selenium import webdriver
from selenium.webdriver.chrome.options import Options
import time
import os

opts = Options()
opts.add_argument('--headless=new')
opts.add_argument('--no-sandbox')
driver = webdriver.Chrome(options=opts)
try:
    url = "file://" + os.path.abspath("test_storage_loop2.html")
    driver.get(url)
    
    logs = driver.get_log('browser')
    for log in logs:
        print(log)
except Exception as e:
    print(e)
finally:
    driver.quit()
