import time
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By

from selenium.webdriver.chrome.service import Service

chrome_opts = Options()
chrome_opts.add_argument("--headless=new")
chrome_opts.add_argument("--no-sandbox")
chrome_opts.add_argument("--disable-dev-shm-usage")
chrome_opts.add_argument("--ignore-certificate-errors")
chrome_opts.set_capability('goog:loggingPrefs', {'browser': 'ALL'})

print("[*] Starting browser...")
service = Service(executable_path="/usr/bin/chromedriver")
driver = webdriver.Chrome(options=chrome_opts, service=service)

try:
    with open("payloads/aes_live.js", 'r') as f:
        js_code = f.read()
    driver.execute_cdp_cmd('Page.addScriptToEvaluateOnNewDocument', {'source': js_code})

    url = "https://uat.mahofin.in/Mahofin_Audit/Rbia/AlertUpload"
    print(f"[*] Navigating to {url}")
    driver.get(url)
    time.sleep(3)

    print("[*] Page loaded. Checking logs before interaction...")
    for entry in driver.get_log('browser'):
        print(f"LOG: {entry['message']}")

    print("[*] Attempting to interact with the page to trigger AES...")
    
    # Try to find common input fields and buttons
    try:
        inputs = driver.find_elements(By.TAG_NAME, "input")
        for inp in inputs:
            if inp.is_displayed() and inp.is_enabled():
                try:
                    inp.send_keys("test_input")
                except:
                    pass
        
        buttons = driver.find_elements(By.TAG_NAME, "button")
        for btn in buttons:
            if btn.is_displayed() and btn.is_enabled():
                try:
                    btn.click()
                    time.sleep(1)
                except:
                    pass
    except Exception as e:
        print(f"Interaction error: {e}")

    # If there's a login function we could call it directly:
    try:
        driver.execute_script("if(typeof Login === 'function') Login();")
        driver.execute_script("if(typeof Submit === 'function') Submit();")
        driver.execute_script("if(typeof checkLogin === 'function') checkLogin();")
        driver.execute_script("if(typeof encrypt === 'function') encrypt('test');")
    except:
        pass
        
    time.sleep(3)
    
    print("[*] Checking logs after interaction...")
    for entry in driver.get_log('browser'):
        print(f"LOG: {entry['message']}")

finally:
    driver.quit()
    print("[*] Done.")
