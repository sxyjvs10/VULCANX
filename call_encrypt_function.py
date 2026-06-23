
import sys
import os
import time
from selenium.webdriver.common.by import By
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from core.behavior import SessionManager

def call_encrypt_function(url):
    session_manager = SessionManager(use_browser=True, live_exploit_script="payloads/aes_live.js")
    driver = session_manager.driver
    
    if not driver:
        print("[-] Browser initialization failed.")
        return

    try:
        print(f"[*] Navigating to {url}...")
        driver.get(url)
        time.sleep(3)

        print("[*] Injecting interception script...")
        session_manager.inject_script("payloads/aes_live.js")
        time.sleep(1)

        print("[*] Calling EncryptAPIReq function with test plaintext...")
        driver.execute_script('EncryptAPIReq("test_plaintext_12345");')
        time.sleep(2)

        print("\n" + "="*60)
        print("                CAPTURED CONSOLE LOGS")
        print("="*60 + "\n")
        
        logs = driver.get_log('browser')
        if not logs:
            print("[-] No logs were captured.")
        else:
            for entry in logs:
                print(f"[{entry['level']}] {entry['message']}")

    except Exception as e:
        print(f"[-] An error occurred: {e}")
    finally:
        session_manager.close()


if __name__ == "__main__":
    call_encrypt_function("https://mac.mactech.net.in/MFI_AUTOMATION/MFWebApp/userdetails")
