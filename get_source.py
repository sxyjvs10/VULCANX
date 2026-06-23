import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from core.behavior import SessionManager

def get_page_source(url):
    session_manager = SessionManager(use_browser=True)
    response = session_manager.get(url)
    if response:
        print(response.text)
    session_manager.close()

if __name__ == "__main__":
    get_page_source("https://mac.mactech.net.in/MFI_AUTOMATION/MFWebApp/userdetails")
