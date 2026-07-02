from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
import time

opts = Options()
opts.add_argument('--headless=new')
opts.add_argument('--no-sandbox')
driver = webdriver.Chrome(options=opts)
try:
    driver.get("http://zero.webappsecurity.com/")
    print("Home Cookies:", driver.get_cookies())
    
    # login
    driver.get("http://zero.webappsecurity.com/login.html")
    driver.find_element(By.ID, "user_login").send_keys("username")
    driver.find_element(By.ID, "user_password").send_keys("password")
    driver.find_element(By.NAME, "submit").click()
    time.sleep(1)
    
    print("Login Cookies:", driver.get_cookies())
    print("LocalStorage:", driver.execute_script("return window.localStorage.length;"))
    print("SessionStorage:", driver.execute_script("return window.sessionStorage.length;"))
except Exception as e:
    print(e)
finally:
    driver.quit()
