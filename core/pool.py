import threading
from queue import Queue
import time
from .behavior import SessionManager

class WebDriverPool:
    """
    A thread-safe pool of SessionManagers (WebDrivers) for concurrent browser crawling.
    """
    def __init__(self, size, cookies, headers, ssl_verify, live_exploit_script=None):
        self.size = size
        self.cookies = cookies
        self.headers = headers
        self.ssl_verify = ssl_verify
        self.live_exploit_script = live_exploit_script
        self.pool = Queue(maxsize=size)
        self.active_count = 0
        self.lock = threading.Lock()

    def initialize(self):
        print(f"[*] Initializing WebDriver Pool with {self.size} browser instances...")
        for i in range(self.size):
            try:
                # Use a small delay to avoid overwhelming the system during spin-up
                time.sleep(1)
                sm = SessionManager(
                    cookies=self.cookies,
                    headers=self.headers,
                    ssl_verify=self.ssl_verify,
                    use_browser=True,
                    live_exploit_script=self.live_exploit_script
                )
                self.pool.put(sm)
                with self.lock:
                    self.active_count += 1
            except Exception as e:
                print(f"[-] Failed to initialize driver {i}: {e}")

    def get_driver(self):
        """Borrow a driver from the pool. Blocks if none are available."""
        return self.pool.get()

    def return_driver(self, driver):
        """Return a driver to the pool."""
        self.pool.put(driver)

    def close_all(self):
        """Close all drivers in the pool."""
        while not self.pool.empty():
            driver = self.pool.get()
            driver.close()
