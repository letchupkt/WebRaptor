import os
import time
from datetime import datetime
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.common.exceptions import WebDriverException
from colorama import Fore, Style
from core.config import Config
from urllib.parse import urlparse

author = "LakshmikanthanK (@letchu_pkt)"
version = "2.1"


def ensure_reports_dir():
    """Ensure the reports directory exists"""
    if not os.path.exists('reports/screenshots'):
        os.makedirs('reports/screenshots')

def get_screenshot_filename(target):
    """Generate a filename for the screenshot"""
    domain = urlparse(target).netloc.replace(':', '_').replace('/', '_')
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"reports/screenshots/{domain}_{timestamp}.png"

def init_webdriver():
    """Initialize a headless Chrome webdriver"""
    options = Options()
    options.add_argument('--headless')
    options.add_argument('--no-sandbox')
    options.add_argument('--disable-dev-shm-usage')
    options.add_argument('--window-size=1920,1080')
    
    # Set user agent to avoid bot detection
    options.add_argument('user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36')
    
    try:
        driver = webdriver.Chrome(options=options)
        return driver
    except WebDriverException as e:
        print(f"{Fore.RED}[-] WebDriver initialization failed: {e}{Style.RESET_ALL}")
        return None

def capture_screenshot(target, driver):
    """Capture screenshot of target URL"""
    try:
        driver.get(target)
        
        # Wait for page to load
        time.sleep(3)
        
        # Scroll to bottom to trigger lazy-loaded content
        driver.execute_script("window.scrollTo(0, document.body.scrollHeight);")
        time.sleep(1)
        
        # Take screenshot
        filename = get_screenshot_filename(target)
        driver.save_screenshot(filename)
        return filename
    except Exception as e:
        print(f"{Fore.RED}[-] Screenshot failed: {e}{Style.RESET_ALL}")
        return None

def run(target):
    print(f"{Fore.CYAN}[Screenshot] Capturing screenshot of {target}...{Style.RESET_ALL}")
    
    ensure_reports_dir()
    driver = init_webdriver()
    
    if not driver:
        Config().add_result('screenshot', 'Failed to initialize browser')
        return
    
    try:
        filename = capture_screenshot(target, driver)
        
        if filename:
            print(f"{Fore.GREEN}[+] Screenshot saved to {filename}{Style.RESET_ALL}")
            # Store relative path in config
            rel_path = os.path.join('screenshots', os.path.basename(filename))
            Config().add_result('screenshot', f'Screenshot captured: {rel_path}')
            
            # Add full path to config for report generation
            if not hasattr(Config, 'screenshots'):
                Config.screenshots = []
            Config.screenshots.append(filename)
        else:
            print(f"{Fore.RED}[-] Failed to capture screenshot{Style.RESET_ALL}")
            Config().add_result('screenshot', 'Failed to capture screenshot')
    
    finally:
        driver.quit()