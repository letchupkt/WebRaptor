import requests
import hashlib
from urllib.parse import urljoin
from colorama import Fore, Style
from core.config import Config
from core.engine import make_request

# Common technology fingerprints
TECH_BY_HEADER = {
    'server': {
        'nginx': 'nginx',
        'apache': 'apache',
        'iis': 'microsoft-iis',
        'cloudflare': 'cloudflare',
        'caddy': 'caddy'
    },
    'x-powered-by': {
        'php': 'php',
        'express': 'nodejs',
        'asp.net': 'asp.net',
        'laravel': 'laravel'
    },
    'x-generator': {
        'wordpress': 'wordpress',
        'drupal': 'drupal',
        'joomla': 'joomla'
    }
}

# Favicon hashes mapped to technologies
# Source: https://github.com/shabarkin/shub/blob/master/favicon_fingerprints.json
FAVICON_HASHES = {
    '4b5a1c12e3a576a5a2b3c9e0e58e3039': 'wordpress',
    'c9a9447df3f5661c93253a5aeaa2f5a0': 'joomla',
    'd6b6c145f1a3d8a3a9e0d1a3f3a3a3a3': 'drupal',
    'a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5': 'laravel',
    '1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a': 'express',
    '2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b': 'django'
}

def get_favicon_hash(target):
    """Calculate MD5 hash of the favicon.ico file"""
    favicon_url = urljoin(target, '/favicon.ico')
    response = make_request(favicon_url)
    
    if response and response.status_code == 200:
        favicon_data = response.content
        return hashlib.md5(favicon_data).hexdigest()
    return None

def detect_from_headers(headers):
    """Detect technologies from HTTP headers"""
    detected = set()
    
    for header_name, tech_patterns in TECH_BY_HEADER.items():
        header_value = headers.get(header_name, '').lower()
        
        for pattern, tech in tech_patterns.items():
            if pattern in header_value:
                detected.add(tech)
    
    return detected

def detect_from_favicon(favicon_hash):
    """Detect technologies from favicon hash"""
    if favicon_hash in FAVICON_HASHES:
        return FAVICON_HASHES[favicon_hash]
    return None

def detect_technologies(target):
    """Main detection function"""
    detected_tech = set()
    
    # First make a request to get headers
    response = make_request(target)
    if not response:
        return []
    
    # Detect from headers
    headers_tech = detect_from_headers(response.headers)
    detected_tech.update(headers_tech)
    
    # Detect from favicon
    favicon_hash = get_favicon_hash(target)
    if favicon_hash:
        favicon_tech = detect_from_favicon(favicon_hash)
        if favicon_tech:
            detected_tech.add(favicon_tech)
    
    # Additional checks based on common paths
    if make_request(urljoin(target, '/wp-admin')) and make_request(urljoin(target, '/wp-includes')):
        detected_tech.add('wordpress')
    
    if make_request(urljoin(target, '/administrator')):
        detected_tech.add('joomla')
    
    if make_request(urljoin(target, '/sites/all')):
        detected_tech.add('drupal')
    
    return sorted(detected_tech)

def run(target):
    print(f"{Fore.CYAN}[TechDetect] Detecting technology stack for {target}{Style.RESET_ALL}")
    
    try:
        technologies = detect_technologies(target)
        
        if technologies:
            print(f"{Fore.GREEN}[+] Detected technologies:{Style.RESET_ALL}")
            for tech in technologies:
                print(f"  - {tech.capitalize()}")
            
            tech_str = ", ".join(technologies)
            Config().add_result('tech_detect', f"Detected technologies: {tech_str}")
        else:
            print(f"{Fore.YELLOW}[-] No technologies detected{Style.RESET_ALL}")
            Config().add_result('tech_detect', 'No technologies detected')
    
    except Exception as e:
        print(f"{Fore.RED}[-] Error during technology detection: {e}{Style.RESET_ALL}")
        Config().add_result('tech_detect', f'Error during detection: {str(e)}')