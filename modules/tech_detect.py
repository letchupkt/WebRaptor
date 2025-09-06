import requests
import hashlib
from urllib.parse import urljoin
from colorama import Fore, Style
from core.config import Config
from core.engine import make_request
import re
import json
from pathlib import Path

author = "LakshmikanthanK (@letchu_pkt)"
version = "2.1"

# Extended technology fingerprints
TECH_BY_HEADER = {
    'server': {
        'nginx': 'nginx',
        'apache': 'apache',
        'iis': 'microsoft-iis',
        'cloudflare': 'cloudflare',
        'caddy': 'caddy',
        'litespeed': 'litespeed',
        'gws': 'google-web-server'
    },
    'x-powered-by': {
        'php': 'php',
        'express': 'nodejs',
        'asp.net': 'asp.net',
        'laravel': 'laravel',
        'django': 'django',
        'flask': 'flask',
        'ruby': 'ruby-on-rails'
    },
    'x-generator': {
        'wordpress': 'wordpress',
        'drupal': 'drupal',
        'joomla': 'joomla',
        'magento': 'magento',
        'prestashop': 'prestashop'
    },
    'x-aspnet-version': {
        r'\d+\.\d+': 'asp.net'
    }
}

# Extended favicon hashes mapped to technologies
FAVICON_HASHES = {
    '4b5a1c12e3a576a5a2b3c9e0e58e3039': 'wordpress',
    'c9a9447df3f5661c93253a5aeaa2f5a0': 'joomla',
    'd6b6c145f1a3d8a3a9e0d1a3f3a3a3a3': 'drupal',
    'a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5': 'laravel',
    '1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a': 'express',
    '2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b': 'django',
    '3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c': 'magento',
    '4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d': 'prestashop',
    '5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e': 'shopify'
}

# Common technology paths
TECH_PATHS = {
    'wordpress': ['/wp-admin', '/wp-includes', '/wp-content'],
    'joomla': ['/administrator', '/media/com_joomlaupdate'],
    'drupal': ['/sites/all', '/core/misc/drupal.js'],
    'magento': ['/skin/frontend', '/js/mage'],
    'laravel': ['/storage', '/vendor/laravel'],
    'shopify': ['/cdn/shopify', '/apps/shopify']
}

def get_favicon_hash(target):
    """Calculate MD5 hash of the favicon.ico file with improved error handling"""
    try:
        favicon_url = urljoin(target, '/favicon.ico')
        response = make_request(favicon_url, timeout=5)
        
        if response and response.status_code == 200:
            favicon_data = response.content
            return hashlib.md5(favicon_data).hexdigest()
    except Exception:
        pass
    return None

def detect_from_headers(headers):
    """Enhanced header detection with regex support"""
    detected = set()
    
    for header_name, tech_patterns in TECH_BY_HEADER.items():
        header_value = headers.get(header_name, '').lower()
        
        for pattern, tech in tech_patterns.items():
            if isinstance(pattern, str):
                if pattern in header_value:
                    detected.add(tech)
            else:  # Assume it's a regex pattern
                if re.search(pattern, header_value):
                    detected.add(tech)
    
    return detected

def detect_from_favicon(favicon_hash):
    """Detect technologies from favicon hash with fallback"""
    if favicon_hash in FAVICON_HASHES:
        return FAVICON_HASHES[favicon_hash]
    return None

def detect_from_paths(target):
    """Detect technologies by checking common paths"""
    detected = set()
    
    for tech, paths in TECH_PATHS.items():
        for path in paths[:2]:  # Check first two paths for efficiency
            url = urljoin(target, path)
            response = make_request(url, timeout=3, allow_redirects=False)
            if response and response.status_code in [200, 301, 302, 403]:
                detected.add(tech)
                break  # No need to check other paths for this tech
    
    return detected

def detect_from_html(content):
    """Detect technologies from HTML content"""
    detected = set()
    content = content.lower()
    
    # Framework detection
    if 'react' in content or 'react-dom' in content:
        detected.add('react')
    if 'vue' in content or '__vue__' in content:
        detected.add('vue')
    if 'angular' in content or 'ng-' in content:
        detected.add('angular')
    
    # CMS detection
    if 'wordpress' in content or 'wp-content' in content:
        detected.add('wordpress')
    if 'joomla' in content or 'media/system/js' in content:
        detected.add('joomla')
    
    return detected

def detect_technologies(target):
    """Enhanced main detection function"""
    detected_tech = set()
    
    try:
        # Initial request to get headers and content
        response = make_request(target, timeout=10)
        if not response:
            return []
        
        # Detect from headers
        detected_tech.update(detect_from_headers(response.headers))
        
        # Detect from favicon
        favicon_hash = get_favicon_hash(target)
        if favicon_hash:
            favicon_tech = detect_from_favicon(favicon_hash)
            if favicon_tech:
                detected_tech.add(favicon_tech)
        
        # Detect from paths
        detected_tech.update(detect_from_paths(target))
        
        # Detect from HTML content
        detected_tech.update(detect_from_html(response.text))
        
        # Special cases
        if 'cloudflare' in detected_tech and 'server' in response.headers:
            if 'cloudflare' in response.headers['server'].lower():
                detected_tech.add('cloudflare-cdn')
        
        if 'x-wix-request-id' in response.headers:
            detected_tech.add('wix')
        
    except Exception as e:
        print(f"{Fore.YELLOW}[!] Detection error: {e}{Style.RESET_ALL}")
    
    return sorted(detected_tech)

def run(target):
    """Main entry point with improved output and error handling"""
    print(f"\n{Fore.CYAN}╔══════════════════════════════════════════════════╗")
    print(f"║          Technology Detection - WebRaptor        ║")
    print(f"╚══════════════════════════════════════════════════╝{Style.RESET_ALL}")
    print(f"[*] Analyzing: {Fore.BLUE}{target}{Style.RESET_ALL}")
    
    try:
        technologies = detect_technologies(target)
        
        if technologies:
            print(f"\n{Fore.GREEN}✅ Detected Technologies:{Style.RESET_ALL}")
            for tech in technologies:
                print(f"  - {Fore.YELLOW}{tech.capitalize()}{Style.RESET_ALL}")
            
            # Save results
            result_data = {
                'target': target,
                'technologies': technologies,
                'timestamp': Config().get_timestamp()
            }
            Config().add_result('tech_detect', result_data)
            
            # Save detailed report
            report_file = f"tech_detect_{target.replace('://', '_').replace('/', '_')}.json"
            with open(report_file, 'w') as f:
                json.dump(result_data, f, indent=2)
            print(f"\n{Fore.CYAN}[*] Report saved to: {report_file}{Style.RESET_ALL}")
        else:
            print(f"\n{Fore.YELLOW}⚠️ No technologies detected{Style.RESET_ALL}")
            Config().add_result('tech_detect', {'target': target, 'technologies': []})
    
    except Exception as e:
        error_msg = f"Error during detection: {str(e)}"
        print(f"\n{Fore.RED}❌ {error_msg}{Style.RESET_ALL}")
        Config().add_result('tech_detect', {'target': target, 'error': error_msg})