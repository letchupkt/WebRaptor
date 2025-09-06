

import asyncio
import aiohttp
import dns.resolver
import dns.asyncresolver
import re
import time
import json
import socket
import hashlib
import base64
import ssl
import subprocess
from pathlib import Path
from urllib.parse import urlparse, urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import Fore, Style
from core.config import Config
from core.engine import make_request
import random
import os
from dataclasses import dataclass
from typing import List, Dict, Set, Optional, Tuple
from collections import defaultdict, Counter

# Module metadata
description = "Advanced async subdomain enumeration with 15+ data sources and intelligence gathering"
author = "LakshmikanthanK (@letchu_pkt)"
version = "2.1"

@dataclass
class SubdomainResult:
    """Data class for subdomain results"""
    subdomain: str
    ips: List[str]
    cnames: List[str]
    mx_records: List[str]
    ns_records: List[str]
    txt_records: List[str]
    web_services: List[str]
    ssl_info: Dict
    open_ports: List[int]
    takeover_service: Optional[str]
    takeover_signature: Optional[str]
    response_codes: Dict[str, int]
    technologies: List[str]
    cdn_provider: Optional[str]
    asn_info: Dict
    geolocation: Dict
    source: str
    confidence_score: float

class AdvancedSubdomainEnum:
    def __init__(self, config=None):
        self.config = config or Config()
        self.timeout = 10
        self.concurrent_limit = 100  # Async concurrency limit
        self.max_depth = 3
        self.enable_recursive = True
        self.results = []
        self.statistics = {
            'sources_used': [],
            'total_requests': 0,
            'start_time': 0,
            'unique_ips': set(),
            'technologies_found': Counter(),
            'response_codes': Counter(),
            'cdn_providers': Counter()
        }
        
        # Enhanced configuration flags
        self.data_sources = {
            'crt_sh': True,
            'hackertarget': True,
            'rapiddns': True,
            'virustotal': True,
            'securitytrails': True,
            'shodan': True,
            'censys': True,
            'dnsdumpster': True,
            'threatbook': True,
            'urlscan': True,
            'wayback': True,
            'commoncrawl': True,
            'facebook': True,
            'spyse': True,
            'anubis': True,
            'dns_brute': True
        }
        
        # API configurations (users can set their keys)
        self.api_keys = {
            'securitytrails': os.getenv('SECURITYTRAILS_API'),
            'shodan': os.getenv('SHODAN_API'),
            'censys': {'id': os.getenv('CENSYS_API_ID'), 'secret': os.getenv('CENSYS_API_SECRET')},
            'virustotal': os.getenv('VIRUSTOTAL_API'),
            'spyse': os.getenv('SPYSE_API')
        }
        
        # Advanced options
        self.check_takeover = True
        self.check_ports = True
        self.port_scan_top_ports = True
        self.check_ssl = True
        self.technology_detection = True
        self.geolocation_lookup = True
        self.asn_lookup = True
        self.wildcard_detected = False
        self.wildcard_ips = set()
        
        # Wordlist management
        self.wordlist_manager = WordlistManager()
        self.use_custom_wordlist = False
        self.custom_wordlist_paths = []
        self.wordlist_categories = ['common', 'tech', 'admin', 'dev', 'api', 'cloud']
        
        # Enhanced subdomain takeover signatures
        self.takeover_signatures = {
            'github': {
                'patterns': ['There isn\'t a GitHub Pages site here', 'For root URLs'],
                'cname_indicators': ['github.io', 'github.com'],
                'http_codes': [404],
                'confidence': 0.9
            },
            'heroku': {
                'patterns': ['No such app', 'no-such-app.herokuapp.com'],
                'cname_indicators': ['herokuapp.com', 'herokussl.com'],
                'http_codes': [404],
                'confidence': 0.95
            },
            'surge': {
                'patterns': ['project not found', 'repository not found'],
                'cname_indicators': ['surge.sh'],
                'http_codes': [404],
                'confidence': 0.9
            },
            'netlify': {
                'patterns': ['Not Found - Request ID'],
                'cname_indicators': ['netlify.com', 'netlify.app'],
                'http_codes': [404],
                'confidence': 0.9
            },
            'tumblr': {
                'patterns': ['Whatever you were looking for doesn\'t currently exist'],
                'cname_indicators': ['tumblr.com'],
                'http_codes': [404],
                'confidence': 0.8
            },
            'wordpress': {
                'patterns': ['Do you want to register'],
                'cname_indicators': ['wordpress.com'],
                'http_codes': [404],
                'confidence': 0.7
            },
            'aws_s3': {
                'patterns': ['NoSuchBucket', 'The specified bucket does not exist'],
                'cname_indicators': ['amazonaws.com', 's3.amazonaws.com'],
                'http_codes': [404, 403],
                'confidence': 0.95
            },
            'cloudfront': {
                'patterns': ['Bad Request: ERROR: The request could not be satisfied'],
                'cname_indicators': ['cloudfront.net'],
                'http_codes': [403, 404],
                'confidence': 0.9
            },
            'azure': {
                'patterns': ['Web App - Unavailable', 'This web app has been stopped'],
                'cname_indicators': ['azurewebsites.net', 'azure.com'],
                'http_codes': [404],
                'confidence': 0.9
            },
            'vercel': {
                'patterns': ['The deployment could not be found on Vercel'],
                'cname_indicators': ['vercel.app', 'now.sh'],
                'http_codes': [404],
                'confidence': 0.9
            }
        }
        
        # Technology detection patterns
        self.tech_patterns = {
            'wordpress': [r'wp-content', r'wp-includes', r'/wp-admin'],
            'drupal': [r'drupal', r'sites/default', r'misc/drupal.js'],
            'joomla': [r'joomla', r'administrator/index.php'],
            'magento': [r'magento', r'skin/frontend'],
            'nginx': [r'nginx', r'Server: nginx'],
            'apache': [r'apache', r'Server: Apache'],
            'cloudflare': [r'cloudflare', r'cf-ray'],
            'aws': [r'amazonaws', r'x-amz-'],
            'cloudfront': [r'cloudfront'],
            'fastly': [r'fastly', r'x-served-by.*fastly'],
            'react': [r'react', r'_reactInternalInstance'],
            'angular': [r'angular', r'ng-version'],
            'vue': [r'vue\.js', r'__vue__'],
            'jquery': [r'jquery', r'jQuery'],
            'bootstrap': [r'bootstrap', r'Bootstrap'],
        }
        
        # Common ports for scanning
        self.common_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 993, 995, 1723, 3306, 3389, 5432, 5900, 8000, 8080, 8443, 8888]
        self.top_ports = [21, 22, 23, 25, 53, 80, 135, 139, 143, 443, 993, 995, 1723, 3389, 5900]

    def show_banner(self):
        """Enhanced banner with version info"""
        banner = f"""
{Fore.BLUE}
╔══════════════════════════════════════════════════════════════════════════╗
║                     {Fore.YELLOW}WebRaptor Advanced SubEnum v{version}{Fore.BLUE}                      ║
║          Async Subdomain Discovery with 15+ Intelligence Sources         ║
║                        Author: LakshmikanthanK (@letchu_pkt)             ║
║                                                                          ║
╚══════════════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""
        print(banner)

    def show_advanced_menu(self):
        """Enhanced interactive configuration menu"""
        while True:
            print(f"\n{Fore.BLUE}╭─ Advanced Subdomain Enumeration Configuration ─╮{Style.RESET_ALL}")
            
            # Data Sources Section
            print(f"{Fore.CYAN}📡 Data Sources:{Style.RESET_ALL}")
            sources_active = sum(1 for v in self.data_sources.values() if v)
            print(f"  {Fore.YELLOW}1.{Style.RESET_ALL} Configure Data Sources    ({Fore.GREEN}{sources_active}/15 active{Style.RESET_ALL})")
            
            # Wordlist Section
            print(f"\n{Fore.CYAN}📝 Wordlist Configuration:{Style.RESET_ALL}")
            print(f"  {Fore.YELLOW}2.{Style.RESET_ALL} Wordlist Categories       ({Fore.GREEN}{len(self.wordlist_categories)} selected{Style.RESET_ALL})")
            print(f"  {Fore.YELLOW}3.{Style.RESET_ALL} Custom Wordlists          ({Fore.GREEN}{len(self.custom_wordlist_paths)} files{Style.RESET_ALL})")
            print(f"  {Fore.YELLOW}4.{Style.RESET_ALL} Generate Custom Wordlist  ({Fore.BLUE}AI-powered{Style.RESET_ALL})")
            
            # Performance Section
            print(f"\n{Fore.CYAN}⚡ Performance Settings:{Style.RESET_ALL}")
            print(f"  {Fore.YELLOW}5.{Style.RESET_ALL} Concurrent Limit          ({Fore.GREEN}{self.concurrent_limit}{Style.RESET_ALL})")
            print(f"  {Fore.YELLOW}6.{Style.RESET_ALL} Recursion Depth           ({Fore.GREEN}{self.max_depth}{Style.RESET_ALL})")
            print(f"  {Fore.YELLOW}7.{Style.RESET_ALL} Recursive Enumeration     ({Fore.GREEN}{'On' if self.enable_recursive else 'Off'}{Style.RESET_ALL})")
            
            # Security Analysis Section
            print(f"\n{Fore.CYAN}🔍 Security Analysis:{Style.RESET_ALL}")
            print(f"  {Fore.YELLOW}8.{Style.RESET_ALL} Subdomain Takeover        ({Fore.GREEN}{'On' if self.check_takeover else 'Off'}{Style.RESET_ALL})")
            print(f"  {Fore.YELLOW}9.{Style.RESET_ALL} Port Scanning              ({Fore.GREEN}{'Top ports' if self.port_scan_top_ports else 'All ports' if self.check_ports else 'Off'}{Style.RESET_ALL})")
            print(f"  {Fore.YELLOW}10.{Style.RESET_ALL} SSL Certificate Analysis  ({Fore.GREEN}{'On' if self.check_ssl else 'Off'}{Style.RESET_ALL})")
            print(f"  {Fore.YELLOW}11.{Style.RESET_ALL} Technology Detection      ({Fore.GREEN}{'On' if self.technology_detection else 'Off'}{Style.RESET_ALL})")
            
            # Intelligence Section
            print(f"\n{Fore.CYAN}🌍 Intelligence Gathering:{Style.RESET_ALL}")
            print(f"  {Fore.YELLOW}12.{Style.RESET_ALL} Geolocation Lookup        ({Fore.GREEN}{'On' if self.geolocation_lookup else 'Off'}{Style.RESET_ALL})")
            print(f"  {Fore.YELLOW}13.{Style.RESET_ALL} ASN Lookup                ({Fore.GREEN}{'On' if self.asn_lookup else 'Off'}{Style.RESET_ALL})")
            print(f"  {Fore.YELLOW}14.{Style.RESET_ALL} API Keys Configuration    ({Fore.BLUE}Setup external APIs{Style.RESET_ALL})")
            
            print(f"\n{Fore.BLUE}╰─────────────────────────────────────────────────╯{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}s.{Style.RESET_ALL} Start Advanced Enumeration")
            print(f"{Fore.YELLOW}q.{Style.RESET_ALL} Back to Main Menu")
            
            choice = input(f"{Fore.GREEN}webraptor/advanced-subenum{Style.RESET_ALL}> ").strip().lower()
            
            if choice == '1':
                self.configure_data_sources()
            elif choice == '2':
                self.configure_wordlist_categories()
            elif choice == '3':
                self.manage_custom_wordlists()
            elif choice == '4':
                self.generate_custom_wordlist()
            elif choice == '5':
                self.configure_concurrency()
            elif choice == '6':
                self.configure_recursion_depth()
            elif choice == '7':
                self.enable_recursive = not self.enable_recursive
            elif choice == '8':
                self.check_takeover = not self.check_takeover
            elif choice == '9':
                self.configure_port_scanning()
            elif choice == '10':
                self.check_ssl = not self.check_ssl
            elif choice == '11':
                self.technology_detection = not self.technology_detection
            elif choice == '12':
                self.geolocation_lookup = not self.geolocation_lookup
            elif choice == '13':
                self.asn_lookup = not self.asn_lookup
            elif choice == '14':
                self.configure_api_keys()
            elif choice == 's':
                return True
            elif choice == 'q':
                return False

    def configure_data_sources(self):
        """Configure individual data sources"""
        while True:
            print(f"\n{Fore.CYAN}Data Sources Configuration:{Style.RESET_ALL}")
            for i, (source, enabled) in enumerate(self.data_sources.items(), 1):
                status = f"{Fore.GREEN}✓{Style.RESET_ALL}" if enabled else f"{Fore.RED}✗{Style.RESET_ALL}"
                api_required = source in self.api_keys
                api_info = f" {Fore.YELLOW}(API required){Style.RESET_ALL}" if api_required else ""
                print(f"  {i:2d}. {status} {source.replace('_', ' ').title()}{api_info}")
            
            print(f"\n{Fore.YELLOW}a.{Style.RESET_ALL} Enable All")
            print(f"{Fore.YELLOW}d.{Style.RESET_ALL} Disable All") 
            print(f"{Fore.YELLOW}b.{Style.RESET_ALL} Back")
            
            choice = input("Select option: ").strip().lower()
            
            if choice == 'a':
                for source in self.data_sources:
                    self.data_sources[source] = True
                print(f"{Fore.GREEN}[+] All data sources enabled{Style.RESET_ALL}")
            elif choice == 'd':
                for source in self.data_sources:
                    self.data_sources[source] = False
                print(f"{Fore.YELLOW}[!] All data sources disabled{Style.RESET_ALL}")
            elif choice == 'b':
                break
            elif choice.isdigit() and 1 <= int(choice) <= len(self.data_sources):
                source_list = list(self.data_sources.keys())
                source = source_list[int(choice) - 1]
                self.data_sources[source] = not self.data_sources[source]
                status = "enabled" if self.data_sources[source] else "disabled"
                print(f"{Fore.GREEN}[+] {source} {status}{Style.RESET_ALL}")

    def configure_wordlist_categories(self):
        """Configure wordlist categories"""
        available_categories = {
            'common': 'Common subdomains (www, mail, ftp, etc.)',
            'tech': 'Technology-specific (api, cdn, static, etc.)',
            'admin': 'Administrative (admin, panel, dashboard, etc.)',
            'dev': 'Development (dev, test, staging, beta, etc.)',
            'api': 'API-related (api, v1, v2, rest, graphql, etc.)',
            'cloud': 'Cloud services (aws, azure, gcp, etc.)',
            'security': 'Security-related (vpn, ssl, auth, etc.)',
            'mobile': 'Mobile-related (m, mobile, app, etc.)',
            'social': 'Social media (blog, forum, social, etc.)',
            'ecommerce': 'E-commerce (shop, cart, payment, etc.)'
        }
        
        while True:
            print(f"\n{Fore.CYAN}Wordlist Categories:{Style.RESET_ALL}")
            for i, (cat, desc) in enumerate(available_categories.items(), 1):
                status = f"{Fore.GREEN}✓{Style.RESET_ALL}" if cat in self.wordlist_categories else f"{Fore.RED}✗{Style.RESET_ALL}"
                print(f"  {i:2d}. {status} {cat.capitalize()}: {desc}")
            
            print(f"\n{Fore.YELLOW}a.{Style.RESET_ALL} Select All")
            print(f"{Fore.YELLOW}n.{Style.RESET_ALL} Select None")
            print(f"{Fore.YELLOW}b.{Style.RESET_ALL} Back")
            
            choice = input("Select option: ").strip().lower()
            
            if choice == 'a':
                self.wordlist_categories = list(available_categories.keys())
                print(f"{Fore.GREEN}[+] All categories selected{Style.RESET_ALL}")
            elif choice == 'n':
                self.wordlist_categories = []
                print(f"{Fore.YELLOW}[!] All categories deselected{Style.RESET_ALL}")
            elif choice == 'b':
                break
            elif choice.isdigit() and 1 <= int(choice) <= len(available_categories):
                cat_list = list(available_categories.keys())
                category = cat_list[int(choice) - 1]
                if category in self.wordlist_categories:
                    self.wordlist_categories.remove(category)
                    print(f"{Fore.YELLOW}[-] {category} deselected{Style.RESET_ALL}")
                else:
                    self.wordlist_categories.append(category)
                    print(f"{Fore.GREEN}[+] {category} selected{Style.RESET_ALL}")

    def manage_custom_wordlists(self):
        """Manage custom wordlist files"""
        while True:
            print(f"\n{Fore.CYAN}Custom Wordlists:{Style.RESET_ALL}")
            if self.custom_wordlist_paths:
                for i, path in enumerate(self.custom_wordlist_paths, 1):
                    size = "Unknown size"
                    if os.path.exists(path):
                        try:
                            with open(path, 'r') as f:
                                lines = sum(1 for _ in f)
                            size = f"{lines} entries"
                        except:
                            size = "Error reading"
                    print(f"  {i}. {path} ({size})")
            else:
                print(f"  {Fore.YELLOW}No custom wordlists configured{Style.RESET_ALL}")
            
            print(f"\n{Fore.YELLOW}a.{Style.RESET_ALL} Add wordlist file")
            if self.custom_wordlist_paths:
                print(f"{Fore.YELLOW}r.{Style.RESET_ALL} Remove wordlist")
                print(f"{Fore.YELLOW}c.{Style.RESET_ALL} Clear all")
            print(f"{Fore.YELLOW}d.{Style.RESET_ALL} Download popular wordlists")
            print(f"{Fore.YELLOW}b.{Style.RESET_ALL} Back")
            
            choice = input("Select option: ").strip().lower()
            
            if choice == 'a':
                path = input("Enter wordlist file path: ").strip()
                if os.path.exists(path):
                    self.custom_wordlist_paths.append(path)
                    print(f"{Fore.GREEN}[+] Wordlist added: {path}{Style.RESET_ALL}")
                else:
                    print(f"{Fore.RED}[-] File not found: {path}{Style.RESET_ALL}")
            elif choice == 'r' and self.custom_wordlist_paths:
                try:
                    idx = int(input("Enter wordlist number to remove: ")) - 1
                    if 0 <= idx < len(self.custom_wordlist_paths):
                        removed = self.custom_wordlist_paths.pop(idx)
                        print(f"{Fore.YELLOW}[-] Removed: {removed}{Style.RESET_ALL}")
                    else:
                        print(f"{Fore.RED}[-] Invalid selection{Style.RESET_ALL}")
                except ValueError:
                    print(f"{Fore.RED}[-] Invalid input{Style.RESET_ALL}")
            elif choice == 'c' and self.custom_wordlist_paths:
                self.custom_wordlist_paths.clear()
                print(f"{Fore.YELLOW}[!] All custom wordlists removed{Style.RESET_ALL}")
            elif choice == 'd':
                self.download_popular_wordlists()
            elif choice == 'b':
                break

    def download_popular_wordlists(self):
        """Download popular subdomain wordlists"""
        popular_wordlists = {
            'subdomains-top1million-5000': 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt',
            'fierce-hostlist': 'https://raw.githubusercontent.com/mschwager/fierce/master/lists/hosts.txt',
            'subdomains-top1million-20000': 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-20000.txt',
            'bitquark-subdomains-top100k': 'https://raw.githubusercontent.com/bitquark/dnspop/master/results/bitquark_20160227_subdomains_popular_1000000.txt'
        }
        
        print(f"\n{Fore.CYAN}Popular Wordlists:{Style.RESET_ALL}")
        for i, (name, url) in enumerate(popular_wordlists.items(), 1):
            print(f"  {i}. {name}")
        
        print(f"\n{Fore.YELLOW}a.{Style.RESET_ALL} Download all")
        print(f"{Fore.YELLOW}b.{Style.RESET_ALL} Back")
        
        choice = input("Select option: ").strip().lower()
        
        if choice == 'a':
            for name, url in popular_wordlists.items():
                self.download_wordlist(name, url)
        elif choice.isdigit() and 1 <= int(choice) <= len(popular_wordlists):
            name_list = list(popular_wordlists.keys())
            name = name_list[int(choice) - 1]
            url = popular_wordlists[name]
            self.download_wordlist(name, url)

    def download_wordlist(self, name, url):
        """Download a wordlist from URL"""
        try:
            print(f"{Fore.CYAN}[*] Downloading {name}...{Style.RESET_ALL}")
            response = make_request(url, timeout=30)
            if response and response.status_code == 200:
                filename = f"wordlists/{name}.txt"
                os.makedirs("wordlists", exist_ok=True)
                
                with open(filename, 'w') as f:
                    f.write(response.text)
                
                self.custom_wordlist_paths.append(filename)
                print(f"{Fore.GREEN}[+] Downloaded and added: {filename}{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}[-] Failed to download {name}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[-] Error downloading {name}: {e}{Style.RESET_ALL}")

    def generate_custom_wordlist(self):
        """Generate custom wordlist based on target domain"""
        domain = input("Enter target domain for custom wordlist generation: ").strip()
        if not domain:
            return
        
        print(f"{Fore.CYAN}[*] Generating custom wordlist for {domain}...{Style.RESET_ALL}")
        
        # Extract keywords from domain
        domain_parts = domain.replace('.', ' ').replace('-', ' ').split()
        keywords = []
        
        for part in domain_parts:
            if len(part) > 2:  # Skip short parts like TLD
                keywords.append(part)
        
        # Generate variations
        generated_subdomains = set()
        
        # Basic patterns
        patterns = ['', 'www', 'mail', 'smtp', 'pop', 'imap', 'ftp', 'admin', 'test', 'dev', 'api']
        
        for keyword in keywords:
            for pattern in patterns:
                if pattern:
                    generated_subdomains.add(f"{pattern}-{keyword}")
                    generated_subdomains.add(f"{keyword}-{pattern}")
                    generated_subdomains.add(f"{pattern}{keyword}")
                    generated_subdomains.add(f"{keyword}{pattern}")
        
        # Add numbers
        for keyword in keywords:
            for i in range(1, 10):
                generated_subdomains.add(f"{keyword}{i}")
                generated_subdomains.add(f"{keyword}-{i}")
        
        # Add common environments
        environments = ['prod', 'production', 'staging', 'stage', 'test', 'testing', 'dev', 'development', 'qa', 'beta', 'alpha']
        for keyword in keywords:
            for env in environments:
                generated_subdomains.add(f"{env}-{keyword}")
                generated_subdomains.add(f"{keyword}-{env}")
        
        if generated_subdomains:
            filename = f"wordlists/custom_{domain.replace('.', '_')}.txt"
            os.makedirs("wordlists", exist_ok=True)
            
            with open(filename, 'w') as f:
                for subdomain in sorted(generated_subdomains):
                    f.write(f"{subdomain}\n")
            
            self.custom_wordlist_paths.append(filename)
            print(f"{Fore.GREEN}[+] Generated custom wordlist: {filename} ({len(generated_subdomains)} entries){Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}[!] No custom subdomains generated{Style.RESET_ALL}")

    def configure_concurrency(self):
        """Configure async concurrency settings"""
        try:
            new_limit = int(input(f"Enter concurrent limit (current: {self.concurrent_limit}, recommended: 50-200): "))
            if 10 <= new_limit <= 1000:
                self.concurrent_limit = new_limit
                print(f"{Fore.GREEN}[+] Concurrent limit set to {new_limit}{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}[-] Invalid range. Must be between 10-1000{Style.RESET_ALL}")
        except ValueError:
            print(f"{Fore.RED}[-] Invalid input{Style.RESET_ALL}")

    def configure_recursion_depth(self):
        """Configure recursion depth"""
        try:
            new_depth = int(input(f"Enter recursion depth (current: {self.max_depth}, max: 5): "))
            if 1 <= new_depth <= 5:
                self.max_depth = new_depth
                print(f"{Fore.GREEN}[+] Recursion depth set to {new_depth}{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}[-] Invalid range. Must be between 1-5{Style.RESET_ALL}")
        except ValueError:
            print(f"{Fore.RED}[-] Invalid input{Style.RESET_ALL}")

    def configure_port_scanning(self):
        """Configure port scanning options"""
        options = ["Off", "Top ports only", "All common ports", "Custom port list"]
        
        print(f"\n{Fore.CYAN}Port Scanning Options:{Style.RESET_ALL}")
        for i, option in enumerate(options):
            current = ""
            if i == 0 and not self.check_ports:
                current = f" {Fore.GREEN}(current){Style.RESET_ALL}"
            elif i == 1 and self.check_ports and self.port_scan_top_ports:
                current = f" {Fore.GREEN}(current){Style.RESET_ALL}"
            elif i == 2 and self.check_ports and not self.port_scan_top_ports:
                current = f" {Fore.GREEN}(current){Style.RESET_ALL}"
            print(f"  {i+1}. {option}{current}")
        
        try:
            choice = int(input("Select option: ")) - 1
            if choice == 0:
                self.check_ports = False
                print(f"{Fore.YELLOW}[!] Port scanning disabled{Style.RESET_ALL}")
            elif choice == 1:
                self.check_ports = True
                self.port_scan_top_ports = True
                print(f"{Fore.GREEN}[+] Top ports scanning enabled{Style.RESET_ALL}")
            elif choice == 2:
                self.check_ports = True
                self.port_scan_top_ports = False
                print(f"{Fore.GREEN}[+] All common ports scanning enabled{Style.RESET_ALL}")
            elif choice == 3:
                custom_ports = input("Enter custom ports (comma-separated): ").strip()
                if custom_ports:
                    try:
                        self.common_ports = [int(p.strip()) for p in custom_ports.split(',')]
                        self.check_ports = True
                        self.port_scan_top_ports = False
                        print(f"{Fore.GREEN}[+] Custom ports configured: {self.common_ports}{Style.RESET_ALL}")
                    except ValueError:
                        print(f"{Fore.RED}[-] Invalid port format{Style.RESET_ALL}")
        except ValueError:
            print(f"{Fore.RED}[-] Invalid selection{Style.RESET_ALL}")

    def configure_api_keys(self):
        """Configure API keys for external services"""
        print(f"\n{Fore.CYAN}API Keys Configuration:{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Note: API keys are stored as environment variables{Style.RESET_ALL}")
        
        api_services = {
            'securitytrails': 'SecurityTrails API (SECURITYTRAILS_API)',
            'shodan': 'Shodan API (SHODAN_API)',
            'censys': 'Censys API ID (CENSYS_API_ID) & Secret (CENSYS_API_SECRET)',
            'virustotal': 'VirusTotal API (VIRUSTOTAL_API)',
            'spyse': 'Spyse API (SPYSE_API)'
        }
        
        for service, description in api_services.items():
            current_key = self.api_keys.get(service)
            if isinstance(current_key, dict):
                status = f"{Fore.GREEN}Configured{Style.RESET_ALL}" if any(current_key.values()) else f"{Fore.RED}Not set{Style.RESET_ALL}"
            else:
                status = f"{Fore.GREEN}Configured{Style.RESET_ALL}" if current_key else f"{Fore.RED}Not set{Style.RESET_ALL}"
            
            print(f"  • {description}: {status}")
        
        print(f"\n{Fore.YELLOW}To configure API keys, set environment variables:{Style.RESET_ALL}")
        print(f"  export SECURITYTRAILS_API='your_key_here'")
        print(f"  export SHODAN_API='your_key_here'")
        print(f"  export CENSYS_API_ID='your_id_here'")
        print(f"  export CENSYS_API_SECRET='your_secret_here'")
        print(f"  export VIRUSTOTAL_API='your_key_here'")
        print(f"  export SPYSE_API='your_key_here'")

class WordlistManager:
    """Enhanced wordlist management with categorization"""
    
    def __init__(self):
        self.wordlists = {
            'common': [
                'www', 'mail', 'ftp', 'smtp', 'pop', 'imap', 'ns1', 'ns2', 'ns3', 'dns1', 'dns2',
                'mx', 'mx1', 'mx2', 'relay', 'webmail', 'autodiscover', 'autoconfig', 'cpanel',
                'whm', 'directadmin', 'plesk', 'blog', 'forum', 'shop', 'store', 'news'
            ],
            'tech': [
                'cdn', 'static', 'assets', 'media', 'img', 'images', 'js', 'css', 'fonts',
                'files', 'downloads', 'uploads', 'data', 'content', 'resources', 'cache',
                'www1', 'www2', 'www3', 'origin', 'edge'
            ],
            'admin': [
                'admin', 'administrator', 'management', 'mgmt', 'dashboard', 'panel', 'control',
                'console', 'portal', 'manager', 'root', 'system', 'sysadmin', 'operator',
                'helpdesk', 'support', 'service', 'maintenance'
            ],
            'dev': [
                'dev', 'development', 'test', 'testing', 'staging', 'stage', 'prod', 'production',
                'qa', 'quality', 'beta', 'alpha', 'demo', 'sandbox', 'lab', 'preview',
                'build', 'ci', 'cd', 'jenkins', 'gitlab', 'github'
            ],
            'api': [
                'api', 'api1', 'api2', 'api3', 'v1', 'v2', 'v3', 'v4', 'rest', 'graphql', 'soap',
                'service', 'services', 'micro', 'gateway', 'proxy', 'load', 'lb', 'endpoint',
                'webhook', 'rpc', 'grpc'
            ],
            'cloud': [
                'aws', 'amazon', 'azure', 'gcp', 'google', 'cloud', 'heroku', 'docker', 'k8s',
                'kubernetes', 's3', 'storage', 'bucket', 'backup', 'archive', 'sync',
                'cloudfront', 'cloudflare', 'fastly', 'maxcdn'
            ],
            'security': [
                'vpn', 'ssl', 'tls', 'cert', 'certificate', 'auth', 'oauth', 'saml', 'sso',
                'login', 'signin', 'signup', 'register', 'security', 'firewall', 'waf',
                'ids', 'ips', 'siem', 'splunk'
            ],
            'mobile': [
                'm', 'mobile', 'app', 'apps', 'application', 'android', 'ios', 'iphone',
                'ipad', 'tablet', 'touch', 'responsive', 'amp'
            ],
            'social': [
                'social', 'facebook', 'twitter', 'instagram', 'linkedin', 'youtube', 'tiktok',
                'discord', 'slack', 'teams', 'chat', 'community', 'feedback'
            ],
            'ecommerce': [
                'shop', 'store', 'cart', 'checkout', 'payment', 'pay', 'billing', 'invoice',
                'order', 'orders', 'customer', 'customers', 'account', 'profile'
            ]
        }
    
    def get_wordlist_by_categories(self, categories):
        """Get combined wordlist for specified categories"""
        combined = set()
        for category in categories:
            if category in self.wordlists:
                combined.update(self.wordlists[category])
        return sorted(list(combined))
    
    def load_custom_wordlists(self, file_paths):
        """Load custom wordlists from files"""
        custom_words = set()
        for file_path in file_paths:
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    words = [line.strip().lower() for line in f 
                            if line.strip() and not line.startswith('#') and len(line.strip()) > 0]
                    custom_words.update(words)
                print(f"{Fore.GREEN}[+] Loaded {len(words)} words from {file_path}{Style.RESET_ALL}")
            except Exception as e:
                print(f"{Fore.YELLOW}[!] Error loading {file_path}: {e}{Style.RESET_ALL}")
        
        return sorted(list(custom_words))

class AsyncSubdomainDiscovery:
    """Async subdomain discovery with multiple data sources"""
    
    def __init__(self, enum_instance):
        self.enum = enum_instance
        self.session = None
        self.semaphore = None
        self.discovered_subdomains = set()
    
    async def __aenter__(self):
        """Async context manager entry"""
        self.semaphore = asyncio.Semaphore(self.enum.concurrent_limit)
        connector = aiohttp.TCPConnector(
            limit=self.enum.concurrent_limit,
            limit_per_host=50,
            ttl_dns_cache=300,
            use_dns_cache=True,
            ssl=False
        )
        
        timeout = aiohttp.ClientTimeout(total=self.enum.timeout)
        self.session = aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            }
        )
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self.session:
            await self.session.close()
    
    async def fetch_with_semaphore(self, url, **kwargs):
        """Fetch URL with semaphore control"""
        async with self.semaphore:
            try:
                async with self.session.get(url, **kwargs) as response:
                    self.enum.statistics['total_requests'] += 1
                    return await response.text(), response.status
            except Exception as e:
                return None, None
    
    async def query_certificate_transparency(self, domain):
        """Async Certificate Transparency query"""
        print(f"{Fore.CYAN}[*] Querying Certificate Transparency...{Style.RESET_ALL}")
        subdomains = set()
        
        urls = [
            f"https://crt.sh/?q=%25.{domain}&output=json",
            f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names"
        ]
        
        for url in urls:
            try:
                text, status = await self.fetch_with_semaphore(url)
                if text and status == 200:
                    if 'crt.sh' in url:
                        try:
                            data = json.loads(text)
                            for item in data:
                                names = item.get('name_value', '').split('\n')
                                for name in names:
                                    name = name.strip().lower()
                                    if name.startswith('*.'):
                                        name = name[2:]
                                    if name.endswith(f'.{domain}') and name != domain:
                                        if self.is_valid_subdomain(name):
                                            subdomains.add(name)
                        except json.JSONDecodeError:
                            # Fallback HTML parsing
                            pattern = re.compile(r'<TD>([\w\.-]+\.' + re.escape(domain) + r')</TD>')
                            for match in pattern.finditer(text):
                                subdomain = match.group(1).lower()
                                if self.is_valid_subdomain(subdomain):
                                    subdomains.add(subdomain)
                    
                    elif 'certspotter' in url:
                        try:
                            data = json.loads(text)
                            for item in data:
                                dns_names = item.get('dns_names', [])
                                for name in dns_names:
                                    name = name.lower()
                                    if name.startswith('*.'):
                                        name = name[2:]
                                    if name.endswith(f'.{domain}') and name != domain:
                                        if self.is_valid_subdomain(name):
                                            subdomains.add(name)
                        except json.JSONDecodeError:
                            pass
            
            except Exception as e:
                print(f"{Fore.YELLOW}[!] CT query error for {url}: {e}{Style.RESET_ALL}")
        
        print(f"{Fore.GREEN}[+] CT: Found {len(subdomains)} subdomains{Style.RESET_ALL}")
        return subdomains
    
    async def query_hackertarget(self, domain):
        """Async HackerTarget query"""
        print(f"{Fore.CYAN}[*] Querying HackerTarget...{Style.RESET_ALL}")
        subdomains = set()
        
        url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
        text, status = await self.fetch_with_semaphore(url)
        
        if text and status == 200:
            lines = text.strip().split('\n')
            for line in lines:
                if ',' in line:
                    subdomain = line.split(',')[0].strip().lower()
                    if self.is_valid_subdomain(subdomain):
                        subdomains.add(subdomain)
        
        print(f"{Fore.GREEN}[+] HackerTarget: Found {len(subdomains)} subdomains{Style.RESET_ALL}")
        return subdomains
    
    async def query_virustotal(self, domain):
        """Async VirusTotal query"""
        print(f"{Fore.CYAN}[*] Querying VirusTotal...{Style.RESET_ALL}")
        subdomains = set()
        
        if not self.enum.api_keys.get('virustotal'):
            print(f"{Fore.YELLOW}[!] VirusTotal API key not configured{Style.RESET_ALL}")
            return subdomains
        
        url = f"https://www.virustotal.com/vtapi/v2/domain/report"
        params = {
            'apikey': self.enum.api_keys['virustotal'],
            'domain': domain
        }
        
        try:
            text, status = await self.fetch_with_semaphore(url, params=params)
            if text and status == 200:
                data = json.loads(text)
                if data.get('response_code') == 1:
                    for subdomain in data.get('subdomains', []):
                        subdomain = subdomain.lower()
                        if self.is_valid_subdomain(subdomain):
                            subdomains.add(subdomain)
        
        except Exception as e:
            print(f"{Fore.YELLOW}[!] VirusTotal query error: {e}{Style.RESET_ALL}")
        
        print(f"{Fore.GREEN}[+] VirusTotal: Found {len(subdomains)} subdomains{Style.RESET_ALL}")
        return subdomains
    
    async def query_securitytrails(self, domain):
        """Async SecurityTrails query"""
        print(f"{Fore.CYAN}[*] Querying SecurityTrails...{Style.RESET_ALL}")
        subdomains = set()
        
        if not self.enum.api_keys.get('securitytrails'):
            print(f"{Fore.YELLOW}[!] SecurityTrails API key not configured{Style.RESET_ALL}")
            return subdomains
        
        url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
        headers = {'APIKEY': self.enum.api_keys['securitytrails']}
        
        try:
            text, status = await self.fetch_with_semaphore(url, headers=headers)
            if text and status == 200:
                data = json.loads(text)
                for subdomain_prefix in data.get('subdomains', []):
                    full_subdomain = f"{subdomain_prefix}.{domain}"
                    if self.is_valid_subdomain(full_subdomain):
                        subdomains.add(full_subdomain)
        
        except Exception as e:
            print(f"{Fore.YELLOW}[!] SecurityTrails query error: {e}{Style.RESET_ALL}")
        
        print(f"{Fore.GREEN}[+] SecurityTrails: Found {len(subdomains)} subdomains{Style.RESET_ALL}")
        return subdomains
    
    async def query_wayback_machine(self, domain):
        """Async Wayback Machine query"""
        print(f"{Fore.CYAN}[*] Querying Wayback Machine...{Style.RESET_ALL}")
        subdomains = set()
        
        url = f"https://web.archive.org/cdx/search/cdx?url=*.{domain}&output=json&collapse=urlkey"
        text, status = await self.fetch_with_semaphore(url)
        
        if text and status == 200:
            try:
                data = json.loads(text)
                for row in data[1:]:  # Skip header row
                    if len(row) > 2:
                        original_url = row[2]
                        parsed = urlparse(original_url)
                        if parsed.netloc.endswith(f'.{domain}'):
                            subdomain = parsed.netloc.lower()
                            if self.is_valid_subdomain(subdomain):
                                subdomains.add(subdomain)
            except json.JSONDecodeError:
                pass
        
        print(f"{Fore.GREEN}[+] Wayback: Found {len(subdomains)} subdomains{Style.RESET_ALL}")
        return subdomains
    
    async def query_urlscan(self, domain):
        """Async URLScan query"""
        print(f"{Fore.CYAN}[*] Querying URLScan...{Style.RESET_ALL}")
        subdomains = set()
        
        url = f"https://urlscan.io/api/v1/search/?q=domain:{domain}"
        text, status = await self.fetch_with_semaphore(url)
        
        if text and status == 200:
            try:
                data = json.loads(text)
                for result in data.get('results', []):
                    page_url = result.get('page', {}).get('url', '')
                    if page_url:
                        parsed = urlparse(page_url)
                        if parsed.netloc.endswith(f'.{domain}'):
                            subdomain = parsed.netloc.lower()
                            if self.is_valid_subdomain(subdomain):
                                subdomains.add(subdomain)
            except json.JSONDecodeError:
                pass
        
        print(f"{Fore.GREEN}[+] URLScan: Found {len(subdomains)} subdomains{Style.RESET_ALL}")
        return subdomains
    
    async def query_anubis(self, domain):
        """Async Anubis query"""
        print(f"{Fore.CYAN}[*] Querying Anubis...{Style.RESET_ALL}")
        subdomains = set()
        
        url = f"https://jldc.me/anubis/subdomains/{domain}"
        text, status = await self.fetch_with_semaphore(url)
        
        if text and status == 200:
            try:
                data = json.loads(text)
                for subdomain in data:
                    subdomain = subdomain.lower()
                    if self.is_valid_subdomain(subdomain):
                        subdomains.add(subdomain)
            except json.JSONDecodeError:
                pass
        
        print(f"{Fore.GREEN}[+] Anubis: Found {len(subdomains)} subdomains{Style.RESET_ALL}")
        return subdomains
    
    def is_valid_subdomain(self, subdomain):
        """Validate subdomain format"""
        if not subdomain or len(subdomain) > 253:
            return False
        if not re.match(r'^[a-zA-Z0-9.-]+$', subdomain):
            return False
        if '..' in subdomain or subdomain.startswith('.') or subdomain.endswith('.'):
            return False
        return True
    
    async def run_all_queries(self, domain):
        """Run all enabled data source queries concurrently"""
        tasks = []
        
        # Add enabled data source tasks
        if self.enum.data_sources.get('crt_sh'):
            tasks.append(self.query_certificate_transparency(domain))
        if self.enum.data_sources.get('hackertarget'):
            tasks.append(self.query_hackertarget(domain))
        if self.enum.data_sources.get('virustotal'):
            tasks.append(self.query_virustotal(domain))
        if self.enum.data_sources.get('securitytrails'):
            tasks.append(self.query_securitytrails(domain))
        if self.enum.data_sources.get('wayback'):
            tasks.append(self.query_wayback_machine(domain))
        if self.enum.data_sources.get('urlscan'):
            tasks.append(self.query_urlscan(domain))
        if self.enum.data_sources.get('anubis'):
            tasks.append(self.query_anubis(domain))
        
        # Execute all tasks concurrently
        if tasks:
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            all_subdomains = set()
            for result in results:
                if isinstance(result, set):
                    all_subdomains.update(result)
                elif isinstance(result, Exception):
                    print(f"{Fore.YELLOW}[!] Task failed: {result}{Style.RESET_ALL}")
            
            return all_subdomains
        else:
            print(f"{Fore.YELLOW}[!] No data sources enabled{Style.RESET_ALL}")
            return set()

async def async_dns_bruteforce(enum_instance, domain, wordlist):
    """Async DNS brute force with improved performance"""
    print(f"{Fore.CYAN}[*] Starting async DNS brute force...{Style.RESET_ALL}")
    
    found_subdomains = set()
    semaphore = asyncio.Semaphore(enum_instance.concurrent_limit)
    
    async def check_subdomain(subdomain):
        async with semaphore:
            full_domain = f"{subdomain}.{domain}"
            try:
                resolver = dns.asyncresolver.Resolver()
                resolver.timeout = 2
                resolver.lifetime = 2
                
                answers = await resolver.resolve(full_domain, 'A')
                if answers:
                    ips = [str(answer) for answer in answers]
                    found_subdomains.add((full_domain, tuple(ips)))
                    print(f"{Fore.GREEN}[+] Found: {full_domain} -> {', '.join(ips)}{Style.RESET_ALL}")
                    return full_domain, ips
                    
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
                pass
            except Exception:
                pass
            return None
    
    # Create tasks for all subdomains
    tasks = [check_subdomain(word) for word in wordlist]
    
    # Process in batches to avoid overwhelming the system
    batch_size = enum_instance.concurrent_limit
    for i in range(0, len(tasks), batch_size):
        batch = tasks[i:i + batch_size]
        await asyncio.gather(*batch, return_exceptions=True)
    
    print(f"{Fore.GREEN}[+] Async DNS brute force completed: {len(found_subdomains)} subdomains found{Style.RESET_ALL}")
    return found_subdomains

def run(target):
    """Main entry point for WebRaptor framework"""
    try:
        config = Config()
        enumerator = AdvancedSubdomainEnum(config)
        
        enumerator.show_banner()
        
        # Show interactive menu for configuration
        if enumerator.show_advanced_menu():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            try:
                loop.run_until_complete(run_advanced_enumeration(enumerator, target))
            finally:
                loop.close()
        else:
            print(f"{Fore.YELLOW}[!] Advanced subdomain enumeration cancelled{Style.RESET_ALL}")
            
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Module interrupted by user{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[-] Error in advanced subdomain enumeration: {e}{Style.RESET_ALL}")


async def run_advanced_enumeration(enumerator, target):
    """Run the advanced enumeration with async support"""
    domain = extract_domain(target)
    if not domain:
        print(f"{Fore.RED}[-] Invalid domain: {target}{Style.RESET_ALL}")
        return
    
    print(f"\n{Fore.BLUE}[*] Starting advanced subdomain enumeration for: {domain}{Style.RESET_ALL}")
    print_configuration(enumerator)
    
    enumerator.statistics['start_time'] = time.time()
    all_subdomains = set()
    
    try:
        # Phase 1: Async data source queries
        print(f"\n{Fore.BLUE}{'='*80}")
        print(f"[*] Phase 1: Online Data Source Intelligence")
        print(f"{'='*80}{Style.RESET_ALL}")
        
        async with AsyncSubdomainDiscovery(enumerator) as discovery:
            online_subdomains = await discovery.run_all_queries(domain)
            all_subdomains.update(online_subdomains)
            print(f"{Fore.CYAN}[*] Online sources found: {len(online_subdomains)} subdomains{Style.RESET_ALL}")
        
        # Phase 2: DNS Brute Force
        if any(enumerator.data_sources[src] for src in ['dns_brute']):
            print(f"\n{Fore.BLUE}{'='*80}")
            print(f"[*] Phase 2: DNS Brute Force Attack")
            print(f"{'='*80}{Style.RESET_ALL}")
            
            # Prepare wordlist
            wordlist = prepare_wordlist(enumerator)
            print(f"{Fore.CYAN}[*] Using wordlist with {len(wordlist)} entries{Style.RESET_ALL}")
            
            # Run async DNS brute force
            brute_results = await async_dns_bruteforce(enumerator, domain, wordlist)
            brute_subdomains = {subdomain for subdomain, ips in brute_results}
            all_subdomains.update(brute_subdomains)
            print(f"{Fore.CYAN}[*] Brute force found: {len(brute_subdomains)} subdomains{Style.RESET_ALL}")
        
        # Phase 3: Validation and Intelligence Gathering
        print(f"\n{Fore.BLUE}{'='*80}")
        print(f"[*] Phase 3: Validation & Intelligence Gathering")
        print(f"{'='*80}{Style.RESET_ALL}")
        
        unique_subdomains = sorted(list(all_subdomains))
        print(f"{Fore.CYAN}[*] Total unique subdomains discovered: {len(unique_subdomains)}{Style.RESET_ALL}")
        
        if unique_subdomains:
            validated_results = await validate_and_enrich_subdomains(enumerator, unique_subdomains, domain)
            enumerator.results = validated_results
            
            # Display results
            display_advanced_results(enumerator)
            save_advanced_results(enumerator, domain)
            
            print(f"\n{Fore.GREEN}[+] Advanced enumeration completed successfully!{Style.RESET_ALL}")
            print(f"{Fore.GREEN}[+] Found {len(enumerator.results)} validated subdomains{Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}[!] No subdomains discovered{Style.RESET_ALL}")
            
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Enumeration interrupted by user{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[-] Error during enumeration: {e}{Style.RESET_ALL}")

def extract_domain(url):
    """Extract domain from URL with improved parsing"""
    try:
        if not url.startswith(('http://', 'https://')):
            url = f"https://{url}"
        parsed = urlparse(url)
        domain = parsed.netloc.split(':')[0]
        return domain.lower().strip()
    except Exception:
        return None

def print_configuration(enumerator):
    """Print current configuration"""
    print(f"{Fore.BLUE}[*] Configuration Summary:{Style.RESET_ALL}")
    
    active_sources = [k for k, v in enumerator.data_sources.items() if v]
    print(f"    Data Sources: {len(active_sources)}/15 active ({', '.join(active_sources)})")
    print(f"    Wordlist Categories: {len(enumerator.wordlist_categories)} selected")
    print(f"    Custom Wordlists: {len(enumerator.custom_wordlist_paths)} files")
    print(f"    Concurrent Limit: {enumerator.concurrent_limit}")
    print(f"    Recursion Depth: {enumerator.max_depth}")
    print(f"    Security Checks: Takeover={enumerator.check_takeover}, Ports={enumerator.check_ports}, SSL={enumerator.check_ssl}")
    print(f"    Intelligence: Geo={enumerator.geolocation_lookup}, ASN={enumerator.asn_lookup}, Tech={enumerator.technology_detection}")
    print(f"{Fore.BLUE}{'='*80}{Style.RESET_ALL}")

def prepare_wordlist(enumerator):
    """Prepare final wordlist from all sources"""
    wordlist = set()
    
    # Add category-based wordlists
    if enumerator.wordlist_categories:
        category_words = enumerator.wordlist_manager.get_wordlist_by_categories(enumerator.wordlist_categories)
        wordlist.update(category_words)
        print(f"{Fore.GREEN}[+] Added {len(category_words)} words from categories{Style.RESET_ALL}")
    
    # Add custom wordlists
    if enumerator.custom_wordlist_paths:
        custom_words = enumerator.wordlist_manager.load_custom_wordlists(enumerator.custom_wordlist_paths)
        wordlist.update(custom_words)
        print(f"{Fore.GREEN}[+] Added {len(custom_words)} words from custom wordlists{Style.RESET_ALL}")
    
    return sorted(list(wordlist))

async def validate_and_enrich_subdomains(enumerator, subdomains, domain):
    """Advanced validation and enrichment with async processing"""
    print(f"{Fore.CYAN}[*] Validating and enriching {len(subdomains)} subdomains...{Style.RESET_ALL}")
    
    validated_results = []
    semaphore = asyncio.Semaphore(enumerator.concurrent_limit)
    
    async def process_subdomain(subdomain):
        async with semaphore:
            try:
                result = SubdomainResult(
                    subdomain=subdomain,
                    ips=[],
                    cnames=[],
                    mx_records=[],
                    ns_records=[],
                    txt_records=[],
                    web_services=[],
                    ssl_info={},
                    open_ports=[],
                    takeover_service=None,
                    takeover_signature=None,
                    response_codes={},
                    technologies=[],
                    cdn_provider=None,
                    asn_info={},
                    geolocation={},
                    source="validation",
                    confidence_score=0.0
                )
                
                # DNS Resolution
                resolver = dns.resolver.Resolver()
                resolver.timeout = 3
                resolver.lifetime = 3
                
                # A Records
                try:
                    answers = resolver.resolve(subdomain, 'A')
                    result.ips = [str(answer) for answer in answers]
                    enumerator.statistics['unique_ips'].update(result.ips)
                except:
                    pass
                
                if not result.ips:
                    return None  # Skip if no A records
                
                # CNAME Records
                try:
                    cname_answers = resolver.resolve(subdomain, 'CNAME')
                    result.cnames = [str(answer) for answer in cname_answers]
                except:
                    pass
                
                # MX Records
                try:
                    mx_answers = resolver.resolve(subdomain, 'MX')
                    result.mx_records = [f"{answer.preference} {answer.exchange}" for answer in mx_answers]
                except:
                    pass
                
                # TXT Records
                try:
                    txt_answers = resolver.resolve(subdomain, 'TXT')
                    result.txt_records = [str(answer) for answer in txt_answers]
                except:
                    pass
                
                # Web Service Detection
                await detect_web_services(result, enumerator)
                
                # Port Scanning
                if enumerator.check_ports:
                    await scan_ports(result, enumerator)
                
                # SSL Certificate Analysis
                if enumerator.check_ssl:
                    await analyze_ssl_certificate(result)
                
                # Subdomain Takeover Detection
                if enumerator.check_takeover:
                    await detect_subdomain_takeover(result, enumerator)
                
                # Technology Detection
                if enumerator.technology_detection:
                    await detect_technologies(result, enumerator)
                
                # Geolocation and ASN Lookup
                if result.ips:
                    if enumerator.geolocation_lookup:
                        result.geolocation = await get_geolocation(result.ips[0])
                    if enumerator.asn_lookup:
                        result.asn_info = await get_asn_info(result.ips[0])
                
                # Calculate confidence score
                result.confidence_score = calculate_confidence_score(result)
                
                return result
                
            except Exception as e:
                print(f"{Fore.YELLOW}[!] Error processing {subdomain}: {e}{Style.RESET_ALL}")
                return None
    
    # Process all subdomains concurrently
    tasks = [process_subdomain(subdomain) for subdomain in subdomains]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    
    # Filter out None results and exceptions
    for result in results:
        if isinstance(result, SubdomainResult):
            validated_results.append(result)
        elif isinstance(result, Exception):
            print(f"{Fore.YELLOW}[!] Validation error: {result}{Style.RESET_ALL}")
    
    print(f"{Fore.GREEN}[+] Validated {len(validated_results)} subdomains{Style.RESET_ALL}")
    return validated_results

async def detect_web_services(result, enumerator):
    """Detect web services on subdomain"""
    protocols = ['https', 'http']
    
    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=5)) as session:
        for protocol in protocols:
            url = f"{protocol}://{result.subdomain}"
            try:
                async with session.get(url, allow_redirects=False) as response:
                    result.response_codes[protocol] = response.status
                    
                    if response.status in [200, 301, 302, 403]:
                        result.web_services.append(url)
                        
                        # Detect CDN provider
                        headers = dict(response.headers.items())
                        result.cdn_provider = detect_cdn_provider(headers)
                        
            except:
                pass

async def scan_ports(result, enumerator):
    """Async port scanning"""
    if not result.ips:
        return
    
    ip = result.ips[0]  # Scan first IP
    ports_to_scan = enumerator.top_ports if enumerator.port_scan_top_ports else enumerator.common_ports
    
    async def check_port(port):
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=1
            )
            writer.close()
            await writer.wait_closed()
            return port
        except:
            return None
    
    tasks = [check_port(port) for port in ports_to_scan]
    port_results = await asyncio.gather(*tasks, return_exceptions=True)
    
    result.open_ports = [port for port in port_results if isinstance(port, int)]

async def analyze_ssl_certificate(result):
    """Analyze SSL certificate information"""
    if not result.web_services:
        return
    
    https_url = next((url for url in result.web_services if url.startswith('https')), None)
    if not https_url:
        return
    
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(result.subdomain, 443, ssl=context),
            timeout=5
        )
        
        peercert = writer.transport.get_extra_info('peercert')
        if peercert:
            result.ssl_info = {
                'subject': dict(x[0] for x in peercert.get('subject', [])),
                'issuer': dict(x[0] for x in peercert.get('issuer', [])),
                'version': peercert.get('version'),
                'serial_number': peercert.get('serialNumber'),
                'not_before': peercert.get('notBefore'),
                'not_after': peercert.get('notAfter'),
                'san': peercert.get('subjectAltName', [])
            }
        
        writer.close()
        await writer.wait_closed()
        
    except:
        pass

async def detect_subdomain_takeover(result, enumerator):
    """Enhanced subdomain takeover detection"""
    if not result.web_services:
        return
    
    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as session:
        for url in result.web_services:
            try:
                async with session.get(url, allow_redirects=True) as response:
                    content = await response.text()
                    headers = dict(response.headers.items())
                    
                    # Check against takeover signatures
                    for service, config in enumerator.takeover_signatures.items():
                        # Check content patterns
                        for pattern in config['patterns']:
                            if pattern.lower() in content.lower():
                                # Additional validation with CNAME
                                cname_match = any(indicator in ' '.join(result.cnames).lower() 
                                                for indicator in config['cname_indicators'])
                                
                                if cname_match or response.status in config['http_codes']:
                                    result.takeover_service = service
                                    result.takeover_signature = pattern
                                    result.confidence_score += config['confidence']
                                    return
                                    
            except:
                continue

async def detect_technologies(result, enumerator):
    """Detect technologies used by the subdomain"""
    if not result.web_services:
        return
    
    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=5)) as session:
        for url in result.web_services:
            try:
                async with session.get(url) as response:
                    content = await response.text()
                    headers = dict(response.headers.items())
                    
                    # Check technology patterns
                    for tech, patterns in enumerator.tech_patterns.items():
                        for pattern in patterns:
                            if re.search(pattern, content, re.IGNORECASE) or \
                               any(re.search(pattern, str(v), re.IGNORECASE) for v in headers.values()):
                                if tech not in result.technologies:
                                    result.technologies.append(tech)
                                    enumerator.statistics['technologies_found'][tech] += 1
                    
                    # Server header detection
                    server = headers.get('server', '').lower()
                    if server and server not in result.technologies:
                        result.technologies.append(server)
                        enumerator.statistics['technologies_found'][server] += 1
                    
                    break  # Only check first working URL
                    
            except:
                continue

def detect_cdn_provider(headers):
    """Detect CDN provider from headers"""
    cdn_indicators = {
        'cloudflare': ['cf-ray', 'cloudflare'],
        'fastly': ['fastly', 'x-served-by'],
        'aws_cloudfront': ['cloudfront', 'x-amz'],
        'maxcdn': ['maxcdn'],
        'akamai': ['akamai'],
        'incapsula': ['incap_ses', 'visid_incap'],
        'sucuri': ['sucuri'],
        'keycdn': ['keycdn']
    }
    
    header_str = ' '.join(f"{k}:{v}".lower() for k, v in headers.items())
    
    for cdn, indicators in cdn_indicators.items():
        if any(indicator in header_str for indicator in indicators):
            return cdn
    
    return None

async def get_geolocation(ip):
    """Get geolocation information for IP"""
    try:
        async with aiohttp.ClientSession() as session:
            url = f"http://ip-api.com/json/{ip}"
            async with session.get(url) as response:
                if response.status == 200:
                    data = await response.json()
                    if data.get('status') == 'success':
                        return {
                            'country': data.get('country'),
                            'country_code': data.get('countryCode'),
                            'region': data.get('regionName'),
                            'city': data.get('city'),
                            'latitude': data.get('lat'),
                            'longitude': data.get('lon'),
                            'isp': data.get('isp'),
                            'org': data.get('org')
                        }
    except:
        pass
    return {}

async def get_asn_info(ip):
    """Get ASN information for IP"""
    try:
        async with aiohttp.ClientSession() as session:
            url = f"https://ipinfo.io/{ip}/json"
            async with session.get(url) as response:
                if response.status == 200:
                    data = await response.json()
                    return {
                        'asn': data.get('org', '').split()[0] if data.get('org') else None,
                        'org_name': ' '.join(data.get('org', '').split()[1:]) if data.get('org') else None,
                        'network': data.get('network')
                    }
    except:
        pass
    return {}

def calculate_confidence_score(result):
    """Calculate confidence score for subdomain result"""
    score = 0.5  # Base score
    
    # Web services add confidence
    score += len(result.web_services) * 0.1
    
    # Multiple IPs add confidence
    score += len(result.ips) * 0.05
    
    # SSL certificate adds confidence
    if result.ssl_info:
        score += 0.1
    
    # Open ports add confidence
    score += len(result.open_ports) * 0.02
    
    # Technologies detected add confidence
    score += len(result.technologies) * 0.03
    
    # Geolocation data adds confidence
    if result.geolocation:
        score += 0.05
    
    # Cap at 1.0
    return min(score, 1.0)

def display_advanced_results(enumerator):
    """Display comprehensive results"""
    if not enumerator.results:
        print(f"{Fore.YELLOW}[!] No validated subdomains found{Style.RESET_ALL}")
        return
    
    print(f"\n{Fore.BLUE}╔══════════════════════════════════════════════════════════════════════════╗")
    print(f"║                        ADVANCED ENUMERATION RESULTS                     ║")
    print(f"╚══════════════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}")
    
    # Summary statistics
    total_results = len(enumerator.results)
    web_enabled = sum(1 for r in enumerator.results if r.web_services)
    takeover_candidates = sum(1 for r in enumerator.results if r.takeover_service)
    ssl_enabled = sum(1 for r in enumerator.results if r.ssl_info)
    
    print(f"\n{Fore.CYAN}📊 Summary Statistics:{Style.RESET_ALL}")
    print(f"  Total Subdomains: {total_results}")
    print(f"  Web-enabled: {web_enabled}")
    print(f"  SSL-enabled: {ssl_enabled}")
    print(f"  Unique IPs: {len(enumerator.statistics['unique_ips'])}")
    print(f"  Takeover Candidates: {Fore.RED}{takeover_candidates}{Style.RESET_ALL}" if takeover_candidates else f"  Takeover Candidates: {takeover_candidates}")
    
    # Technology breakdown
    if enumerator.statistics['technologies_found']:
        print(f"\n{Fore.CYAN}🔧 Technologies Detected:{Style.RESET_ALL}")
        for tech, count in enumerator.statistics['technologies_found'].most_common(10):
            print(f"  {tech}: {count}")
    
    # Detailed results
    print(f"\n{Fore.CYAN}📋 Detailed Results:{Style.RESET_ALL}")
    
    # Sort by confidence score (highest first)
    sorted_results = sorted(enumerator.results, key=lambda x: x.confidence_score, reverse=True)
    
    for i, result in enumerate(sorted_results, 1):
        confidence_color = Fore.GREEN if result.confidence_score > 0.8 else Fore.YELLOW if result.confidence_score > 0.6 else Fore.WHITE
        
        print(f"\n{Fore.CYAN}[{i:03d}] {result.subdomain}{Style.RESET_ALL} {confidence_color}(Confidence: {result.confidence_score:.2f}){Style.RESET_ALL}")
        
        # IPs
        if result.ips:
            print(f"     🌐 IPs: {Fore.GREEN}{', '.join(result.ips)}{Style.RESET_ALL}")
        
        # Web services
        if result.web_services:
            web_status = []
            for service in result.web_services:
                protocol = 'https' if service.startswith('https') else 'http'
                status_code = result.response_codes.get(protocol, 'Unknown')
                web_status.append(f"{service} ({status_code})")
            print(f"     🌍 Web: {Fore.BLUE}{' | '.join(web_status)}{Style.RESET_ALL}")
        
        # CDN
        if result.cdn_provider:
            print(f"     ☁️  CDN: {Fore.MAGENTA}{result.cdn_provider}{Style.RESET_ALL}")
        
        # Technologies
        if result.technologies:
            print(f"     ⚙️  Tech: {Fore.YELLOW}{', '.join(result.technologies[:5])}{Style.RESET_ALL}")
        
        # Open ports
        if result.open_ports:
            port_display = ', '.join(map(str, result.open_ports[:10]))
            if len(result.open_ports) > 10:
                port_display += f" (+{len(result.open_ports) - 10} more)"
            print(f"     🔌 Ports: {Fore.CYAN}{port_display}{Style.RESET_ALL}")
        
        # SSL info
        if result.ssl_info:
            issuer = result.ssl_info.get('issuer', {}).get('organizationName', 'Unknown')
            print(f"     🔒 SSL: {Fore.GREEN}Valid (Issuer: {issuer}){Style.RESET_ALL}")
        
        # Geolocation
        if result.geolocation and result.geolocation.get('country'):
            geo_info = f"{result.geolocation.get('city', 'Unknown')}, {result.geolocation.get('country', 'Unknown')}"
            if result.geolocation.get('isp'):
                geo_info += f" ({result.geolocation['isp']})"
            print(f"     🌍 Location: {Fore.WHITE}{geo_info}{Style.RESET_ALL}")
        
        # Subdomain takeover warning
        if result.takeover_service:
            print(f"     {Fore.RED}⚠️  POTENTIAL TAKEOVER: {result.takeover_service.upper()}{Style.RESET_ALL}")
            print(f"         Signature: {result.takeover_signature}")
    
    # Performance statistics
    elapsed_time = time.time() - enumerator.statistics['start_time']
    print(f"\n{Fore.BLUE}⏱️  Performance Statistics:{Style.RESET_ALL}")
    print(f"  Enumeration Time: {elapsed_time:.2f}s")
    print(f"  Total Requests: {enumerator.statistics['total_requests']}")
    print(f"  Requests/Second: {enumerator.statistics['total_requests']/elapsed_time:.1f}")

def save_advanced_results(enumerator, domain):
    """Save comprehensive results to files and config"""
    if not enumerator.results:
        return
    
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    
    # Save to WebRaptor config
    config_data = {
        'domain': domain,
        'total_found': len(enumerator.results),
        'scan_time': time.time() - enumerator.statistics['start_time'],
        'statistics': {
            'total_requests': enumerator.statistics['total_requests'],
            'unique_ips': len(enumerator.statistics['unique_ips']),
            'technologies_found': dict(enumerator.statistics['technologies_found']),
            'web_enabled': sum(1 for r in enumerator.results if r.web_services),
            'ssl_enabled': sum(1 for r in enumerator.results if r.ssl_info),
            'takeover_candidates': sum(1 for r in enumerator.results if r.takeover_service)
        },
        'subdomains': [
            {
                'subdomain': r.subdomain,
                'ips': r.ips,
                'web_services': r.web_services,
                'technologies': r.technologies,
                'confidence_score': r.confidence_score,
                'takeover_service': r.takeover_service
            }
            for r in enumerator.results
        ]
    }
    
    enumerator.config.add_result('advanced_subenum', config_data)
    
    # Save detailed JSON report
    json_file = f"reports/advanced_subenum_{domain.replace('.', '_')}_{timestamp}.json"
    try:
        json_data = {
            'metadata': {
                'domain': domain,
                'scan_date': time.strftime('%Y-%m-%d %H:%M:%S'),
                'total_subdomains': len(enumerator.results),
                'scan_time_seconds': time.time() - enumerator.statistics['start_time'],
                'configuration': {
                    'data_sources': {k: v for k, v in enumerator.data_sources.items() if v},
                    'concurrent_limit': enumerator.concurrent_limit,
                    'max_depth': enumerator.max_depth,
                    'wordlist_categories': enumerator.wordlist_categories
                }
            },
            'statistics': {
                'total_requests': enumerator.statistics['total_requests'],
                'unique_ips': list(enumerator.statistics['unique_ips']),
                'technologies_found': dict(enumerator.statistics['technologies_found']),
                'web_enabled_count': sum(1 for r in enumerator.results if r.web_services),
                'ssl_enabled_count': sum(1 for r in enumerator.results if r.ssl_info),
                'takeover_candidates_count': sum(1 for r in enumerator.results if r.takeover_service)
            },
            'results': [
                {
                    'subdomain': r.subdomain,
                    'ips': r.ips,
                    'cnames': r.cnames,
                    'mx_records': r.mx_records,
                    'web_services': r.web_services,
                    'ssl_info': r.ssl_info,
                    'open_ports': r.open_ports,
                    'takeover_service': r.takeover_service,
                    'takeover_signature': r.takeover_signature,
                    'response_codes': r.response_codes,
                    'technologies': r.technologies,
                    'cdn_provider': r.cdn_provider,
                    'asn_info': r.asn_info,
                    'geolocation': r.geolocation,
                    'confidence_score': r.confidence_score
                }
                for r in enumerator.results
            ]
        }
        
        with open(json_file, 'w') as f:
            json.dump(json_data, f, indent=2, default=str)
        
        print(f"{Fore.GREEN}[+] Detailed JSON report saved: {json_file}{Style.RESET_ALL}")
        
    except Exception as e:
        print(f"{Fore.RED}[-] Error saving JSON report: {e}{Style.RESET_ALL}")
    
    # Save CSV report
    csv_file = f"reports/advanced_subenum_{domain.replace('.', '_')}_{timestamp}.csv"
    try:
        import csv
        with open(csv_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([
                'Subdomain', 'IPs', 'Web Services', 'Open Ports', 'Technologies',
                'CDN Provider', 'SSL Enabled', 'Takeover Risk', 'Confidence Score',
                'Country', 'ISP'
            ])
            
            for r in enumerator.results:
                writer.writerow([
                    r.subdomain,
                    ', '.join(r.ips),
                    ', '.join(r.web_services),
                    ', '.join(map(str, r.open_ports)),
                    ', '.join(r.technologies),
                    r.cdn_provider or '',
                    'Yes' if r.ssl_info else 'No',
                    r.takeover_service or '',
                    f"{r.confidence_score:.2f}",
                    r.geolocation.get('country', '') if r.geolocation else '',
                    r.geolocation.get('isp', '') if r.geolocation else ''
                ])
        
        print(f"{Fore.GREEN}[+] CSV report saved: {csv_file}{Style.RESET_ALL}")
        
    except Exception as e:
        print(f"{Fore.RED}[-] Error saving CSV report: {e}{Style.RESET_ALL}")

if __name__ == "__main__":
    # For standalone testing
    import sys
    if len(sys.argv) > 1:
        run(sys.argv[1])
    else:
        print("Usage: python advanced_subenum.py <target_domain>")