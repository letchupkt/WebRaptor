#!/usr/bin/env python3
"""
WebRaptor Advanced Reconnaissance Module
Comprehensive reconnaissance using multiple tools (Amass, Subfinder, HTTPx, etc.)
"""

import os
import sys
import json
import subprocess
import time
import asyncio
import aiohttp
from pathlib import Path
from typing import List, Dict, Optional, Set
from colorama import Fore, Style, init
from core.config import Config
from core.tool_manager import ToolManager

init()

# Module metadata
description = "Advanced reconnaissance with Amass, Subfinder, HTTPx, and intelligence gathering"
author = "LakshmikanthanK (@letchu_pkt)"
version = "2.1"

class AdvancedReconnaissance:
    """Advanced reconnaissance using multiple tools and techniques"""
    
    def __init__(self, config: Config = None):
        self.config = config or Config()
        self.tool_manager = ToolManager()
        self.results_dir = Path("reports/recon")
        self.temp_dir = Path("temp/recon")
        
        # Create directories
        self.results_dir.mkdir(parents=True, exist_ok=True)
        self.temp_dir.mkdir(parents=True, exist_ok=True)
        
        # Reconnaissance configuration
        self.recon_config = {
            'timeout': 30,
            'threads': 50,
            'rate_limit': 100,
            'depth': 2,
            'passive_only': False,
            'active_scanning': True,
            'dns_bruteforce': True,
            'web_crawling': True,
            'technology_detection': True,
            'port_scanning': True
        }
        
        # Tool configurations
        self.tool_configs = {
            'amass': {
                'passive': ['-passive', '-d', '{target}'],
                'active': ['-active', '-d', '{target}', '-brute'],
                'intel': ['-intel', '-d', '{target}']
            },
            'subfinder': {
                'basic': ['-d', '{target}', '-silent'],
                'comprehensive': ['-d', '{target}', '-silent', '-all-sources'],
                'with_resolvers': ['-d', '{target}', '-silent', '-r', '8.8.8.8,1.1.1.1']
            },
            'httpx': {
                'basic': ['-l', '{subdomains_file}', '-silent', '-json'],
                'comprehensive': ['-l', '{subdomains_file}', '-silent', '-json', '-tech-detect', '-title', '-status-code'],
                'with_screenshots': ['-l', '{subdomains_file}', '-silent', '-json', '-screenshot']
            },
            'nmap': {
                'quick': ['-sS', '-T4', '-F', '--open'],
                'comprehensive': ['-sS', '-sV', '-sC', '-O', '-A', '--script=vuln'],
                'stealth': ['-sS', '-T2', '--scan-delay', '1s']
            }
        }
        
        # Intelligence sources
        self.intelligence_sources = {
            'passive': [
                'amass', 'subfinder', 'assetfinder', 'findomain',
                'crt.sh', 'virustotal', 'shodan', 'censys'
            ],
            'active': [
                'amass_active', 'dnsrecon', 'fierce', 'dnsenum'
            ],
            'web': [
                'httpx', 'gobuster', 'ffuf', 'dirb', 'wfuzz'
            ],
            'network': [
                'nmap', 'masscan', 'zmap', 'unicornscan'
            ]
        }
    
    def show_banner(self):
        """Display reconnaissance banner"""
        banner = f"""
{Fore.BLUE}
╔══════════════════════════════════════════════════════════════════════════╗
║                  {Fore.YELLOW}WebRaptor Advanced Reconnaissance v{version}{Fore.BLUE}                ║
║            Comprehensive Intelligence Gathering & Asset Discovery        ║
║                        Author: LakshmikanthanK (@letchu_pkt)             ║
║                                                                          ║
╚══════════════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""
        print(banner)
    
    def check_tools_installed(self) -> Dict[str, bool]:
        """Check which reconnaissance tools are installed"""
        tools = ['amass', 'subfinder', 'httpx', 'nmap', 'gobuster', 'ffuf']
        status = {}
        
        for tool in tools:
            status[tool] = self.tool_manager.check_tool_installed(tool)
        
        return status
    
    def install_missing_tools(self, tools_status: Dict[str, bool]) -> bool:
        """Install missing reconnaissance tools"""
        missing_tools = [tool for tool, installed in tools_status.items() if not installed]
        
        if not missing_tools:
            return True
        
        print(f"{Fore.YELLOW}[!] Missing tools: {', '.join(missing_tools)}{Style.RESET_ALL}")
        install = input("Install missing tools? (y/n): ").strip().lower()
        
        if install == 'y':
            for tool in missing_tools:
                print(f"{Fore.CYAN}[*] Installing {tool}...{Style.RESET_ALL}")
                success = self.tool_manager.install_tool(tool)
                if success:
                    tools_status[tool] = True
                else:
                    print(f"{Fore.RED}[-] Failed to install {tool}{Style.RESET_ALL}")
                    return False
            return True
        else:
            print(f"{Fore.RED}[-] Cannot proceed without required tools{Style.RESET_ALL}")
            return False
    
    def run_passive_reconnaissance(self, target: str) -> Dict:
        """Run passive reconnaissance using multiple sources"""
        print(f"{Fore.BLUE}[*] Starting passive reconnaissance for {target}...{Style.RESET_ALL}")
        
        all_subdomains = set()
        results = {
            'target': target,
            'phase': 'passive',
            'subdomains': [],
            'sources_used': [],
            'start_time': time.time()
        }
        
        # Run Amass passive
        if self.tool_manager.check_tool_installed('amass'):
            print(f"{Fore.CYAN}[*] Running Amass passive enumeration...{Style.RESET_ALL}")
            amass_subdomains = self._run_amass_passive(target)
            all_subdomains.update(amass_subdomains)
            results['sources_used'].append('amass_passive')
        
        # Run Subfinder
        if self.tool_manager.check_tool_installed('subfinder'):
            print(f"{Fore.CYAN}[*] Running Subfinder enumeration...{Style.RESET_ALL}")
            subfinder_subdomains = self._run_subfinder(target)
            all_subdomains.update(subfinder_subdomains)
            results['sources_used'].append('subfinder')
        
        # Run additional passive sources
        additional_subdomains = self._run_additional_passive_sources(target)
        all_subdomains.update(additional_subdomains)
        
        results['subdomains'] = list(all_subdomains)
        results['total_found'] = len(all_subdomains)
        results['end_time'] = time.time()
        results['duration'] = results['end_time'] - results['start_time']
        
        print(f"{Fore.GREEN}[+] Passive reconnaissance completed: {len(all_subdomains)} subdomains found{Style.RESET_ALL}")
        return results
    
    def run_active_reconnaissance(self, target: str, subdomains: List[str]) -> Dict:
        """Run active reconnaissance on discovered subdomains"""
        print(f"{Fore.BLUE}[*] Starting active reconnaissance...{Style.RESET_ALL}")
        
        results = {
            'target': target,
            'phase': 'active',
            'live_hosts': [],
            'technologies': {},
            'ports': {},
            'web_apps': [],
            'start_time': time.time()
        }
        
        # HTTPx for live host detection
        if self.tool_manager.check_tool_installed('httpx') and subdomains:
            print(f"{Fore.CYAN}[*] Detecting live hosts with HTTPx...{Style.RESET_ALL}")
            live_hosts = self._run_httpx(subdomains)
            results['live_hosts'] = live_hosts
            
            # Technology detection on live hosts
            if live_hosts:
                print(f"{Fore.CYAN}[*] Detecting technologies...{Style.RESET_ALL}")
                technologies = self._detect_technologies(live_hosts)
                results['technologies'] = technologies
        
        # Port scanning on live hosts
        if self.recon_config['port_scanning'] and results['live_hosts']:
            print(f"{Fore.CYAN}[*] Running port scans...{Style.RESET_ALL}")
            port_results = self._run_port_scanning(results['live_hosts'])
            results['ports'] = port_results
        
        # Web application discovery
        if self.recon_config['web_crawling'] and results['live_hosts']:
            print(f"{Fore.CYAN}[*] Discovering web applications...{Style.RESET_ALL}")
            web_apps = self._discover_web_applications(results['live_hosts'])
            results['web_apps'] = web_apps
        
        results['end_time'] = time.time()
        results['duration'] = results['end_time'] - results['start_time']
        
        print(f"{Fore.GREEN}[+] Active reconnaissance completed: {len(results['live_hosts'])} live hosts found{Style.RESET_ALL}")
        return results
    
    def _run_amass_passive(self, target: str) -> List[str]:
        """Run Amass passive enumeration"""
        try:
            args = ['-passive', '-d', target, '-silent']
            success, stdout, stderr = self.tool_manager.run_tool('amass', args, timeout=300)
            
            if success:
                subdomains = [line.strip() for line in stdout.split('\n') if line.strip()]
                print(f"{Fore.GREEN}[+] Amass found {len(subdomains)} subdomains{Style.RESET_ALL}")
                return subdomains
            else:
                print(f"{Fore.RED}[-] Amass failed: {stderr}{Style.RESET_ALL}")
                return []
        except Exception as e:
            print(f"{Fore.RED}[-] Error running Amass: {e}{Style.RESET_ALL}")
            return []
    
    def _run_subfinder(self, target: str) -> List[str]:
        """Run Subfinder enumeration"""
        try:
            args = ['-d', target, '-silent', '-all-sources']
            success, stdout, stderr = self.tool_manager.run_tool('subfinder', args, timeout=300)
            
            if success:
                subdomains = [line.strip() for line in stdout.split('\n') if line.strip()]
                print(f"{Fore.GREEN}[+] Subfinder found {len(subdomains)} subdomains{Style.RESET_ALL}")
                return subdomains
            else:
                print(f"{Fore.RED}[-] Subfinder failed: {stderr}{Style.RESET_ALL}")
                return []
        except Exception as e:
            print(f"{Fore.RED}[-] Error running Subfinder: {e}{Style.RESET_ALL}")
            return []
    
    def _run_additional_passive_sources(self, target: str) -> List[str]:
        """Run additional passive reconnaissance sources"""
        subdomains = set()
        
        # Certificate Transparency logs
        print(f"{Fore.CYAN}[*] Checking Certificate Transparency logs...{Style.RESET_ALL}")
        ct_subdomains = self._check_certificate_transparency(target)
        subdomains.update(ct_subdomains)
        
        # DNS records
        print(f"{Fore.CYAN}[*] Enumerating DNS records...{Style.RESET_ALL}")
        dns_subdomains = self._enumerate_dns_records(target)
        subdomains.update(dns_subdomains)
        
        return list(subdomains)
    
    def _check_certificate_transparency(self, target: str) -> List[str]:
        """Check Certificate Transparency logs"""
        subdomains = set()
        
        try:
            import requests
            
            # crt.sh API
            url = f"https://crt.sh/?q=%25.{target}&output=json"
            response = requests.get(url, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                for item in data:
                    names = item.get('name_value', '').split('\n')
                    for name in names:
                        name = name.strip().lower()
                        if name.endswith(f'.{target}') and name != target:
                            subdomains.add(name)
            
            print(f"{Fore.GREEN}[+] Certificate Transparency: {len(subdomains)} subdomains{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.YELLOW}[!] CT check error: {e}{Style.RESET_ALL}")
        
        return list(subdomains)
    
    def _enumerate_dns_records(self, target: str) -> List[str]:
        """Enumerate DNS records"""
        subdomains = set()
        
        try:
            import dns.resolver
            
            # Common subdomain patterns
            common_subdomains = [
                'www', 'mail', 'ftp', 'smtp', 'pop', 'imap', 'ns1', 'ns2',
                'admin', 'test', 'dev', 'staging', 'api', 'cdn', 'static',
                'blog', 'forum', 'shop', 'store', 'news', 'support'
            ]
            
            for subdomain in common_subdomains:
                try:
                    full_domain = f"{subdomain}.{target}"
                    dns.resolver.resolve(full_domain, 'A')
                    subdomains.add(full_domain)
                except:
                    pass
            
            print(f"{Fore.GREEN}[+] DNS enumeration: {len(subdomains)} subdomains{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.YELLOW}[!] DNS enumeration error: {e}{Style.RESET_ALL}")
        
        return list(subdomains)
    
    def _run_httpx(self, subdomains: List[str]) -> List[str]:
        """Run HTTPx to detect live hosts"""
        try:
            # Write subdomains to temporary file
            subdomains_file = self.temp_dir / "subdomains.txt"
            with open(subdomains_file, 'w') as f:
                for subdomain in subdomains:
                    f.write(f"{subdomain}\n")
            
            # Run HTTPx
            args = ['-l', str(subdomains_file), '-silent', '-json', '-tech-detect']
            success, stdout, stderr = self.tool_manager.run_tool('httpx', args, timeout=600)
            
            live_hosts = []
            if success:
                for line in stdout.split('\n'):
                    if line.strip():
                        try:
                            data = json.loads(line)
                            if data.get('status_code') in [200, 301, 302, 403]:
                                live_hosts.append(data.get('url', ''))
                        except json.JSONDecodeError:
                            continue
            
            print(f"{Fore.GREEN}[+] HTTPx found {len(live_hosts)} live hosts{Style.RESET_ALL}")
            return live_hosts
        except Exception as e:
            print(f"{Fore.RED}[-] Error running HTTPx: {e}{Style.RESET_ALL}")
            return []
    
    def _detect_technologies(self, live_hosts: List[str]) -> Dict:
        """Detect technologies on live hosts"""
        technologies = {}
        
        try:
            import requests
            from bs4 import BeautifulSoup
            
            tech_patterns = {
                'wordpress': ['wp-content', 'wp-includes', 'wp-admin'],
                'drupal': ['drupal', 'sites/default'],
                'joomla': ['joomla', 'administrator'],
                'apache': ['apache', 'Server: Apache'],
                'nginx': ['nginx', 'Server: nginx'],
                'php': ['php', 'PHP/'],
                'asp': ['asp', 'ASP.NET'],
                'jquery': ['jquery', 'jQuery'],
                'bootstrap': ['bootstrap', 'Bootstrap']
            }
            
            for host in live_hosts[:10]:  # Limit to first 10 hosts
                try:
                    response = requests.get(host, timeout=10, allow_redirects=True)
                    content = response.text.lower()
                    headers = str(response.headers).lower()
                    
                    host_techs = []
                    for tech, patterns in tech_patterns.items():
                        for pattern in patterns:
                            if pattern.lower() in content or pattern.lower() in headers:
                                host_techs.append(tech)
                                break
                    
                    if host_techs:
                        technologies[host] = host_techs
                        
                except Exception:
                    continue
            
            print(f"{Fore.GREEN}[+] Technology detection completed on {len(technologies)} hosts{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.YELLOW}[!] Technology detection error: {e}{Style.RESET_ALL}")
        
        return technologies
    
    def _run_port_scanning(self, live_hosts: List[str]) -> Dict:
        """Run port scanning on live hosts"""
        port_results = {}
        
        if not self.tool_manager.check_tool_installed('nmap'):
            print(f"{Fore.YELLOW}[!] Nmap not available for port scanning{Style.RESET_ALL}")
            return port_results
        
        for host in live_hosts[:5]:  # Limit to first 5 hosts
            try:
                # Extract IP from URL
                import urllib.parse
                parsed = urllib.parse.urlparse(host)
                hostname = parsed.hostname
                
                if hostname:
                    print(f"{Fore.CYAN}[*] Scanning ports on {hostname}...{Style.RESET_ALL}")
                    args = ['-sS', '-T4', '-F', '--open', hostname]
                    success, stdout, stderr = self.tool_manager.run_tool('nmap', args, timeout=300)
                    
                    if success:
                        open_ports = self._parse_nmap_output(stdout)
                        port_results[hostname] = open_ports
                        print(f"{Fore.GREEN}[+] Found {len(open_ports)} open ports on {hostname}{Style.RESET_ALL}")
                    
            except Exception as e:
                print(f"{Fore.YELLOW}[!] Port scan error for {host}: {e}{Style.RESET_ALL}")
        
        return port_results
    
    def _parse_nmap_output(self, output: str) -> List[Dict]:
        """Parse Nmap output to extract open ports"""
        open_ports = []
        lines = output.split('\n')
        
        for line in lines:
            if '/tcp' in line and 'open' in line:
                parts = line.split()
                if len(parts) >= 3:
                    port_info = parts[0].split('/')
                    if len(port_info) == 2:
                        port = port_info[0]
                        protocol = port_info[1]
                        state = parts[1]
                        service = parts[2] if len(parts) > 2 else 'unknown'
                        
                        open_ports.append({
                            'port': int(port),
                            'protocol': protocol,
                            'state': state,
                            'service': service
                        })
        
        return open_ports
    
    def _discover_web_applications(self, live_hosts: List[str]) -> List[Dict]:
        """Discover web applications and directories"""
        web_apps = []
        
        if not self.tool_manager.check_tool_installed('gobuster'):
            print(f"{Fore.YELLOW}[!] Gobuster not available for web discovery{Style.RESET_ALL}")
            return web_apps
        
        for host in live_hosts[:3]:  # Limit to first 3 hosts
            try:
                print(f"{Fore.CYAN}[*] Discovering web applications on {host}...{Style.RESET_ALL}")
                args = ['-u', host, '-w', 'wordlists/common.txt', '-q', '-t', '20']
                success, stdout, stderr = self.tool_manager.run_tool('gobuster', args, timeout=300)
                
                if success:
                    directories = self._parse_gobuster_output(stdout)
                    web_apps.append({
                        'host': host,
                        'directories': directories
                    })
                    print(f"{Fore.GREEN}[+] Found {len(directories)} directories on {host}{Style.RESET_ALL}")
                
            except Exception as e:
                print(f"{Fore.YELLOW}[!] Web discovery error for {host}: {e}{Style.RESET_ALL}")
        
        return web_apps
    
    def _parse_gobuster_output(self, output: str) -> List[str]:
        """Parse Gobuster output to extract directories"""
        directories = []
        lines = output.split('\n')
        
        for line in lines:
            if 'Status:' in line and '200' in line:
                parts = line.split()
                if len(parts) >= 2:
                    directory = parts[0]
                    directories.append(directory)
        
        return directories
    
    def save_results(self, passive_results: Dict, active_results: Dict, target: str):
        """Save reconnaissance results"""
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        
        # Combine results
        combined_results = {
            'target': target,
            'scan_date': time.strftime('%Y-%m-%d %H:%M:%S'),
            'passive_recon': passive_results,
            'active_recon': active_results,
            'summary': {
                'total_subdomains': len(passive_results.get('subdomains', [])),
                'live_hosts': len(active_results.get('live_hosts', [])),
                'technologies_detected': len(active_results.get('technologies', {})),
                'open_ports': sum(len(ports) for ports in active_results.get('ports', {}).values()),
                'web_applications': len(active_results.get('web_apps', []))
            }
        }
        
        # Save JSON report
        json_file = self.results_dir / f"recon_{target.replace('.', '_')}_{timestamp}.json"
        with open(json_file, 'w') as f:
            json.dump(combined_results, f, indent=2)
        
        print(f"{Fore.GREEN}[+] Reconnaissance results saved to: {json_file}{Style.RESET_ALL}")
        return str(json_file)
    
    def display_results(self, passive_results: Dict, active_results: Dict):
        """Display reconnaissance results"""
        print(f"\n{Fore.BLUE}╔══════════════════════════════════════════════════════════════════════════╗")
        print(f"║                      RECONNAISSANCE RESULTS                         ║")
        print(f"╚══════════════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}")
        
        # Passive reconnaissance summary
        print(f"\n{Fore.CYAN}📡 Passive Reconnaissance:{Style.RESET_ALL}")
        print(f"  Subdomains Found: {len(passive_results.get('subdomains', []))}")
        print(f"  Sources Used: {', '.join(passive_results.get('sources_used', []))}")
        print(f"  Duration: {passive_results.get('duration', 0):.2f}s")
        
        # Active reconnaissance summary
        print(f"\n{Fore.CYAN}🎯 Active Reconnaissance:{Style.RESET_ALL}")
        print(f"  Live Hosts: {len(active_results.get('live_hosts', []))}")
        print(f"  Technologies Detected: {len(active_results.get('technologies', {}))}")
        print(f"  Open Ports: {sum(len(ports) for ports in active_results.get('ports', {}).values())}")
        print(f"  Web Applications: {len(active_results.get('web_apps', []))}")
        
        # Show top subdomains
        subdomains = passive_results.get('subdomains', [])
        if subdomains:
            print(f"\n{Fore.CYAN}🌐 Top Subdomains:{Style.RESET_ALL}")
            for i, subdomain in enumerate(subdomains[:10], 1):
                print(f"  {i:2d}. {subdomain}")
            if len(subdomains) > 10:
                print(f"  ... and {len(subdomains) - 10} more")
        
        # Show technologies
        technologies = active_results.get('technologies', {})
        if technologies:
            print(f"\n{Fore.CYAN}🔧 Technologies Detected:{Style.RESET_ALL}")
            all_techs = set()
            for host_techs in technologies.values():
                all_techs.update(host_techs)
            for tech in sorted(all_techs):
                print(f"  • {tech}")

def run(target):
    """Main entry point for advanced reconnaissance module"""
    try:
        recon = AdvancedReconnaissance()
        recon.show_banner()
        
        # Check tools
        tools_status = recon.check_tools_installed()
        if not recon.install_missing_tools(tools_status):
            return
        
        print(f"{Fore.BLUE}[*] Starting comprehensive reconnaissance for {target}...{Style.RESET_ALL}")
        
        # Phase 1: Passive reconnaissance
        passive_results = recon.run_passive_reconnaissance(target)
        
        # Phase 2: Active reconnaissance
        subdomains = passive_results.get('subdomains', [])
        active_results = recon.run_active_reconnaissance(target, subdomains)
        
        # Save and display results
        results_file = recon.save_results(passive_results, active_results, target)
        recon.display_results(passive_results, active_results)
        
        print(f"\n{Fore.GREEN}[+] Advanced reconnaissance completed successfully!{Style.RESET_ALL}")
        
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Reconnaissance interrupted by user{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[-] Error in reconnaissance: {e}{Style.RESET_ALL}")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        run(sys.argv[1])
    else:
        print("Usage: python advanced_recon.py <target_domain>")
