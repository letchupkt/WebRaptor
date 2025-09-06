#!/usr/bin/env python3
"""
WebRaptor Advanced Tools Integration Module
Comprehensive integration of multiple advanced security tools
"""

import os
import sys
import json
import subprocess
import time
import threading
from pathlib import Path
from typing import Dict, List, Optional, Any, Set
from colorama import Fore, Style, init
from datetime import datetime
import requests
import re
from urllib.parse import urlparse, urljoin
import concurrent.futures
import tempfile

init()

# Module metadata
description = "Comprehensive integration of multiple advanced security tools"
author = "LakshmikanthanK (@letchu_pkt)"
version = "2.1"

class AdvancedToolsIntegration:
    """Advanced tools integration for WebRaptor"""
    
    def __init__(self):
        self.results = []
        self.config = {
            'timeout': 600,
            'threads': 20,
            'output_dir': 'output/scans/advanced_tools',
            'tools': {
                'wfuzz': {
                    'enabled': True,
                    'wordlist': 'wordlists/directories.txt',
                    'extensions': ['.php', '.asp', '.aspx', '.jsp', '.html'],
                    'threads': 50
                },
                'dirb': {
                    'enabled': True,
                    'wordlist': '/usr/share/dirb/wordlists/common.txt',
                    'extensions': ['.php', '.asp', '.aspx', '.jsp', '.html']
                },
                'gobuster': {
                    'enabled': True,
                    'wordlist': 'wordlists/directories.txt',
                    'extensions': ['.php', '.asp', '.aspx', '.jsp', '.html'],
                    'threads': 50
                },
                'ffuf': {
                    'enabled': True,
                    'wordlist': 'wordlists/directories.txt',
                    'extensions': ['.php', '.asp', '.aspx', '.jsp', '.html'],
                    'threads': 50
                },
                'whatweb': {
                    'enabled': True,
                    'aggression': 1
                },
                'wafw00f': {
                    'enabled': True
                },
                'dnsrecon': {
                    'enabled': True,
                    'threads': 10
                },
                'theharvester': {
                    'enabled': True,
                    'sources': ['baidu', 'bing', 'duckduckgo', 'google', 'yahoo']
                },
                'sublist3r': {
                    'enabled': True,
                    'threads': 10
                },
                'knockpy': {
                    'enabled': True,
                    'threads': 10
                },
                'assetfinder': {
                    'enabled': True
                },
                'findomain': {
                    'enabled': True,
                    'threads': 10
                },
                'chaos': {
                    'enabled': True
                },
                'shuffledns': {
                    'enabled': True,
                    'wordlist': 'wordlists/subdomains.txt',
                    'threads': 50
                },
                'dnsx': {
                    'enabled': True,
                    'threads': 50
                },
                'katana': {
                    'enabled': True,
                    'depth': 2,
                    'threads': 10
                },
                'unfurl': {
                    'enabled': True
                },
                'qsreplace': {
                    'enabled': True
                },
                'linkfinder': {
                    'enabled': True
                },
                'secretfinder': {
                    'enabled': True
                },
                'jsfinder': {
                    'enabled': True
                },
                'paramspider': {
                    'enabled': True,
                    'depth': 2
                },
                'arjun': {
                    'enabled': True,
                    'threads': 10
                },
                'masscan': {
                    'enabled': True,
                    'rate': 1000,
                    'ports': '1-65535'
                },
                'zap': {
                    'enabled': False,  # Requires manual setup
                    'port': 8080
                },
                'burpsuite': {
                    'enabled': False,  # Requires manual setup
                    'port': 8080
                }
            }
        }
        
        # Create output directory
        Path(self.config['output_dir']).mkdir(parents=True, exist_ok=True)
        
        # Tool status
        self.tool_status = {}
        self.scan_results = {}
    
    def show_banner(self):
        """Display advanced tools integration banner"""
        banner = f"""
{Fore.BLUE}╔══════════════════════════════════════════════════════════════════════════╗
║                {Fore.YELLOW}WebRaptor Advanced Tools Integration v{version}{Fore.BLUE}               ║
║                    Comprehensive Security Tool Orchestration             ║
║                        Author: LakshmikanthanK (@letchu_pkt)             ║
║                                                                          ║
╚══════════════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""
        print(banner)
    
    def check_tool_installed(self, tool_name: str) -> bool:
        """Check if a tool is installed"""
        try:
            if tool_name == 'wfuzz':
                result = subprocess.run(['wfuzz', '--help'], 
                                     capture_output=True, text=True, timeout=10)
            elif tool_name == 'dirb':
                result = subprocess.run(['dirb', '--help'], 
                                     capture_output=True, text=True, timeout=10)
            elif tool_name == 'gobuster':
                result = subprocess.run(['gobuster', 'version'], 
                                     capture_output=True, text=True, timeout=10)
            elif tool_name == 'ffuf':
                result = subprocess.run(['ffuf', '-V'], 
                                     capture_output=True, text=True, timeout=10)
            elif tool_name == 'whatweb':
                result = subprocess.run(['whatweb', '--version'], 
                                     capture_output=True, text=True, timeout=10)
            elif tool_name == 'wafw00f':
                result = subprocess.run(['wafw00f', '--help'], 
                                     capture_output=True, text=True, timeout=10)
            elif tool_name == 'dnsrecon':
                result = subprocess.run(['dnsrecon', '--help'], 
                                     capture_output=True, text=True, timeout=10)
            elif tool_name == 'theharvester':
                result = subprocess.run(['theHarvester', '--help'], 
                                     capture_output=True, text=True, timeout=10)
            elif tool_name == 'sublist3r':
                result = subprocess.run(['sublist3r', '--help'], 
                                     capture_output=True, text=True, timeout=10)
            elif tool_name == 'knockpy':
                result = subprocess.run(['knockpy', '--version'], 
                                     capture_output=True, text=True, timeout=10)
            elif tool_name == 'assetfinder':
                result = subprocess.run(['assetfinder', '-h'], 
                                     capture_output=True, text=True, timeout=10)
            elif tool_name == 'findomain':
                result = subprocess.run(['findomain', '--version'], 
                                     capture_output=True, text=True, timeout=10)
            elif tool_name == 'chaos':
                result = subprocess.run(['chaos', '-version'], 
                                     capture_output=True, text=True, timeout=10)
            elif tool_name == 'shuffledns':
                result = subprocess.run(['shuffledns', '-version'], 
                                     capture_output=True, text=True, timeout=10)
            elif tool_name == 'dnsx':
                result = subprocess.run(['dnsx', '-version'], 
                                     capture_output=True, text=True, timeout=10)
            elif tool_name == 'katana':
                result = subprocess.run(['katana', '-version'], 
                                     capture_output=True, text=True, timeout=10)
            elif tool_name == 'unfurl':
                result = subprocess.run(['unfurl', '-h'], 
                                     capture_output=True, text=True, timeout=10)
            elif tool_name == 'qsreplace':
                result = subprocess.run(['qsreplace', '-h'], 
                                     capture_output=True, text=True, timeout=10)
            elif tool_name == 'linkfinder':
                result = subprocess.run(['python3', 'LinkFinder.py', '--help'], 
                                     capture_output=True, text=True, timeout=10)
            elif tool_name == 'secretfinder':
                result = subprocess.run(['python3', 'SecretFinder.py', '--help'], 
                                     capture_output=True, text=True, timeout=10)
            elif tool_name == 'jsfinder':
                result = subprocess.run(['python3', 'JSFinder.py', '--help'], 
                                     capture_output=True, text=True, timeout=10)
            elif tool_name == 'paramspider':
                result = subprocess.run(['python3', 'paramspider.py', '--help'], 
                                     capture_output=True, text=True, timeout=10)
            elif tool_name == 'arjun':
                result = subprocess.run(['arjun', '--version'], 
                                     capture_output=True, text=True, timeout=10)
            elif tool_name == 'masscan':
                result = subprocess.run(['masscan', '--version'], 
                                     capture_output=True, text=True, timeout=10)
            else:
                return False
            
            return result.returncode == 0
            
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False
    
    def check_all_tools(self) -> Dict[str, bool]:
        """Check status of all tools"""
        print(f"{Fore.BLUE}[*] Checking tool installation status...{Style.RESET_ALL}")
        
        tool_status = {}
        for tool_name in self.config['tools'].keys():
            tool_status[tool_name] = self.check_tool_installed(tool_name)
            status = f"{Fore.GREEN}✓{Style.RESET_ALL}" if tool_status[tool_name] else f"{Fore.RED}✗{Style.RESET_ALL}"
            print(f"  {status} {tool_name}")
        
        self.tool_status = tool_status
        return tool_status
    
    def run_directory_bruteforce(self, target: str) -> Dict:
        """Run directory bruteforce with multiple tools"""
        print(f"{Fore.BLUE}[*] Running directory bruteforce on {target}{Style.RESET_ALL}")
        
        results = {
            'target': target,
            'timestamp': datetime.now().isoformat(),
            'tools_used': [],
            'directories_found': set(),
            'files_found': set(),
            'status_codes': {},
            'errors': []
        }
        
        # WFuzz
        if self.config['tools']['wfuzz']['enabled'] and self.tool_status.get('wfuzz', False):
            try:
                wfuzz_results = self._run_wfuzz(target)
                if wfuzz_results:
                    results['tools_used'].append('wfuzz')
                    results['directories_found'].update(wfuzz_results.get('directories', []))
                    results['files_found'].update(wfuzz_results.get('files', []))
                    results['status_codes'].update(wfuzz_results.get('status_codes', {}))
            except Exception as e:
                results['errors'].append(f"WFuzz error: {e}")
        
        # Dirb
        if self.config['tools']['dirb']['enabled'] and self.tool_status.get('dirb', False):
            try:
                dirb_results = self._run_dirb(target)
                if dirb_results:
                    results['tools_used'].append('dirb')
                    results['directories_found'].update(dirb_results.get('directories', []))
                    results['files_found'].update(dirb_results.get('files', []))
                    results['status_codes'].update(dirb_results.get('status_codes', {}))
            except Exception as e:
                results['errors'].append(f"Dirb error: {e}")
        
        # Gobuster
        if self.config['tools']['gobuster']['enabled'] and self.tool_status.get('gobuster', False):
            try:
                gobuster_results = self._run_gobuster(target)
                if gobuster_results:
                    results['tools_used'].append('gobuster')
                    results['directories_found'].update(gobuster_results.get('directories', []))
                    results['files_found'].update(gobuster_results.get('files', []))
                    results['status_codes'].update(gobuster_results.get('status_codes', {}))
            except Exception as e:
                results['errors'].append(f"Gobuster error: {e}")
        
        # FFuF
        if self.config['tools']['ffuf']['enabled'] and self.tool_status.get('ffuf', False):
            try:
                ffuf_results = self._run_ffuf(target)
                if ffuf_results:
                    results['tools_used'].append('ffuf')
                    results['directories_found'].update(ffuf_results.get('directories', []))
                    results['files_found'].update(ffuf_results.get('files', []))
                    results['status_codes'].update(ffuf_results.get('status_codes', {}))
            except Exception as e:
                results['errors'].append(f"FFuF error: {e}")
        
        # Convert sets to lists for JSON serialization
        results['directories_found'] = list(results['directories_found'])
        results['files_found'] = list(results['files_found'])
        
        return results
    
    def _run_wfuzz(self, target: str) -> Optional[Dict]:
        """Run WFuzz directory bruteforce"""
        print(f"{Fore.CYAN}[*] Running WFuzz on {target}{Style.RESET_ALL}")
        
        try:
            cmd = [
                'wfuzz', '-c', '-z', 'file,wordlists/directories.txt',
                '--hc', '404', '-t', str(self.config['tools']['wfuzz']['threads']),
                target + '/FUZZ'
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, 
                                 timeout=self.config['timeout'])
            
            if result.returncode == 0:
                return self._parse_wfuzz_output(result.stdout)
            else:
                print(f"{Fore.RED}[-] WFuzz error: {result.stderr}{Style.RESET_ALL}")
                return None
                
        except subprocess.TimeoutExpired:
            print(f"{Fore.RED}[-] WFuzz timeout{Style.RESET_ALL}")
            return None
        except Exception as e:
            print(f"{Fore.RED}[-] WFuzz error: {e}{Style.RESET_ALL}")
            return None
    
    def _run_dirb(self, target: str) -> Optional[Dict]:
        """Run Dirb directory bruteforce"""
        print(f"{Fore.CYAN}[*] Running Dirb on {target}{Style.RESET_ALL}")
        
        try:
            cmd = ['dirb', target, self.config['tools']['dirb']['wordlist']]
            
            result = subprocess.run(cmd, capture_output=True, text=True, 
                                 timeout=self.config['timeout'])
            
            if result.returncode == 0:
                return self._parse_dirb_output(result.stdout)
            else:
                print(f"{Fore.RED}[-] Dirb error: {result.stderr}{Style.RESET_ALL}")
                return None
                
        except subprocess.TimeoutExpired:
            print(f"{Fore.RED}[-] Dirb timeout{Style.RESET_ALL}")
            return None
        except Exception as e:
            print(f"{Fore.RED}[-] Dirb error: {e}{Style.RESET_ALL}")
            return None
    
    def _run_gobuster(self, target: str) -> Optional[Dict]:
        """Run Gobuster directory bruteforce"""
        print(f"{Fore.CYAN}[*] Running Gobuster on {target}{Style.RESET_ALL}")
        
        try:
            cmd = [
                'gobuster', 'dir', '-u', target,
                '-w', self.config['tools']['gobuster']['wordlist'],
                '-t', str(self.config['tools']['gobuster']['threads']),
                '-q'
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, 
                                 timeout=self.config['timeout'])
            
            if result.returncode == 0:
                return self._parse_gobuster_output(result.stdout)
            else:
                print(f"{Fore.RED}[-] Gobuster error: {result.stderr}{Style.RESET_ALL}")
                return None
                
        except subprocess.TimeoutExpired:
            print(f"{Fore.RED}[-] Gobuster timeout{Style.RESET_ALL}")
            return None
        except Exception as e:
            print(f"{Fore.RED}[-] Gobuster error: {e}{Style.RESET_ALL}")
            return None
    
    def _run_ffuf(self, target: str) -> Optional[Dict]:
        """Run FFuF directory bruteforce"""
        print(f"{Fore.CYAN}[*] Running FFuF on {target}{Style.RESET_ALL}")
        
        try:
            cmd = [
                'ffuf', '-w', self.config['tools']['ffuf']['wordlist'],
                '-u', target + '/FUZZ',
                '-t', str(self.config['tools']['ffuf']['threads']),
                '-fs', '0', '-mc', '200,301,302,403'
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, 
                                 timeout=self.config['timeout'])
            
            if result.returncode == 0:
                return self._parse_ffuf_output(result.stdout)
            else:
                print(f"{Fore.RED}[-] FFuF error: {result.stderr}{Style.RESET_ALL}")
                return None
                
        except subprocess.TimeoutExpired:
            print(f"{Fore.RED}[-] FFuF timeout{Style.RESET_ALL}")
            return None
        except Exception as e:
            print(f"{Fore.RED}[-] FFuF error: {e}{Style.RESET_ALL}")
            return None
    
    def _parse_wfuzz_output(self, output: str) -> Dict:
        """Parse WFuzz output"""
        results = {
            'directories': set(),
            'files': set(),
            'status_codes': {}
        }
        
        lines = output.split('\n')
        for line in lines:
            if '200' in line or '301' in line or '302' in line or '403' in line:
                parts = line.split()
                if len(parts) >= 3:
                    status_code = parts[1]
                    path = parts[2]
                    
                    if status_code.isdigit():
                        results['status_codes'][int(status_code)] = results['status_codes'].get(int(status_code), 0) + 1
                        
                        if path.endswith('/'):
                            results['directories'].add(path)
                        else:
                            results['files'].add(path)
        
        return results
    
    def _parse_dirb_output(self, output: str) -> Dict:
        """Parse Dirb output"""
        results = {
            'directories': set(),
            'files': set(),
            'status_codes': {}
        }
        
        lines = output.split('\n')
        for line in lines:
            if 'CODE:' in line:
                parts = line.split()
                if len(parts) >= 2:
                    status_code = parts[1].replace('CODE:', '')
                    path = parts[0]
                    
                    if status_code.isdigit():
                        results['status_codes'][int(status_code)] = results['status_codes'].get(int(status_code), 0) + 1
                        
                        if path.endswith('/'):
                            results['directories'].add(path)
                        else:
                            results['files'].add(path)
        
        return results
    
    def _parse_gobuster_output(self, output: str) -> Dict:
        """Parse Gobuster output"""
        results = {
            'directories': set(),
            'files': set(),
            'status_codes': {}
        }
        
        lines = output.split('\n')
        for line in lines:
            if line.strip() and not line.startswith('Gobuster'):
                parts = line.split()
                if len(parts) >= 2:
                    status_code = parts[1]
                    path = parts[0]
                    
                    if status_code.isdigit():
                        results['status_codes'][int(status_code)] = results['status_codes'].get(int(status_code), 0) + 1
                        
                        if path.endswith('/'):
                            results['directories'].add(path)
                        else:
                            results['files'].add(path)
        
        return results
    
    def _parse_ffuf_output(self, output: str) -> Dict:
        """Parse FFuF output"""
        results = {
            'directories': set(),
            'files': set(),
            'status_codes': {}
        }
        
        lines = output.split('\n')
        for line in lines:
            if line.strip() and not line.startswith('ffuf'):
                parts = line.split()
                if len(parts) >= 2:
                    status_code = parts[1]
                    path = parts[0]
                    
                    if status_code.isdigit():
                        results['status_codes'][int(status_code)] = results['status_codes'].get(int(status_code), 0) + 1
                        
                        if path.endswith('/'):
                            results['directories'].add(path)
                        else:
                            results['files'].add(path)
        
        return results
    
    def run_technology_detection(self, target: str) -> Dict:
        """Run technology detection with WhatWeb"""
        print(f"{Fore.BLUE}[*] Running technology detection on {target}{Style.RESET_ALL}")
        
        if not self.config['tools']['whatweb']['enabled'] or not self.tool_status.get('whatweb', False):
            return {'error': 'WhatWeb not available'}
        
        try:
            cmd = [
                'whatweb', '--aggression', str(self.config['tools']['whatweb']['aggression']),
                '--no-errors', target
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, 
                                 timeout=self.config['timeout'])
            
            if result.returncode == 0:
                return self._parse_whatweb_output(result.stdout)
            else:
                return {'error': f'WhatWeb error: {result.stderr}'}
                
        except subprocess.TimeoutExpired:
            return {'error': 'WhatWeb timeout'}
        except Exception as e:
            return {'error': f'WhatWeb error: {e}'}
    
    def _parse_whatweb_output(self, output: str) -> Dict:
        """Parse WhatWeb output"""
        results = {
            'technologies': [],
            'server': None,
            'cms': None,
            'framework': None,
            'language': None
        }
        
        lines = output.split('\n')
        for line in lines:
            if '[' in line and ']' in line:
                # Extract technology information
                tech_info = line.split('[')[1].split(']')[0]
                results['technologies'].append(tech_info)
                
                # Parse specific technologies
                if 'Server' in tech_info:
                    results['server'] = tech_info
                elif any(cms in tech_info.lower() for cms in ['wordpress', 'drupal', 'joomla']):
                    results['cms'] = tech_info
                elif any(fw in tech_info.lower() for fw in ['django', 'flask', 'rails', 'laravel']):
                    results['framework'] = tech_info
                elif any(lang in tech_info.lower() for lang in ['php', 'asp', 'jsp', 'python']):
                    results['language'] = tech_info
        
        return results
    
    def run_waf_detection(self, target: str) -> Dict:
        """Run WAF detection with WAFW00F"""
        print(f"{Fore.BLUE}[*] Running WAF detection on {target}{Style.RESET_ALL}")
        
        if not self.config['tools']['wafw00f']['enabled'] or not self.tool_status.get('wafw00f', False):
            return {'error': 'WAFW00F not available'}
        
        try:
            cmd = ['wafw00f', target]
            
            result = subprocess.run(cmd, capture_output=True, text=True, 
                                 timeout=self.config['timeout'])
            
            if result.returncode == 0:
                return self._parse_wafw00f_output(result.stdout)
            else:
                return {'error': f'WAFW00F error: {result.stderr}'}
                
        except subprocess.TimeoutExpired:
            return {'error': 'WAFW00F timeout'}
        except Exception as e:
            return {'error': f'WAFW00F error: {e}'}
    
    def _parse_wafw00f_output(self, output: str) -> Dict:
        """Parse WAFW00F output"""
        results = {
            'waf_detected': False,
            'waf_name': None,
            'confidence': None
        }
        
        lines = output.split('\n')
        for line in lines:
            if 'WAF' in line and 'detected' in line.lower():
                results['waf_detected'] = True
                # Extract WAF name
                if ':' in line:
                    waf_name = line.split(':')[1].strip()
                    results['waf_name'] = waf_name
            elif 'confidence' in line.lower():
                # Extract confidence level
                if '%' in line:
                    confidence = line.split('%')[0].split()[-1]
                    results['confidence'] = confidence
        
        return results
    
    def run_comprehensive_scan(self, target: str) -> Dict:
        """Run comprehensive scan with all available tools"""
        print(f"{Fore.BLUE}[*] Starting comprehensive scan on {target}{Style.RESET_ALL}")
        
        start_time = time.time()
        
        # Check tool status
        self.check_all_tools()
        
        # Initialize results
        comprehensive_results = {
            'target': target,
            'timestamp': datetime.now().isoformat(),
            'tools_status': self.tool_status,
            'directory_bruteforce': {},
            'technology_detection': {},
            'waf_detection': {},
            'errors': []
        }
        
        # Run directory bruteforce
        try:
            dir_results = self.run_directory_bruteforce(target)
            comprehensive_results['directory_bruteforce'] = dir_results
        except Exception as e:
            comprehensive_results['errors'].append(f"Directory bruteforce error: {e}")
        
        # Run technology detection
        try:
            tech_results = self.run_technology_detection(target)
            comprehensive_results['technology_detection'] = tech_results
        except Exception as e:
            comprehensive_results['errors'].append(f"Technology detection error: {e}")
        
        # Run WAF detection
        try:
            waf_results = self.run_waf_detection(target)
            comprehensive_results['waf_detection'] = waf_results
        except Exception as e:
            comprehensive_results['errors'].append(f"WAF detection error: {e}")
        
        end_time = time.time()
        comprehensive_results['duration'] = end_time - start_time
        
        # Save results
        self._save_results(comprehensive_results)
        
        return comprehensive_results
    
    def _save_results(self, results: Dict):
        """Save scan results to file"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        results_file = Path(self.config['output_dir']) / f"advanced_tools_{timestamp}.json"
        
        try:
            with open(results_file, 'w') as f:
                json.dump(results, f, indent=2)
            print(f"{Fore.GREEN}[+] Results saved to {results_file}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[-] Error saving results: {e}{Style.RESET_ALL}")
    
    def show_results(self, results: Dict):
        """Display scan results"""
        print(f"\n{Fore.BLUE}╔══════════════════════════════════════════════════════════════════════════╗")
        print(f"║                    Advanced Tools Integration Results                    ║")
        print(f"╚══════════════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}")
        
        print(f"\n{Fore.CYAN}Target:{Style.RESET_ALL} {results.get('target', 'N/A')}")
        print(f"{Fore.CYAN}Duration:{Style.RESET_ALL} {results.get('duration', 0):.2f} seconds")
        print(f"{Fore.CYAN}Timestamp:{Style.RESET_ALL} {results.get('timestamp', 'N/A')}")
        
        # Tool status
        tools_status = results.get('tools_status', {})
        print(f"\n{Fore.CYAN}Tool Status:{Style.RESET_ALL}")
        for tool, status in tools_status.items():
            status_color = Fore.GREEN if status else Fore.RED
            print(f"  {status_color}• {tool}: {'Available' if status else 'Not Available'}{Style.RESET_ALL}")
        
        # Directory bruteforce results
        dir_results = results.get('directory_bruteforce', {})
        if dir_results and not dir_results.get('error'):
            print(f"\n{Fore.CYAN}Directory Bruteforce Results:{Style.RESET_ALL}")
            print(f"  Tools Used: {', '.join(dir_results.get('tools_used', []))}")
            print(f"  Directories Found: {len(dir_results.get('directories_found', []))}")
            print(f"  Files Found: {len(dir_results.get('files_found', []))}")
            
            # Show some examples
            directories = dir_results.get('directories_found', [])[:10]
            if directories:
                print(f"  Sample Directories:")
                for dir_path in directories:
                    print(f"    • {dir_path}")
            
            files = dir_results.get('files_found', [])[:10]
            if files:
                print(f"  Sample Files:")
                for file_path in files:
                    print(f"    • {file_path}")
        
        # Technology detection results
        tech_results = results.get('technology_detection', {})
        if tech_results and not tech_results.get('error'):
            print(f"\n{Fore.CYAN}Technology Detection Results:{Style.RESET_ALL}")
            technologies = tech_results.get('technologies', [])
            if technologies:
                print(f"  Technologies Found:")
                for tech in technologies:
                    print(f"    • {tech}")
            
            if tech_results.get('server'):
                print(f"  Server: {tech_results['server']}")
            if tech_results.get('cms'):
                print(f"  CMS: {tech_results['cms']}")
            if tech_results.get('framework'):
                print(f"  Framework: {tech_results['framework']}")
            if tech_results.get('language'):
                print(f"  Language: {tech_results['language']}")
        
        # WAF detection results
        waf_results = results.get('waf_detection', {})
        if waf_results and not waf_results.get('error'):
            print(f"\n{Fore.CYAN}WAF Detection Results:{Style.RESET_ALL}")
            if waf_results.get('waf_detected'):
                print(f"  WAF Detected: {waf_results.get('waf_name', 'Unknown')}")
                if waf_results.get('confidence'):
                    print(f"  Confidence: {waf_results['confidence']}%")
            else:
                print(f"  No WAF detected")
        
        # Errors
        errors = results.get('errors', [])
        if errors:
            print(f"\n{Fore.RED}Errors:{Style.RESET_ALL}")
            for error in errors:
                print(f"  • {error}")
    
    def interactive_config(self):
        """Interactive configuration menu"""
        print(f"\n{Fore.CYAN}Advanced Tools Configuration:{Style.RESET_ALL}")
        
        # Enable/disable tools
        for tool_name, tool_config in self.config['tools'].items():
            current_status = "enabled" if tool_config['enabled'] else "disabled"
            enable = input(f"Enable {tool_name}? (y/n) [current: {current_status}]: ").strip().lower()
            if enable == 'y':
                tool_config['enabled'] = True
            elif enable == 'n':
                tool_config['enabled'] = False
        
        # Threads
        threads = input(f"Number of threads [default: {self.config['threads']}]: ").strip()
        if threads.isdigit():
            self.config['threads'] = int(threads)
        
        # Timeout
        timeout = input(f"Timeout in seconds [default: {self.config['timeout']}]: ").strip()
        if timeout.isdigit():
            self.config['timeout'] = int(timeout)
        
        print(f"\n{Fore.GREEN}[+] Configuration updated{Style.RESET_ALL}")

def run(target: str):
    """Main function to run advanced tools integration"""
    scanner = AdvancedToolsIntegration()
    scanner.show_banner()
    
    # Interactive configuration
    scanner.interactive_config()
    
    # Run comprehensive scan
    results = scanner.run_comprehensive_scan(target)
    
    if 'error' in results:
        print(f"{Fore.RED}[-] Scan failed: {results['error']}{Style.RESET_ALL}")
        return
    
    # Display results
    scanner.show_results(results)

if __name__ == "__main__":
    if len(sys.argv) > 1:
        run(sys.argv[1])
    else:
        print(f"{Fore.RED}[-] Usage: python advanced_tools.py <target_url>{Style.RESET_ALL}")
