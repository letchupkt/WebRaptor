#!/usr/bin/env python3
"""
WebRaptor Tool Manager
Advanced tool installation and management system for bug bounty automation
"""

import os
import sys
import subprocess
import platform
import shutil
import json
import requests
import zipfile
import tarfile
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from colorama import Fore, Style, init
import threading
import time

init()

class ToolManager:
    """Advanced tool management system for WebRaptor"""
    
    def __init__(self):
        self.tools_dir = Path("output/tools")
        self.bin_dir = Path("output/tools/bin")
        self.config_file = Path("output/config/tools_config.json")
        self.tools_config = self._load_config()
        
        # Create directories
        self.tools_dir.mkdir(parents=True, exist_ok=True)
        self.bin_dir.mkdir(parents=True, exist_ok=True)
        
        # Tool definitions with installation methods
        self.tool_definitions = {
            'nmap': {
                'name': 'Nmap',
                'description': 'Network mapper and port scanner',
                'install_method': 'package_manager',
                'package_names': {
                    'linux': 'nmap',
                    'darwin': 'nmap',
                    'windows': 'nmap'
                },
                'download_urls': {
                    'windows': 'https://nmap.org/dist/nmap-7.94-setup.exe'
                },
                'bin_name': 'nmap',
                'version_command': ['nmap', '--version'],
                'required': True
            },
            'nuclei': {
                'name': 'Nuclei',
                'description': 'Vulnerability scanner based on templates',
                'install_method': 'github_release',
                'github_repo': 'projectdiscovery/nuclei',
                'bin_name': 'nuclei',
                'version_command': ['nuclei', '-version'],
                'required': True
            },
            'nikto': {
                'name': 'Nikto',
                'description': 'Web vulnerability scanner',
                'install_method': 'package_manager',
                'package_names': {
                    'linux': 'nikto',
                    'darwin': 'nikto'
                },
                'download_urls': {
                    'windows': 'https://cirt.net/nikto/nikto-2.1.6.tar.bz2'
                },
                'bin_name': 'nikto',
                'version_command': ['nikto', '-Version'],
                'required': True
            },
            'subfinder': {
                'name': 'Subfinder',
                'description': 'Subdomain discovery tool',
                'install_method': 'github_release',
                'github_repo': 'projectdiscovery/subfinder',
                'bin_name': 'subfinder',
                'version_command': ['subfinder', '-version'],
                'required': True
            },
            'amass': {
                'name': 'Amass',
                'description': 'In-depth attack surface mapping',
                'install_method': 'github_release',
                'github_repo': 'owasp-amass/amass',
                'bin_name': 'amass',
                'version_command': ['amass', 'version'],
                'required': True
            },
            'httpx': {
                'name': 'HTTPx',
                'description': 'Fast HTTP toolkit',
                'install_method': 'github_release',
                'github_repo': 'projectdiscovery/httpx',
                'bin_name': 'httpx',
                'version_command': ['httpx', '-version'],
                'required': True
            },
            'gobuster': {
                'name': 'Gobuster',
                'description': 'Directory/file brute-forcer',
                'install_method': 'github_release',
                'github_repo': 'OJ/gobuster',
                'bin_name': 'gobuster',
                'version_command': ['gobuster', 'version'],
                'required': True
            },
            'ffuf': {
                'name': 'Ffuf',
                'description': 'Fast web fuzzer',
                'install_method': 'github_release',
                'github_repo': 'ffuf/ffuf',
                'bin_name': 'ffuf',
                'version_command': ['ffuf', '-V'],
                'required': True
            },
            'subjack': {
                'name': 'Subjack',
                'description': 'Subdomain takeover tool',
                'install_method': 'go_install',
                'go_package': 'github.com/haccer/subjack',
                'bin_name': 'subjack',
                'version_command': ['subjack', '-h'],
                'required': True
            },
            'subzy': {
                'name': 'Subzy',
                'description': 'Subdomain takeover vulnerability checker',
                'install_method': 'go_install',
                'go_package': 'github.com/lukasikic/subzy',
                'bin_name': 'subzy',
                'version_command': ['subzy', 'version'],
                'required': True
            },
            'sublist3r': {
                'name': 'Sublist3r',
                'description': 'Subdomain enumeration tool',
                'install_method': 'pip',
                'pip_package': 'sublist3r',
                'bin_name': 'sublist3r',
                'version_command': ['sublist3r', '--help'],
                'required': True
            },
            'linkfinder': {
                'name': 'LinkFinder',
                'description': 'JavaScript endpoint discovery',
                'install_method': 'github_clone',
                'github_repo': 'GerbenJavado/LinkFinder',
                'bin_name': 'linkfinder.py',
                'version_command': ['python3', 'linkfinder.py', '--help'],
                'required': False
            },
            'metasploit': {
                'name': 'Metasploit',
                'description': 'Penetration testing framework',
                'install_method': 'package_manager',
                'package_names': {
                    'linux': 'metasploit-framework',
                    'darwin': 'metasploit-framework'
                },
                'bin_name': 'msfconsole',
                'version_command': ['msfconsole', '-v'],
                'required': False
            },
            'searchsploit': {
                'name': 'SearchSploit',
                'description': 'Exploit database search tool',
                'install_method': 'package_manager',
                'package_names': {
                    'linux': 'exploitdb',
                    'darwin': 'exploitdb'
                },
                'bin_name': 'searchsploit',
                'version_command': ['searchsploit', '--help'],
                'required': False
            },
            'sqlmap': {
                'name': 'SQLMap',
                'description': 'SQL injection testing tool',
                'install_method': 'pip',
                'pip_package': 'sqlmap',
                'bin_name': 'sqlmap',
                'version_command': ['sqlmap', '--version'],
                'required': True
            },
            'dirb': {
                'name': 'Dirb',
                'description': 'Web content scanner',
                'install_method': 'package_manager',
                'package_names': {
                    'linux': 'dirb',
                    'darwin': 'dirb'
                },
                'bin_name': 'dirb',
                'version_command': ['dirb', '--help'],
                'required': False
            },
            'wfuzz': {
                'name': 'WFuzz',
                'description': 'Web application fuzzer',
                'install_method': 'pip',
                'pip_package': 'wfuzz',
                'bin_name': 'wfuzz',
                'version_command': ['wfuzz', '--help'],
                'required': False
            },
            'whatweb': {
                'name': 'WhatWeb',
                'description': 'Web technology identifier',
                'install_method': 'package_manager',
                'package_names': {
                    'linux': 'whatweb',
                    'darwin': 'whatweb'
                },
                'bin_name': 'whatweb',
                'version_command': ['whatweb', '--version'],
                'required': False
            },
            'wafw00f': {
                'name': 'WAFW00F',
                'description': 'Web Application Firewall fingerprinting',
                'install_method': 'pip',
                'pip_package': 'wafw00f',
                'bin_name': 'wafw00f',
                'version_command': ['wafw00f', '--help'],
                'required': False
            },
            'dnsrecon': {
                'name': 'DNSRecon',
                'description': 'DNS enumeration tool',
                'install_method': 'pip',
                'pip_package': 'dnsrecon',
                'bin_name': 'dnsrecon',
                'version_command': ['dnsrecon', '--help'],
                'required': False
            },
            'theharvester': {
                'name': 'theHarvester',
                'description': 'Email, subdomain, and people names harvester',
                'install_method': 'pip',
                'pip_package': 'theharvester',
                'bin_name': 'theHarvester',
                'version_command': ['theHarvester', '--help'],
                'required': False
            },
            'waybackurls': {
                'name': 'WaybackURLs',
                'description': 'Fetch all URLs that the Wayback Machine has for a domain',
                'install_method': 'go_install',
                'go_package': 'github.com/tomnomnom/waybackurls',
                'bin_name': 'waybackurls',
                'version_command': ['waybackurls', '-h'],
                'required': True
            },
            'gau': {
                'name': 'GAU (Get All URLs)',
                'description': 'Fetch known URLs from AlienVault Open Threat Exchange, Wayback Machine, and Common Crawl',
                'install_method': 'go_install',
                'go_package': 'github.com/lc/gau',
                'bin_name': 'gau',
                'version_command': ['gau', '-version'],
                'required': True
            },
            'assetfinder': {
                'name': 'Assetfinder',
                'description': 'Find domains and subdomains',
                'install_method': 'go_install',
                'go_package': 'github.com/tomnomnom/assetfinder',
                'bin_name': 'assetfinder',
                'version_command': ['assetfinder', '-h'],
                'required': False
            },
            'findomain': {
                'name': 'Findomain',
                'description': 'Cross-platform subdomain discovery tool',
                'install_method': 'github_release',
                'github_repo': 'Findomain/Findomain',
                'bin_name': 'findomain',
                'version_command': ['findomain', '--version'],
                'required': False
            },
            'chaos': {
                'name': 'Chaos',
                'description': 'Chaos client for Chaos DNS',
                'install_method': 'go_install',
                'go_package': 'github.com/projectdiscovery/chaos-client',
                'bin_name': 'chaos',
                'version_command': ['chaos', '-version'],
                'required': False
            },
            'shuffledns': {
                'name': 'ShuffleDNS',
                'description': 'Massive DNS resolver',
                'install_method': 'go_install',
                'go_package': 'github.com/projectdiscovery/shuffledns',
                'bin_name': 'shuffledns',
                'version_command': ['shuffledns', '-version'],
                'required': False
            },
            'dnsx': {
                'name': 'DNSx',
                'description': 'Fast and multi-purpose DNS toolkit',
                'install_method': 'go_install',
                'go_package': 'github.com/projectdiscovery/dnsx',
                'bin_name': 'dnsx',
                'version_command': ['dnsx', '-version'],
                'required': False
            },
            'katana': {
                'name': 'Katana',
                'description': 'Web crawling framework',
                'install_method': 'go_install',
                'go_package': 'github.com/projectdiscovery/katana',
                'bin_name': 'katana',
                'version_command': ['katana', '-version'],
                'required': False
            },
            'unfurl': {
                'name': 'Unfurl',
                'description': 'Parse and extract URLs',
                'install_method': 'go_install',
                'go_package': 'github.com/tomnomnom/unfurl',
                'bin_name': 'unfurl',
                'version_command': ['unfurl', '-h'],
                'required': False
            },
            'qsreplace': {
                'name': 'Qsreplace',
                'description': 'Replace query string values',
                'install_method': 'go_install',
                'go_package': 'github.com/tomnomnom/qsreplace',
                'bin_name': 'qsreplace',
                'version_command': ['qsreplace', '-h'],
                'required': False
            },
            'secretfinder': {
                'name': 'SecretFinder',
                'description': 'Find sensitive data in JavaScript files',
                'install_method': 'git_clone',
                'git_repo': 'https://github.com/m4ll0k/SecretFinder.git',
                'bin_name': 'SecretFinder.py',
                'version_command': ['python3', 'SecretFinder.py', '--help'],
                'required': False,
                'python_script': True
            },
            'jsfinder': {
                'name': 'JSFinder',
                'description': 'Find URLs and subdomains in JavaScript files',
                'install_method': 'git_clone',
                'git_repo': 'https://github.com/Threezh1/JSFinder.git',
                'bin_name': 'JSFinder.py',
                'version_command': ['python3', 'JSFinder.py', '--help'],
                'required': False,
                'python_script': True
            },
            'paramspider': {
                'name': 'ParamSpider',
                'description': 'Mining parameters from web archives',
                'install_method': 'git_clone',
                'git_repo': 'https://github.com/devanshbatham/ParamSpider.git',
                'bin_name': 'paramspider.py',
                'version_command': ['python3', 'paramspider.py', '--help'],
                'required': False,
                'python_script': True
            },
            'arjun': {
                'name': 'Arjun',
                'description': 'HTTP parameter discovery suite',
                'install_method': 'pip',
                'pip_package': 'arjun',
                'bin_name': 'arjun',
                'version_command': ['arjun', '--version'],
                'required': False
            },
            'masscan': {
                'name': 'Masscan',
                'description': 'Fast port scanner',
                'install_method': 'package_manager',
                'package_names': {
                    'linux': 'masscan',
                    'darwin': 'masscan'
                },
                'download_urls': {
                    'windows': 'https://github.com/robertdavidgraham/masscan/releases/latest'
                },
                'bin_name': 'masscan',
                'version_command': ['masscan', '--version'],
                'required': False
            },
            'zap': {
                'name': 'OWASP ZAP',
                'description': 'Web application security scanner',
                'install_method': 'download',
                'download_urls': {
                    'linux': 'https://github.com/zaproxy/zaproxy/releases/latest/download/ZAP_2_14_0_unix.sh',
                    'darwin': 'https://github.com/zaproxy/zaproxy/releases/latest/download/ZAP_2_14_0_unix.sh',
                    'windows': 'https://github.com/zaproxy/zaproxy/releases/latest/download/ZAP_2_14_0_windows.exe'
                },
                'bin_name': 'zap.sh',
                'version_command': ['zap.sh', '-version'],
                'required': False
            },
            'burpsuite': {
                'name': 'Burp Suite Community',
                'description': 'Web vulnerability scanner',
                'install_method': 'download',
                'download_urls': {
                    'linux': 'https://portswigger.net/burp/releases/download?product=community&version=2023.12.1&type=jar',
                    'darwin': 'https://portswigger.net/burp/releases/download?product=community&version=2023.12.1&type=jar',
                    'windows': 'https://portswigger.net/burp/releases/download?product=community&version=2023.12.1&type=jar'
                },
                'bin_name': 'burpsuite_community.jar',
                'version_command': ['java', '-jar', 'burpsuite_community.jar', '-h'],
                'required': False,
                'java_jar': True
            },
            'knockpy': {
                'name': 'Knockpy',
                'description': 'Subdomain scanner',
                'install_method': 'pip',
                'pip_package': 'knockpy',
                'bin_name': 'knockpy',
                'version_command': ['knockpy', '--version'],
                'required': False
            },
            'dirbuster': {
                'name': 'DirBuster',
                'description': 'Multi-threaded directory brute-forcer',
                'install_method': 'download',
                'download_urls': {
                    'linux': 'https://sourceforge.net/projects/dirbuster/files/DirBuster%20%28jar%20%2B%20lists%29/1.0-RC1/DirBuster-1.0-RC1.tar.gz',
                    'darwin': 'https://sourceforge.net/projects/dirbuster/files/DirBuster%20%28jar%20%2B%20lists%29/1.0-RC1/DirBuster-1.0-RC1.tar.gz',
                    'windows': 'https://sourceforge.net/projects/dirbuster/files/DirBuster%20%28jar%20%2B%20lists%29/1.0-RC1/DirBuster-1.0-RC1.tar.gz'
                },
                'bin_name': 'DirBuster-1.0-RC1.jar',
                'version_command': ['java', '-jar', 'DirBuster-1.0-RC1.jar', '-h'],
                'required': False,
                'java_jar': True
            }
        }
    
    def _load_config(self) -> Dict:
        """Load tools configuration from file"""
        if self.config_file.exists():
            try:
                with open(self.config_file, 'r') as f:
                    return json.load(f)
            except Exception as e:
                print(f"{Fore.YELLOW}[!] Error loading config: {e}{Style.RESET_ALL}")
        return {}
    
    def _save_config(self) -> None:
        """Save tools configuration to file"""
        try:
            with open(self.config_file, 'w') as f:
                json.dump(self.tools_config, f, indent=2)
        except Exception as e:
            print(f"{Fore.RED}[-] Error saving config: {e}{Style.RESET_ALL}")
    
    def check_system_requirements(self) -> Dict[str, bool]:
        """Check system requirements for tool installation"""
        requirements = {
            'python3': shutil.which('python3') is not None,
            'pip': shutil.which('pip') is not None,
            'git': shutil.which('git') is not None,
            'curl': shutil.which('curl') is not None,
            'wget': shutil.which('wget') is not None,
            'unzip': shutil.which('unzip') is not None,
            'tar': shutil.which('tar') is not None
        }
        
        # Check package managers
        if platform.system() == 'Linux':
            requirements['apt'] = shutil.which('apt') is not None
            requirements['yum'] = shutil.which('yum') is not None
            requirements['dnf'] = shutil.which('dnf') is not None
            requirements['pacman'] = shutil.which('pacman') is not None
        elif platform.system() == 'Darwin':
            requirements['brew'] = shutil.which('brew') is not None
        elif platform.system() == 'Windows':
            requirements['chocolatey'] = shutil.which('choco') is not None
            requirements['scoop'] = shutil.which('scoop') is not None
        
        # Check Go for Go-based tools
        requirements['go'] = shutil.which('go') is not None
        
        return requirements
    
    def install_package_manager_tool(self, tool_name: str, tool_config: Dict) -> bool:
        """Install tool using package manager"""
        system = platform.system().lower()
        package_name = tool_config.get('package_names', {}).get(system)
        
        if not package_name:
            print(f"{Fore.YELLOW}[!] No package name for {tool_name} on {system}{Style.RESET_ALL}")
            return False
        
        # Determine package manager
        if system == 'linux':
            if shutil.which('apt'):
                cmd = ['sudo', 'apt', 'update'] + ['sudo', 'apt', 'install', '-y', package_name]
            elif shutil.which('yum'):
                cmd = ['sudo', 'yum', 'install', '-y', package_name]
            elif shutil.which('dnf'):
                cmd = ['sudo', 'dnf', 'install', '-y', package_name]
            elif shutil.which('pacman'):
                cmd = ['sudo', 'pacman', '-S', '--noconfirm', package_name]
            else:
                print(f"{Fore.RED}[-] No supported package manager found{Style.RESET_ALL}")
                return False
        elif system == 'darwin':
            if shutil.which('brew'):
                cmd = ['brew', 'install', package_name]
            else:
                print(f"{Fore.RED}[-] Homebrew not found{Style.RESET_ALL}")
                return False
        elif system == 'windows':
            if shutil.which('choco'):
                cmd = ['choco', 'install', package_name, '-y']
            elif shutil.which('scoop'):
                cmd = ['scoop', 'install', package_name]
            else:
                print(f"{Fore.RED}[-] No supported package manager found{Style.RESET_ALL}")
                return False
        else:
            print(f"{Fore.RED}[-] Unsupported system: {system}{Style.RESET_ALL}")
            return False
        
        try:
            print(f"{Fore.CYAN}[*] Installing {tool_name} using package manager...{Style.RESET_ALL}")
            for c in cmd:
                result = subprocess.run(c, capture_output=True, text=True)
                if result.returncode != 0:
                    print(f"{Fore.RED}[-] Error running {c}: {result.stderr}{Style.RESET_ALL}")
                    return False
            return True
        except Exception as e:
            print(f"{Fore.RED}[-] Error installing {tool_name}: {e}{Style.RESET_ALL}")
            return False
    
    def install_github_release_tool(self, tool_name: str, tool_config: Dict) -> bool:
        """Install tool from GitHub releases"""
        github_repo = tool_config.get('github_repo')
        if not github_repo:
            print(f"{Fore.RED}[-] No GitHub repo specified for {tool_name}{Style.RESET_ALL}")
            return False
        
        try:
            # Get latest release info
            api_url = f"https://api.github.com/repos/{github_repo}/releases/latest"
            response = requests.get(api_url, timeout=30)
            if response.status_code != 200:
                print(f"{Fore.RED}[-] Failed to get release info for {github_repo}{Style.RESET_ALL}")
                return False
            
            release_data = response.json()
            system = platform.system().lower()
            arch = platform.machine().lower()
            
            # Find appropriate asset
            asset_url = None
            asset_name = None
            
            for asset in release_data.get('assets', []):
                asset_name = asset['name'].lower()
                if system == 'windows' and 'windows' in asset_name and '.exe' in asset_name:
                    asset_url = asset['browser_download_url']
                    break
                elif system == 'linux' and 'linux' in asset_name and arch in asset_name:
                    asset_url = asset['browser_download_url']
                    break
                elif system == 'darwin' and 'darwin' in asset_name:
                    asset_url = asset['browser_download_url']
                    break
            
            if not asset_url:
                print(f"{Fore.RED}[-] No suitable release found for {system} {arch}{Style.RESET_ALL}")
                return False
            
            # Download and install
            print(f"{Fore.CYAN}[*] Downloading {tool_name} from GitHub...{Style.RESET_ALL}")
            tool_path = self.tools_dir / tool_name
            tool_path.mkdir(exist_ok=True)
            
            download_path = tool_path / asset_name
            self._download_file(asset_url, download_path)
            
            # Extract if needed
            if asset_name.endswith('.zip'):
                with zipfile.ZipFile(download_path, 'r') as zip_ref:
                    zip_ref.extractall(tool_path)
            elif asset_name.endswith(('.tar.gz', '.tar.bz2')):
                with tarfile.open(download_path, 'r:*') as tar_ref:
                    tar_ref.extractall(tool_path)
            
            # Find binary and make executable
            bin_name = tool_config.get('bin_name', tool_name)
            binary_path = self._find_binary(tool_path, bin_name)
            
            if binary_path:
                # Copy to bin directory
                final_path = self.bin_dir / bin_name
                shutil.copy2(binary_path, final_path)
                
                # Make executable on Unix systems
                if platform.system() != 'Windows':
                    os.chmod(final_path, 0o755)
                
                # Update PATH
                self._add_to_path(str(self.bin_dir))
                
                return True
            else:
                print(f"{Fore.RED}[-] Binary {bin_name} not found in downloaded files{Style.RESET_ALL}")
                return False
                
        except Exception as e:
            print(f"{Fore.RED}[-] Error installing {tool_name}: {e}{Style.RESET_ALL}")
            return False
    
    def install_pip_tool(self, tool_name: str, tool_config: Dict) -> bool:
        """Install tool using pip"""
        pip_package = tool_config.get('pip_package', tool_name)
        
        try:
            print(f"{Fore.CYAN}[*] Installing {tool_name} using pip...{Style.RESET_ALL}")
            result = subprocess.run([sys.executable, '-m', 'pip', 'install', pip_package], 
                                  capture_output=True, text=True)
            if result.returncode == 0:
                return True
            else:
                print(f"{Fore.RED}[-] Pip install failed: {result.stderr}{Style.RESET_ALL}")
                return False
        except Exception as e:
            print(f"{Fore.RED}[-] Error installing {tool_name}: {e}{Style.RESET_ALL}")
            return False
    
    def install_go_tool(self, tool_name: str, tool_config: Dict) -> bool:
        """Install Go-based tool"""
        go_package = tool_config.get('go_package')
        if not go_package:
            print(f"{Fore.RED}[-] No Go package specified for {tool_name}{Style.RESET_ALL}")
            return False
        
        if not shutil.which('go'):
            print(f"{Fore.RED}[-] Go not found. Please install Go first.{Style.RESET_ALL}")
            return False
        
        try:
            print(f"{Fore.CYAN}[*] Installing {tool_name} using go install...{Style.RESET_ALL}")
            result = subprocess.run(['go', 'install', f"{go_package}@latest"], 
                                  capture_output=True, text=True)
            if result.returncode == 0:
                # Go installs to GOPATH/bin, add to PATH
                go_path = subprocess.run(['go', 'env', 'GOPATH'], 
                                       capture_output=True, text=True)
                if go_path.returncode == 0:
                    bin_path = Path(go_path.stdout.strip()) / 'bin'
                    self._add_to_path(str(bin_path))
                return True
            else:
                print(f"{Fore.RED}[-] Go install failed: {result.stderr}{Style.RESET_ALL}")
                return False
        except Exception as e:
            print(f"{Fore.RED}[-] Error installing {tool_name}: {e}{Style.RESET_ALL}")
            return False
    
    def install_github_clone_tool(self, tool_name: str, tool_config: Dict) -> bool:
        """Install tool by cloning from GitHub"""
        github_repo = tool_config.get('github_repo')
        if not github_repo:
            print(f"{Fore.RED}[-] No GitHub repo specified for {tool_name}{Style.RESET_ALL}")
            return False
        
        if not shutil.which('git'):
            print(f"{Fore.RED}[-] Git not found. Please install Git first.{Style.RESET_ALL}")
            return False
        
        try:
            print(f"{Fore.CYAN}[*] Cloning {tool_name} from GitHub...{Style.RESET_ALL}")
            tool_path = self.tools_dir / tool_name
            if tool_path.exists():
                shutil.rmtree(tool_path)
            
            result = subprocess.run(['git', 'clone', f"https://github.com/{github_repo}.git", str(tool_path)], 
                                  capture_output=True, text=True)
            if result.returncode == 0:
                # Install Python dependencies if requirements.txt exists
                req_file = tool_path / 'requirements.txt'
                if req_file.exists():
                    print(f"{Fore.CYAN}[*] Installing Python dependencies...{Style.RESET_ALL}")
                    subprocess.run([sys.executable, '-m', 'pip', 'install', '-r', str(req_file)], 
                                 capture_output=True)
                
                return True
            else:
                print(f"{Fore.RED}[-] Git clone failed: {result.stderr}{Style.RESET_ALL}")
                return False
        except Exception as e:
            print(f"{Fore.RED}[-] Error installing {tool_name}: {e}{Style.RESET_ALL}")
            return False
    
    def _download_file(self, url: str, filepath: Path) -> None:
        """Download file from URL"""
        response = requests.get(url, stream=True, timeout=30)
        response.raise_for_status()
        
        with open(filepath, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
    
    def _find_binary(self, directory: Path, bin_name: str) -> Optional[Path]:
        """Find binary in directory"""
        for root, dirs, files in os.walk(directory):
            for file in files:
                if file == bin_name or file == f"{bin_name}.exe":
                    return Path(root) / file
        return None
    
    def _add_to_path(self, path: str) -> None:
        """Add path to system PATH"""
        if path not in os.environ.get('PATH', ''):
            os.environ['PATH'] = f"{path}:{os.environ.get('PATH', '')}"
    
    def check_tool_installed(self, tool_name: str) -> bool:
        """Check if tool is installed and working"""
        tool_config = self.tool_definitions.get(tool_name)
        if not tool_config:
            return False
        
        bin_name = tool_config.get('bin_name', tool_name)
        version_cmd = tool_config.get('version_command', [bin_name, '--version'])
        
        try:
            result = subprocess.run(version_cmd, capture_output=True, text=True, timeout=10)
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False
    
    def install_tool(self, tool_name: str) -> bool:
        """Install a specific tool"""
        if tool_name not in self.tool_definitions:
            print(f"{Fore.RED}[-] Unknown tool: {tool_name}{Style.RESET_ALL}")
            return False
        
        tool_config = self.tool_definitions[tool_name]
        install_method = tool_config.get('install_method')
        
        print(f"{Fore.BLUE}[*] Installing {tool_config['name']}...{Style.RESET_ALL}")
        
        success = False
        if install_method == 'package_manager':
            success = self.install_package_manager_tool(tool_name, tool_config)
        elif install_method == 'github_release':
            success = self.install_github_release_tool(tool_name, tool_config)
        elif install_method == 'pip':
            success = self.install_pip_tool(tool_name, tool_config)
        elif install_method == 'go_install':
            success = self.install_go_tool(tool_name, tool_config)
        elif install_method == 'github_clone':
            success = self.install_github_clone_tool(tool_name, tool_config)
        
        if success:
            self.tools_config[tool_name] = {
                'installed': True,
                'install_date': time.strftime('%Y-%m-%d %H:%M:%S'),
                'version': 'unknown'
            }
            self._save_config()
            print(f"{Fore.GREEN}[+] {tool_config['name']} installed successfully{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}[-] Failed to install {tool_config['name']}{Style.RESET_ALL}")
        
        return success
    
    def install_all_tools(self) -> Dict[str, bool]:
        """Install all required tools"""
        print(f"{Fore.BLUE}[*] Installing all required tools...{Style.RESET_ALL}")
        
        # Check system requirements first
        requirements = self.check_system_requirements()
        missing_reqs = [req for req, available in requirements.items() if not available]
        if missing_reqs:
            print(f"{Fore.YELLOW}[!] Missing requirements: {', '.join(missing_reqs)}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[!] Please install missing requirements first{Style.RESET_ALL}")
        
        results = {}
        required_tools = [name for name, config in self.tool_definitions.items() 
                         if config.get('required', False)]
        
        for tool_name in required_tools:
            if not self.check_tool_installed(tool_name):
                results[tool_name] = self.install_tool(tool_name)
            else:
                print(f"{Fore.GREEN}[+] {tool_name} already installed{Style.RESET_ALL}")
                results[tool_name] = True
        
        return results
    
    def show_tool_status(self) -> None:
        """Show status of all tools"""
        print(f"\n{Fore.BLUE}╔══════════════════════════════════════════════════════════════════════════╗")
        print(f"║                           TOOL STATUS                              ║")
        print(f"╚══════════════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}")
        
        required_tools = []
        optional_tools = []
        
        for name, config in self.tool_definitions.items():
            if config.get('required', False):
                required_tools.append((name, config))
            else:
                optional_tools.append((name, config))
        
        print(f"\n{Fore.CYAN}🔧 Required Tools:{Style.RESET_ALL}")
        for name, config in required_tools:
            status = f"{Fore.GREEN}✓{Style.RESET_ALL}" if self.check_tool_installed(name) else f"{Fore.RED}✗{Style.RESET_ALL}"
            print(f"  {status} {config['name']:<20} - {config['description']}")
        
        print(f"\n{Fore.CYAN}🔧 Optional Tools:{Style.RESET_ALL}")
        for name, config in optional_tools:
            status = f"{Fore.GREEN}✓{Style.RESET_ALL}" if self.check_tool_installed(name) else f"{Fore.YELLOW}○{Style.RESET_ALL}"
            print(f"  {status} {config['name']:<20} - {config['description']}")
    
    def get_tool_path(self, tool_name: str) -> Optional[str]:
        """Get the path to a tool binary"""
        tool_config = self.tool_definitions.get(tool_name)
        if not tool_config:
            return None
        
        bin_name = tool_config.get('bin_name', tool_name)
        
        # Check in bin directory first
        bin_path = self.bin_dir / bin_name
        if bin_path.exists():
            return str(bin_path)
        
        # Check in system PATH
        system_path = shutil.which(bin_name)
        if system_path:
            return system_path
        
        return None
    
    def run_tool(self, tool_name: str, args: List[str], timeout: int = 300) -> Tuple[bool, str, str]:
        """Run a tool with given arguments"""
        tool_path = self.get_tool_path(tool_name)
        if not tool_path:
            return False, "", f"Tool {tool_name} not found"
        
        try:
            cmd = [tool_path] + args
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            return result.returncode == 0, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return False, "", f"Tool {tool_name} timed out after {timeout} seconds"
        except Exception as e:
            return False, "", f"Error running {tool_name}: {str(e)}"

def main():
    """Main function for standalone tool manager"""
    manager = ToolManager()
    
    print(f"{Fore.CYAN}WebRaptor Tool Manager{Style.RESET_ALL}")
    print("=" * 50)
    
    while True:
        print(f"\n{Fore.YELLOW}Available commands:{Style.RESET_ALL}")
        print("1. Check tool status")
        print("2. Install specific tool")
        print("3. Install all required tools")
        print("4. Check system requirements")
        print("5. Exit")
        
        choice = input(f"\n{Fore.GREEN}Select option: {Style.RESET_ALL}").strip()
        
        if choice == '1':
            manager.show_tool_status()
        elif choice == '2':
            tool_name = input("Enter tool name: ").strip()
            manager.install_tool(tool_name)
        elif choice == '3':
            manager.install_all_tools()
        elif choice == '4':
            requirements = manager.check_system_requirements()
            print(f"\n{Fore.CYAN}System Requirements:{Style.RESET_ALL}")
            for req, available in requirements.items():
                status = f"{Fore.GREEN}✓{Style.RESET_ALL}" if available else f"{Fore.RED}✗{Style.RESET_ALL}"
                print(f"  {status} {req}")
        elif choice == '5':
            break
        else:
            print(f"{Fore.RED}[-] Invalid option{Style.RESET_ALL}")

if __name__ == "__main__":
    main()
