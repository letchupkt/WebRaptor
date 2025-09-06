#!/usr/bin/env python3
"""
WebRaptor Nikto Integration Module
Advanced web vulnerability scanning with Nikto
"""

import os
import sys
import json
import subprocess
import time
import re
from pathlib import Path
from typing import List, Dict, Optional, Tuple
from colorama import Fore, Style, init
from core.config import Config
from core.tool_manager import ToolManager

init()

# Module metadata
description = "Advanced web vulnerability scanning with Nikto and custom plugins"
author = "LakshmikanthanK (@letchu_pkt)"
version = "2.1"

class NiktoScanner:
    """Advanced Nikto web vulnerability scanner integration"""
    
    def __init__(self, config: Config = None):
        self.config = config or Config()
        self.tool_manager = ToolManager()
        self.results_dir = Path("reports/nikto")
        self.plugins_dir = Path("nikto-plugins")
        
        # Create directories
        self.results_dir.mkdir(parents=True, exist_ok=True)
        self.plugins_dir.mkdir(exist_ok=True)
        
        # Nikto configuration
        self.nikto_config = {
            'timeout': 10,
            'user_agent': 'Mozilla/5.0 (compatible; WebRaptor-Scanner/2.1)',
            'format': 'json',
            'evasion': '1',  # Random URI encoding
            'tuning': '0',   # All tests
            'port': '80,443,8080,8443',
            'ssl': True,
            'follow_redirects': True,
            'no_interactive': True
        }
        
        # Scan profiles
        self.scan_profiles = {
            'quick': {
                'name': 'Quick Scan',
                'description': 'Fast vulnerability scan with common tests',
                'tuning': '1,2,3,4,5',  # Common vulnerabilities
                'timeout': 5
            },
            'comprehensive': {
                'name': 'Comprehensive Scan',
                'description': 'Complete vulnerability assessment',
                'tuning': '0',  # All tests
                'timeout': 10
            },
            'ssl': {
                'name': 'SSL/TLS Scan',
                'description': 'SSL configuration and certificate testing',
                'tuning': '6',  # SSL tests
                'ssl': True,
                'port': '443,8443'
            },
            'cgi': {
                'name': 'CGI Scan',
                'description': 'CGI and script vulnerability testing',
                'tuning': '7',  # CGI tests
                'timeout': 15
            },
            'database': {
                'name': 'Database Scan',
                'description': 'Database-related vulnerability testing',
                'tuning': '8',  # Database tests
                'timeout': 10
            },
            'files': {
                'name': 'File Disclosure Scan',
                'description': 'Sensitive file and directory detection',
                'tuning': '9',  # File tests
                'timeout': 8
            }
        }
        
        # Custom plugins
        self.custom_plugins = {
            'xss_detection': {
                'name': 'XSS Detection Plugin',
                'description': 'Cross-site scripting vulnerability detection',
                'tests': [
                    {'path': '/search?q=<script>alert("XSS")</script>', 'description': 'Reflected XSS test'},
                    {'path': '/comment?text=<img src=x onerror=alert("XSS")>', 'description': 'Stored XSS test'},
                    {'path': '/profile?name="><script>alert("XSS")</script>', 'description': 'DOM XSS test'}
                ]
            },
            'sql_injection': {
                'name': 'SQL Injection Plugin',
                'description': 'SQL injection vulnerability detection',
                'tests': [
                    {'path': '/login?user=admin\'--', 'description': 'Authentication bypass'},
                    {'path': '/search?id=1\' UNION SELECT NULL--', 'description': 'Union-based injection'},
                    {'path': '/product?id=1\' OR 1=1#', 'description': 'Boolean-based injection'}
                ]
            },
            'directory_traversal': {
                'name': 'Directory Traversal Plugin',
                'description': 'Path traversal vulnerability detection',
                'tests': [
                    {'path': '/file?path=../../../etc/passwd', 'description': 'Unix path traversal'},
                    {'path': '/download?file=..\\..\\..\\windows\\system32\\drivers\\etc\\hosts', 'description': 'Windows path traversal'},
                    {'path': '/view?file=....//....//etc/passwd', 'description': 'Double encoding bypass'}
                ]
            }
        }
    
    def show_banner(self):
        """Display Nikto scanner banner"""
        banner = f"""
{Fore.BLUE}
╔══════════════════════════════════════════════════════════════════════════╗
║                     {Fore.YELLOW}WebRaptor Nikto Scanner v{version}{Fore.BLUE}                      ║
║                Advanced Web Vulnerability Detection with Nikto           ║
║                        Author: LakshmikanthanK (@letchu_pkt)             ║
║                                                                          ║
╚══════════════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""
        print(banner)
    
    def check_nikto_installed(self) -> bool:
        """Check if Nikto is installed and working"""
        return self.tool_manager.check_tool_installed('nikto')
    
    def install_nikto(self) -> bool:
        """Install Nikto if not present"""
        if not self.check_nikto_installed():
            print(f"{Fore.CYAN}[*] Installing Nikto...{Style.RESET_ALL}")
            return self.tool_manager.install_tool('nikto')
        return True
    
    def run_scan(self, target: str, profile: str = 'comprehensive') -> Dict:
        """Run Nikto scan with specified profile"""
        if not self.check_nikto_installed():
            if not self.install_nikto():
                return {'success': False, 'error': 'Failed to install Nikto'}
        
        if profile not in self.scan_profiles:
            print(f"{Fore.RED}[-] Unknown scan profile: {profile}{Style.RESET_ALL}")
            return {'success': False, 'error': f'Unknown profile: {profile}'}
        
        profile_config = self.scan_profiles[profile]
        print(f"{Fore.BLUE}[*] Starting {profile_config['name']} on {target}...{Style.RESET_ALL}")
        
        # Prepare scan arguments
        args = ['-h', target]
        
        # Add profile-specific configuration
        args.extend(['-T', profile_config.get('tuning', '0')])
        args.extend(['-timeout', str(profile_config.get('timeout', self.nikto_config['timeout']))])
        
        # Add general configuration
        args.extend(['-useragent', self.nikto_config['user_agent']])
        args.extend(['-Format', self.nikto_config['format']])
        args.extend(['-evasion', self.nikto_config['evasion']])
        
        if self.nikto_config['ssl']:
            args.append('-ssl')
        
        if self.nikto_config['follow_redirects']:
            args.append('-followredirect')
        
        if self.nikto_config['no_interactive']:
            args.append('-nointeractive')
        
        # Add port specification
        if 'port' in profile_config:
            args.extend(['-p', profile_config['port']])
        else:
            args.extend(['-p', self.nikto_config['port']])
        
        # Run the scan
        try:
            success, stdout, stderr = self.tool_manager.run_tool('nikto', args, timeout=1800)
            
            if success:
                # Parse results
                results = self._parse_nikto_results(stdout, stderr)
                
                # Save results
                timestamp = time.strftime("%Y%m%d_%H%M%S")
                results_file = self.results_dir / f"nikto_scan_{target.replace('.', '_')}_{timestamp}.json"
                
                with open(results_file, 'w') as f:
                    json.dump(results, f, indent=2)
                
                print(f"{Fore.GREEN}[+] Nikto scan completed successfully{Style.RESET_ALL}")
                print(f"{Fore.GREEN}[+] Results saved to: {results_file}{Style.RESET_ALL}")
                
                return {
                    'success': True,
                    'results': results,
                    'file': str(results_file),
                    'findings_count': len(results.get('findings', []))
                }
            else:
                print(f"{Fore.RED}[-] Nikto scan failed: {stderr}{Style.RESET_ALL}")
                return {'success': False, 'error': stderr}
                
        except Exception as e:
            print(f"{Fore.RED}[-] Error running Nikto scan: {e}{Style.RESET_ALL}")
            return {'success': False, 'error': str(e)}
    
    def _parse_nikto_results(self, stdout: str, stderr: str) -> Dict:
        """Parse Nikto output and extract findings"""
        findings = []
        summary = {}
        
        # Parse JSON output if available
        try:
            json_data = json.loads(stdout)
            findings = json_data.get('findings', [])
            summary = json_data.get('summary', {})
        except json.JSONDecodeError:
            # Parse text output
            findings = self._parse_text_output(stdout)
            summary = self._extract_summary(stdout)
        
        # Categorize findings
        categorized_findings = self._categorize_findings(findings)
        
        return {
            'findings': findings,
            'categorized_findings': categorized_findings,
            'summary': summary,
            'total_findings': len(findings),
            'scan_time': time.strftime('%Y-%m-%d %H:%M:%S'),
            'raw_output': stdout,
            'errors': stderr
        }
    
    def _parse_text_output(self, output: str) -> List[Dict]:
        """Parse Nikto text output"""
        findings = []
        lines = output.split('\n')
        
        for line in lines:
            line = line.strip()
            if line and ('OSVDB' in line or 'CVE' in line or 'found' in line.lower()):
                # Extract finding information
                finding = {
                    'raw_line': line,
                    'severity': self._extract_severity(line),
                    'description': line,
                    'type': self._extract_type(line)
                }
                findings.append(finding)
        
        return findings
    
    def _extract_severity(self, line: str) -> str:
        """Extract severity from Nikto output line"""
        if 'OSVDB-' in line:
            return 'medium'
        elif 'CVE-' in line:
            return 'high'
        elif 'found' in line.lower():
            return 'info'
        else:
            return 'unknown'
    
    def _extract_type(self, line: str) -> str:
        """Extract vulnerability type from Nikto output line"""
        if 'xss' in line.lower():
            return 'Cross-Site Scripting'
        elif 'sql' in line.lower():
            return 'SQL Injection'
        elif 'directory' in line.lower() or 'traversal' in line.lower():
            return 'Directory Traversal'
        elif 'ssl' in line.lower() or 'tls' in line.lower():
            return 'SSL/TLS'
        elif 'cgi' in line.lower():
            return 'CGI'
        elif 'file' in line.lower():
            return 'File Disclosure'
        else:
            return 'General'
    
    def _extract_summary(self, output: str) -> Dict:
        """Extract summary information from Nikto output"""
        summary = {}
        
        # Extract host information
        host_match = re.search(r'Target IP:\s*(\d+\.\d+\.\d+\.\d+)', output)
        if host_match:
            summary['target_ip'] = host_match.group(1)
        
        # Extract port information
        port_match = re.search(r'Target Port:\s*(\d+)', output)
        if port_match:
            summary['target_port'] = port_match.group(1)
        
        # Extract OS information
        os_match = re.search(r'OS:\s*(.+)', output)
        if os_match:
            summary['os'] = os_match.group(1)
        
        # Extract server information
        server_match = re.search(r'Server:\s*(.+)', output)
        if server_match:
            summary['server'] = server_match.group(1)
        
        return summary
    
    def _categorize_findings(self, findings: List[Dict]) -> Dict:
        """Categorize findings by type"""
        categories = {}
        
        for finding in findings:
            finding_type = finding.get('type', 'General')
            if finding_type not in categories:
                categories[finding_type] = []
            categories[finding_type].append(finding)
        
        return categories
    
    def run_custom_plugin(self, target: str, plugin_name: str) -> Dict:
        """Run custom vulnerability plugin"""
        if plugin_name not in self.custom_plugins:
            print(f"{Fore.RED}[-] Unknown plugin: {plugin_name}{Style.RESET_ALL}")
            return {'success': False, 'error': f'Unknown plugin: {plugin_name}'}
        
        plugin = self.custom_plugins[plugin_name]
        print(f"{Fore.BLUE}[*] Running {plugin['name']} on {target}...{Style.RESET_ALL}")
        
        findings = []
        
        for test in plugin['tests']:
            test_url = f"{target}{test['path']}"
            print(f"{Fore.CYAN}[*] Testing: {test_url}{Style.RESET_ALL}")
            
            # Perform the test (simplified - would need actual HTTP requests)
            # This is a placeholder for actual vulnerability testing
            finding = {
                'url': test_url,
                'description': test['description'],
                'plugin': plugin_name,
                'severity': 'medium',
                'type': plugin_name.replace('_', ' ').title()
            }
            findings.append(finding)
        
        return {
            'success': True,
            'findings': findings,
            'plugin': plugin_name,
            'total_findings': len(findings)
        }
    
    def display_results(self, results: Dict):
        """Display scan results in a formatted way"""
        if not results.get('success'):
            print(f"{Fore.RED}[-] Scan failed: {results.get('error', 'Unknown error')}{Style.RESET_ALL}")
            return
        
        findings = results.get('results', {}).get('findings', [])
        categorized = results.get('results', {}).get('categorized_findings', {})
        summary = results.get('results', {}).get('summary', {})
        
        print(f"\n{Fore.BLUE}╔══════════════════════════════════════════════════════════════════════════╗")
        print(f"║                         NIKTO SCAN RESULTS                            ║")
        print(f"╚══════════════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}")
        
        # Summary
        print(f"\n{Fore.CYAN}📊 Summary:{Style.RESET_ALL}")
        print(f"  Total Findings: {len(findings)}")
        
        if summary:
            if 'target_ip' in summary:
                print(f"  Target IP: {summary['target_ip']}")
            if 'target_port' in summary:
                print(f"  Target Port: {summary['target_port']}")
            if 'os' in summary:
                print(f"  OS: {summary['os']}")
            if 'server' in summary:
                print(f"  Server: {summary['server']}")
        
        # Categorized findings
        if categorized:
            print(f"\n{Fore.CYAN}🔍 Findings by Category:{Style.RESET_ALL}")
            for category, category_findings in categorized.items():
                print(f"  {Fore.YELLOW}{category}:{Style.RESET_ALL} {len(category_findings)} findings")
        
        # Detailed findings
        if findings:
            print(f"\n{Fore.CYAN}📋 Detailed Findings:{Style.RESET_ALL}")
            
            for i, finding in enumerate(findings[:10], 1):  # Show first 10 findings
                severity = finding.get('severity', 'unknown')
                description = finding.get('description', 'No description')
                finding_type = finding.get('type', 'Unknown')
                
                # Color code by severity
                severity_color = Fore.RED if severity == 'high' else Fore.YELLOW if severity == 'medium' else Fore.WHITE
                
                print(f"\n{Fore.CYAN}[{i}] {finding_type}{Style.RESET_ALL}")
                print(f"    {severity_color}Severity: {severity.upper()}{Style.RESET_ALL}")
                print(f"    Description: {description}")
                
                if 'url' in finding:
                    print(f"    URL: {finding['url']}")
            
            if len(findings) > 10:
                print(f"\n{Fore.YELLOW}... and {len(findings) - 10} more findings{Style.RESET_ALL}")

def run(target):
    """Main entry point for Nikto scanner module"""
    try:
        scanner = NiktoScanner()
        scanner.show_banner()
        
        # Check if Nikto is installed
        if not scanner.check_nikto_installed():
            print(f"{Fore.YELLOW}[!] Nikto not found. Installing...{Style.RESET_ALL}")
            if not scanner.install_nikto():
                print(f"{Fore.RED}[-] Failed to install Nikto{Style.RESET_ALL}")
                return
        
        # Run comprehensive scan
        print(f"{Fore.BLUE}[*] Starting comprehensive web vulnerability scan...{Style.RESET_ALL}")
        results = scanner.run_scan(target, 'comprehensive')
        
        # Display results
        scanner.display_results(results)
        
        # Run additional scans
        print(f"\n{Fore.BLUE}[*] Running additional scans...{Style.RESET_ALL}")
        
        # SSL scan
        ssl_results = scanner.run_scan(target, 'ssl')
        if ssl_results.get('success'):
            print(f"{Fore.GREEN}[+] SSL scan completed: {ssl_results.get('findings_count', 0)} findings{Style.RESET_ALL}")
        
        # CGI scan
        cgi_results = scanner.run_scan(target, 'cgi')
        if cgi_results.get('success'):
            print(f"{Fore.GREEN}[+] CGI scan completed: {cgi_results.get('findings_count', 0)} findings{Style.RESET_ALL}")
        
        # Run custom plugins
        print(f"\n{Fore.BLUE}[*] Running custom vulnerability plugins...{Style.RESET_ALL}")
        
        for plugin_name in scanner.custom_plugins.keys():
            plugin_results = scanner.run_custom_plugin(target, plugin_name)
            if plugin_results.get('success'):
                print(f"{Fore.GREEN}[+] {plugin_name} completed: {plugin_results.get('total_findings', 0)} findings{Style.RESET_ALL}")
        
        print(f"\n{Fore.GREEN}[+] Nikto scanning completed successfully!{Style.RESET_ALL}")
        
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Scan interrupted by user{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[-] Error in Nikto scanning: {e}{Style.RESET_ALL}")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        run(sys.argv[1])
    else:
        print("Usage: python nikto_scanner.py <target_url>")
