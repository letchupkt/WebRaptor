#!/usr/bin/env python3
"""
WebRaptor SQLMap Integration Module
Advanced SQL injection testing with automated SQLMap integration
"""

import os
import sys
import json
import subprocess
import time
import threading
from pathlib import Path
from typing import Dict, List, Optional, Any
from colorama import Fore, Style, init
from datetime import datetime
import requests
import re

init()

# Module metadata
description = "Advanced SQL injection testing with automated SQLMap integration"
author = "LakshmikanthanK (@letchu_pkt)"
version = "2.1"

class SQLMapScanner:
    """Advanced SQLMap integration for WebRaptor"""
    
    def __init__(self):
        self.results = []
        self.config = {
            'timeout': 300,
            'threads': 10,
            'risk_level': 1,
            'level': 1,
            'techniques': 'BEUSTQ',
            'batch': True,
            'no_interaction': True,
            'output_dir': 'output/scans/sqlmap',
            'wordlists': {
                'common': 'wordlists/sqlmap_common.txt',
                'extensive': 'wordlists/sqlmap_extensive.txt'
            }
        }
        
        # Create output directory
        Path(self.config['output_dir']).mkdir(parents=True, exist_ok=True)
        
        # SQLMap techniques mapping
        self.techniques = {
            'B': 'Boolean-based blind',
            'E': 'Error-based',
            'U': 'Union query-based',
            'S': 'Stacked queries',
            'T': 'Time-based blind',
            'Q': 'Inline queries'
        }
        
        # Risk levels
        self.risk_levels = {
            1: 'Low risk',
            2: 'Medium risk', 
            3: 'High risk'
        }
        
        # Test levels
        self.test_levels = {
            1: 'Basic tests',
            2: 'Intermediate tests',
            3: 'Advanced tests',
            4: 'Expert tests',
            5: 'All tests'
        }
    
    def show_banner(self):
        """Display SQLMap scanner banner"""
        banner = f"""
{Fore.BLUE}
╔══════════════════════════════════════════════════════════════════════════╗
║                    {Fore.YELLOW}WebRaptor SQLMap Integration v{version}{Fore.BLUE}                    ║
║                    Advanced SQL Injection Testing Framework              ║
║                        Author: LakshmikanthanK (@letchu_pkt)             ║
║                                                                          ║
╚══════════════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""
        print(banner)
    
    def check_sqlmap_installed(self) -> bool:
        """Check if SQLMap is installed"""
        try:
            result = subprocess.run(['sqlmap', '--version'], 
                                 capture_output=True, text=True, timeout=10)
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False
    
    def install_sqlmap(self) -> bool:
        """Install SQLMap"""
        print(f"{Fore.BLUE}[*] Installing SQLMap...{Style.RESET_ALL}")
        
        try:
            # Try pip install first
            result = subprocess.run(['pip', 'install', 'sqlmap'], 
                                 capture_output=True, text=True, timeout=300)
            if result.returncode == 0:
                print(f"{Fore.GREEN}[+] SQLMap installed successfully via pip{Style.RESET_ALL}")
                return True
            
            # Try git clone as fallback
            print(f"{Fore.YELLOW}[!] Pip install failed, trying git clone...{Style.RESET_ALL}")
            result = subprocess.run([
                'git', 'clone', 'https://github.com/sqlmapproject/sqlmap.git', 
                'tools/sqlmap'
            ], capture_output=True, text=True, timeout=300)
            
            if result.returncode == 0:
                print(f"{Fore.GREEN}[+] SQLMap cloned successfully{Style.RESET_ALL}")
                return True
            else:
                print(f"{Fore.RED}[-] Failed to install SQLMap: {result.stderr}{Style.RESET_ALL}")
                return False
                
        except subprocess.TimeoutExpired:
            print(f"{Fore.RED}[-] Installation timeout{Style.RESET_ALL}")
            return False
        except Exception as e:
            print(f"{Fore.RED}[-] Installation error: {e}{Style.RESET_ALL}")
            return False
    
    def get_sqlmap_command(self, target: str, options: Dict = None) -> List[str]:
        """Build SQLMap command with options"""
        if options is None:
            options = {}
        
        # Base command
        cmd = ['sqlmap']
        
        # Target URL
        cmd.extend(['-u', target])
        
        # Basic options
        cmd.extend(['--batch', '--no-interaction'])
        
        # Risk and level
        risk = options.get('risk', self.config['risk_level'])
        level = options.get('level', self.config['level'])
        cmd.extend(['--risk', str(risk), '--level', str(level)])
        
        # Techniques
        techniques = options.get('techniques', self.config['techniques'])
        cmd.extend(['--technique', techniques])
        
        # Threads
        threads = options.get('threads', self.config['threads'])
        cmd.extend(['--threads', str(threads)])
        
        # Timeout
        timeout = options.get('timeout', self.config['timeout'])
        cmd.extend(['--timeout', str(timeout)])
        
        # Output directory
        output_dir = options.get('output_dir', self.config['output_dir'])
        cmd.extend(['--output-dir', output_dir])
        
        # Additional options
        if options.get('forms', False):
            cmd.append('--forms')
        
        if options.get('crawl', False):
            crawl_depth = options.get('crawl_depth', 2)
            cmd.extend(['--crawl', str(crawl_depth)])
        
        if options.get('os_shell', False):
            cmd.append('--os-shell')
        
        if options.get('sql_shell', False):
            cmd.append('--sql-shell')
        
        if options.get('dump_all', False):
            cmd.append('--dump-all')
        
        if options.get('dump_tables', False):
            cmd.append('--dump-tables')
        
        if options.get('dump_columns', False):
            cmd.append('--dump-columns')
        
        # Custom headers
        if options.get('headers'):
            headers = options.get('headers')
            for header in headers:
                cmd.extend(['--header', header])
        
        # Cookies
        if options.get('cookies'):
            cmd.extend(['--cookie', options.get('cookies')])
        
        # User agent
        if options.get('user_agent'):
            cmd.extend(['--user-agent', options.get('user_agent')])
        
        # Proxy
        if options.get('proxy'):
            cmd.extend(['--proxy', options.get('proxy')])
        
        # Tor
        if options.get('tor', False):
            cmd.extend(['--tor', '--tor-port', '9050'])
        
        # Random agent
        if options.get('random_agent', False):
            cmd.append('--random-agent')
        
        # Delay
        if options.get('delay'):
            cmd.extend(['--delay', str(options.get('delay'))])
        
        return cmd
    
    def run_sqlmap_scan(self, target: str, options: Dict = None) -> Dict:
        """Run SQLMap scan on target"""
        if not self.check_sqlmap_installed():
            print(f"{Fore.RED}[-] SQLMap not installed. Installing...{Style.RESET_ALL}")
            if not self.install_sqlmap():
                return {'error': 'Failed to install SQLMap'}
        
        print(f"{Fore.BLUE}[*] Starting SQLMap scan on {target}{Style.RESET_ALL}")
        
        # Build command
        cmd = self.get_sqlmap_command(target, options)
        
        # Add output file
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = Path(self.config['output_dir']) / f"sqlmap_{timestamp}.txt"
        cmd.extend(['--output-file', str(output_file)])
        
        print(f"{Fore.CYAN}[*] Command: {' '.join(cmd)}{Style.RESET_ALL}")
        
        try:
            # Run SQLMap
            start_time = time.time()
            result = subprocess.run(cmd, capture_output=True, text=True, 
                                 timeout=options.get('timeout', self.config['timeout']))
            
            end_time = time.time()
            duration = end_time - start_time
            
            # Parse results
            scan_result = {
                'target': target,
                'timestamp': datetime.now().isoformat(),
                'duration': duration,
                'return_code': result.returncode,
                'stdout': result.stdout,
                'stderr': result.stderr,
                'output_file': str(output_file),
                'vulnerabilities': [],
                'databases': [],
                'tables': [],
                'columns': [],
                'data': []
            }
            
            # Parse SQLMap output for vulnerabilities
            vulnerabilities = self._parse_sqlmap_output(result.stdout)
            scan_result['vulnerabilities'] = vulnerabilities
            
            # Parse for databases, tables, columns, and data
            scan_result.update(self._parse_sqlmap_data(result.stdout))
            
            # Save detailed results
            self._save_results(scan_result)
            
            return scan_result
            
        except subprocess.TimeoutExpired:
            print(f"{Fore.RED}[-] SQLMap scan timeout{Style.RESET_ALL}")
            return {'error': 'Scan timeout'}
        except Exception as e:
            print(f"{Fore.RED}[-] SQLMap scan error: {e}{Style.RESET_ALL}")
            return {'error': str(e)}
    
    def _parse_sqlmap_output(self, output: str) -> List[Dict]:
        """Parse SQLMap output for vulnerabilities"""
        vulnerabilities = []
        
        # Look for SQL injection patterns
        patterns = {
            'boolean_blind': r'Boolean-based blind SQL injection',
            'error_based': r'Error-based SQL injection',
            'union_based': r'Union query-based SQL injection',
            'time_based': r'Time-based blind SQL injection',
            'stacked_queries': r'Stacked queries SQL injection'
        }
        
        for vuln_type, pattern in patterns.items():
            if re.search(pattern, output, re.IGNORECASE):
                vulnerabilities.append({
                    'type': vuln_type,
                    'severity': 'critical',
                    'description': f'{vuln_type.replace("_", " ").title()} vulnerability detected',
                    'confidence': 'high'
                })
        
        # Look for database information
        db_patterns = {
            'mysql': r'MySQL',
            'postgresql': r'PostgreSQL',
            'oracle': r'Oracle',
            'mssql': r'Microsoft SQL Server',
            'sqlite': r'SQLite'
        }
        
        for db_type, pattern in db_patterns.items():
            if re.search(pattern, output, re.IGNORECASE):
                vulnerabilities.append({
                    'type': 'database_disclosure',
                    'severity': 'high',
                    'description': f'{db_type} database detected',
                    'confidence': 'high'
                })
        
        return vulnerabilities
    
    def _parse_sqlmap_data(self, output: str) -> Dict:
        """Parse SQLMap output for database data"""
        data = {
            'databases': [],
            'tables': [],
            'columns': [],
            'data': []
        }
        
        # Parse databases
        db_pattern = r'available databases \[(\d+)\]:\s*(.+)'
        db_match = re.search(db_pattern, output, re.IGNORECASE | re.DOTALL)
        if db_match:
            databases = db_match.group(2).strip().split('\n')
            data['databases'] = [db.strip() for db in databases if db.strip()]
        
        # Parse tables
        table_pattern = r'Database: (.+)\n.*?available tables \[(\d+)\]:\s*(.+)'
        table_matches = re.findall(table_pattern, output, re.IGNORECASE | re.DOTALL)
        for db_name, count, tables in table_matches:
            table_list = tables.strip().split('\n')
            data['tables'].extend([{'database': db_name, 'table': t.strip()} 
                                 for t in table_list if t.strip()])
        
        # Parse columns
        column_pattern = r'Table: (.+)\n.*?available columns \[(\d+)\]:\s*(.+)'
        column_matches = re.findall(column_pattern, output, re.IGNORECASE | re.DOTALL)
        for table_name, count, columns in column_matches:
            column_list = columns.strip().split('\n')
            data['columns'].extend([{'table': table_name, 'column': c.strip()} 
                                  for c in column_list if c.strip()])
        
        return data
    
    def _save_results(self, results: Dict):
        """Save scan results to file"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        results_file = Path(self.config['output_dir']) / f"results_{timestamp}.json"
        
        try:
            with open(results_file, 'w') as f:
                json.dump(results, f, indent=2)
            print(f"{Fore.GREEN}[+] Results saved to {results_file}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[-] Error saving results: {e}{Style.RESET_ALL}")
    
    def interactive_config(self):
        """Interactive configuration menu"""
        print(f"\n{Fore.CYAN}SQLMap Configuration:{Style.RESET_ALL}")
        
        # Risk level
        print(f"\n{Fore.YELLOW}Risk Level:{Style.RESET_ALL}")
        for level, desc in self.risk_levels.items():
            print(f"  {level}. {desc}")
        
        risk = input(f"Select risk level (1-3) [default: {self.config['risk_level']}]: ").strip()
        if risk.isdigit() and 1 <= int(risk) <= 3:
            self.config['risk_level'] = int(risk)
        
        # Test level
        print(f"\n{Fore.YELLOW}Test Level:{Style.RESET_ALL}")
        for level, desc in self.test_levels.items():
            print(f"  {level}. {desc}")
        
        level = input(f"Select test level (1-5) [default: {self.config['level']}]: ").strip()
        if level.isdigit() and 1 <= int(level) <= 5:
            self.config['level'] = int(level)
        
        # Techniques
        print(f"\n{Fore.YELLOW}SQL Injection Techniques:{Style.RESET_ALL}")
        for technique, desc in self.techniques.items():
            print(f"  {technique}. {desc}")
        
        techniques = input(f"Select techniques (e.g., BEUSTQ) [default: {self.config['techniques']}]: ").strip()
        if techniques:
            self.config['techniques'] = techniques
        
        # Threads
        threads = input(f"Number of threads [default: {self.config['threads']}]: ").strip()
        if threads.isdigit():
            self.config['threads'] = int(threads)
        
        # Timeout
        timeout = input(f"Timeout in seconds [default: {self.config['timeout']}]: ").strip()
        if timeout.isdigit():
            self.config['timeout'] = int(timeout)
        
        # Additional options
        print(f"\n{Fore.YELLOW}Additional Options:{Style.RESET_ALL}")
        
        forms = input("Test forms? (y/n) [default: n]: ").strip().lower()
        if forms == 'y':
            self.config['forms'] = True
        
        crawl = input("Crawl website? (y/n) [default: n]: ").strip().lower()
        if crawl == 'y':
            self.config['crawl'] = True
            crawl_depth = input("Crawl depth [default: 2]: ").strip()
            if crawl_depth.isdigit():
                self.config['crawl_depth'] = int(crawl_depth)
        
        os_shell = input("Attempt OS shell? (y/n) [default: n]: ").strip().lower()
        if os_shell == 'y':
            self.config['os_shell'] = True
        
        sql_shell = input("Attempt SQL shell? (y/n) [default: n]: ").strip().lower()
        if sql_shell == 'y':
            self.config['sql_shell'] = True
        
        dump_all = input("Dump all data? (y/n) [default: n]: ").strip().lower()
        if dump_all == 'y':
            self.config['dump_all'] = True
        
        print(f"\n{Fore.GREEN}[+] Configuration updated{Style.RESET_ALL}")
    
    def show_results(self, results: Dict):
        """Display scan results"""
        print(f"\n{Fore.BLUE}╔══════════════════════════════════════════════════════════════════════════╗")
        print(f"║                           SQLMap Scan Results                              ║")
        print(f"╚══════════════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}")
        
        print(f"\n{Fore.CYAN}Target:{Style.RESET_ALL} {results.get('target', 'N/A')}")
        print(f"{Fore.CYAN}Duration:{Style.RESET_ALL} {results.get('duration', 0):.2f} seconds")
        print(f"{Fore.CYAN}Timestamp:{Style.RESET_ALL} {results.get('timestamp', 'N/A')}")
        
        # Vulnerabilities
        vulnerabilities = results.get('vulnerabilities', [])
        if vulnerabilities:
            print(f"\n{Fore.RED}Vulnerabilities Found:{Style.RESET_ALL}")
            for vuln in vulnerabilities:
                severity_color = Fore.RED if vuln['severity'] == 'critical' else Fore.YELLOW
                print(f"  {severity_color}• {vuln['type']}: {vuln['description']}{Style.RESET_ALL}")
        else:
            print(f"\n{Fore.GREEN}No SQL injection vulnerabilities detected{Style.RESET_ALL}")
        
        # Database information
        databases = results.get('databases', [])
        if databases:
            print(f"\n{Fore.CYAN}Databases Found:{Style.RESET_ALL}")
            for db in databases:
                print(f"  • {db}")
        
        # Tables
        tables = results.get('tables', [])
        if tables:
            print(f"\n{Fore.CYAN}Tables Found:{Style.RESET_ALL}")
            for table in tables:
                print(f"  • {table.get('database', 'N/A')}.{table.get('table', 'N/A')}")
        
        # Columns
        columns = results.get('columns', [])
        if columns:
            print(f"\n{Fore.CYAN}Columns Found:{Style.RESET_ALL}")
            for column in columns:
                print(f"  • {column.get('table', 'N/A')}.{column.get('column', 'N/A')}")
    
    def generate_report(self, results: Dict) -> str:
        """Generate HTML report"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = Path(self.config['output_dir']) / f"sqlmap_report_{timestamp}.html"
        
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>SQLMap Scan Report - {results.get('target', 'N/A')}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .header {{ background: #2c3e50; color: white; padding: 20px; border-radius: 5px; }}
        .vulnerability {{ background: #e74c3c; color: white; padding: 10px; margin: 5px 0; border-radius: 3px; }}
        .info {{ background: #3498db; color: white; padding: 10px; margin: 5px 0; border-radius: 3px; }}
        .success {{ background: #27ae60; color: white; padding: 10px; margin: 5px 0; border-radius: 3px; }}
        table {{ border-collapse: collapse; width: 100%; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #f2f2f2; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>SQLMap Scan Report</h1>
        <p>Target: {results.get('target', 'N/A')}</p>
        <p>Scan Date: {results.get('timestamp', 'N/A')}</p>
        <p>Duration: {results.get('duration', 0):.2f} seconds</p>
    </div>
    
    <h2>Vulnerabilities</h2>
"""
        
        vulnerabilities = results.get('vulnerabilities', [])
        if vulnerabilities:
            for vuln in vulnerabilities:
                severity_class = 'vulnerability' if vuln['severity'] == 'critical' else 'info'
                html_content += f"""
    <div class="{severity_class}">
        <strong>{vuln['type']}</strong>: {vuln['description']}
    </div>
"""
        else:
            html_content += '<div class="success">No SQL injection vulnerabilities detected</div>'
        
        # Add database information
        databases = results.get('databases', [])
        if databases:
            html_content += """
    <h2>Databases Found</h2>
    <ul>
"""
            for db in databases:
                html_content += f"<li>{db}</li>"
            html_content += "</ul>"
        
        html_content += """
</body>
</html>
"""
        
        try:
            with open(report_file, 'w') as f:
                f.write(html_content)
            print(f"{Fore.GREEN}[+] HTML report generated: {report_file}{Style.RESET_ALL}")
            return str(report_file)
        except Exception as e:
            print(f"{Fore.RED}[-] Error generating report: {e}{Style.RESET_ALL}")
            return ""

def run(target: str):
    """Main function to run SQLMap scanner"""
    scanner = SQLMapScanner()
    scanner.show_banner()
    
    # Interactive configuration
    scanner.interactive_config()
    
    # Run scan
    results = scanner.run_sqlmap_scan(target, scanner.config)
    
    if 'error' in results:
        print(f"{Fore.RED}[-] Scan failed: {results['error']}{Style.RESET_ALL}")
        return
    
    # Display results
    scanner.show_results(results)
    
    # Generate report
    report_file = scanner.generate_report(results)
    if report_file:
        print(f"\n{Fore.GREEN}[+] Report saved: {report_file}{Style.RESET_ALL}")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        run(sys.argv[1])
    else:
        print(f"{Fore.RED}[-] Usage: python sqlmap_scanner.py <target_url>{Style.RESET_ALL}")
