#!/usr/bin/env python3
"""
WebRaptor WaybackURLs Integration Module
Historical URL discovery and analysis using Wayback Machine data
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

init()

# Module metadata
description = "Historical URL discovery and analysis using Wayback Machine data"
author = "LakshmikanthanK (@letchu_pkt)"
version = "2.1"

class WaybackURLsScanner:
    """Advanced WaybackURLs integration for WebRaptor"""
    
    def __init__(self):
        self.results = []
        self.config = {
            'timeout': 300,
            'threads': 20,
            'output_dir': 'output/scans/waybackurls',
            'filters': {
                'status_codes': [200, 301, 302, 403, 404],
                'file_extensions': ['.php', '.asp', '.aspx', '.jsp', '.html', '.htm'],
                'exclude_extensions': ['.css', '.js', '.png', '.jpg', '.gif', '.ico'],
                'min_length': 10,
                'max_length': 200
            },
            'analysis': {
                'check_live': True,
                'check_parameters': True,
                'check_endpoints': True,
                'check_technologies': True
            }
        }
        
        # Create output directory
        Path(self.config['output_dir']).mkdir(parents=True, exist_ok=True)
        
        # Common parameter patterns
        self.parameter_patterns = [
            r'[?&]([a-zA-Z0-9_\-]+)=',
            r'([a-zA-Z0-9_\-]+)\s*=\s*[^&\s]+',
            r'param\s*=\s*([a-zA-Z0-9_\-]+)',
            r'([a-zA-Z0-9_\-]+)\s*:\s*[^,\s]+'
        ]
        
        # Technology patterns
        self.tech_patterns = {
            'php': [r'\.php', r'phpinfo', r'PHP/'],
            'asp': [r'\.asp', r'\.aspx', r'ASP\.NET'],
            'jsp': [r'\.jsp', r'JSP/'],
            'python': [r'\.py', r'Django', r'Flask'],
            'node': [r'\.js', r'Node\.js', r'Express'],
            'wordpress': [r'wp-content', r'wp-admin', r'WordPress'],
            'drupal': [r'drupal', r'Drupal'],
            'joomla': [r'joomla', r'Joomla']
        }
    
    def show_banner(self):
        """Display WaybackURLs scanner banner"""
        banner = f"""
{Fore.BLUE}
╔══════════════════════════════════════════════════════════════════════════╗
║                  {Fore.YELLOW}WebRaptor WaybackURLs Integration v{version}{Fore.BLUE}                 ║
║                    Historical URL Discovery & Analysis                   ║
║                        Author: LakshmikanthanK (@letchu_pkt)             ║
║                                                                          ║
╚══════════════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""
        print(banner)
    
    def check_waybackurls_installed(self) -> bool:
        """Check if WaybackURLs is installed"""
        try:
            result = subprocess.run(['waybackurls', '-h'], 
                                 capture_output=True, text=True, timeout=10)
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False
    
    def install_waybackurls(self) -> bool:
        """Install WaybackURLs"""
        print(f"{Fore.BLUE}[*] Installing WaybackURLs...{Style.RESET_ALL}")
        
        try:
            # Try go install
            result = subprocess.run([
                'go', 'install', 'github.com/tomnomnom/waybackurls@latest'
            ], capture_output=True, text=True, timeout=300)
            
            if result.returncode == 0:
                print(f"{Fore.GREEN}[+] WaybackURLs installed successfully{Style.RESET_ALL}")
                return True
            else:
                print(f"{Fore.RED}[-] Failed to install WaybackURLs: {result.stderr}{Style.RESET_ALL}")
                return False
                
        except subprocess.TimeoutExpired:
            print(f"{Fore.RED}[-] Installation timeout{Style.RESET_ALL}")
            return False
        except Exception as e:
            print(f"{Fore.RED}[-] Installation error: {e}{Style.RESET_ALL}")
            return False
    
    def get_wayback_urls(self, domain: str) -> List[str]:
        """Get URLs from Wayback Machine"""
        if not self.check_waybackurls_installed():
            print(f"{Fore.RED}[-] WaybackURLs not installed. Installing...{Style.RESET_ALL}")
            if not self.install_waybackurls():
                return []
        
        print(f"{Fore.BLUE}[*] Fetching URLs from Wayback Machine for {domain}{Style.RESET_ALL}")
        
        try:
            # Run waybackurls
            cmd = ['waybackurls', domain]
            result = subprocess.run(cmd, capture_output=True, text=True, 
                                 timeout=self.config['timeout'])
            
            if result.returncode == 0:
                urls = result.stdout.strip().split('\n')
                urls = [url.strip() for url in urls if url.strip()]
                print(f"{Fore.GREEN}[+] Found {len(urls)} URLs from Wayback Machine{Style.RESET_ALL}")
                return urls
            else:
                print(f"{Fore.RED}[-] WaybackURLs error: {result.stderr}{Style.RESET_ALL}")
                return []
                
        except subprocess.TimeoutExpired:
            print(f"{Fore.RED}[-] WaybackURLs timeout{Style.RESET_ALL}")
            return []
        except Exception as e:
            print(f"{Fore.RED}[-] WaybackURLs error: {e}{Style.RESET_ALL}")
            return []
    
    def filter_urls(self, urls: List[str]) -> List[str]:
        """Filter URLs based on configuration"""
        filtered_urls = []
        
        for url in urls:
            try:
                parsed = urlparse(url)
                
                # Check URL length
                if len(url) < self.config['filters']['min_length'] or \
                   len(url) > self.config['filters']['max_length']:
                    continue
                
                # Check file extensions
                path = parsed.path.lower()
                exclude_ext = any(path.endswith(ext) for ext in self.config['filters']['exclude_extensions'])
                if exclude_ext:
                    continue
                
                # Check for interesting extensions
                include_ext = any(path.endswith(ext) for ext in self.config['filters']['file_extensions'])
                if include_ext or '?' in url or '=' in url:
                    filtered_urls.append(url)
                
            except Exception:
                continue
        
        print(f"{Fore.CYAN}[*] Filtered to {len(filtered_urls)} interesting URLs{Style.RESET_ALL}")
        return filtered_urls
    
    def analyze_urls(self, urls: List[str]) -> Dict[str, Any]:
        """Analyze discovered URLs"""
        analysis = {
            'total_urls': len(urls),
            'unique_domains': set(),
            'unique_paths': set(),
            'parameters': set(),
            'technologies': set(),
            'status_codes': {},
            'live_urls': [],
            'interesting_urls': [],
            'endpoints': set()
        }
        
        print(f"{Fore.BLUE}[*] Analyzing {len(urls)} URLs...{Style.RESET_ALL}")
        
        # Analyze URLs in parallel
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.config['threads']) as executor:
            futures = []
            
            for url in urls:
                future = executor.submit(self._analyze_single_url, url)
                futures.append(future)
            
            # Collect results
            for future in concurrent.futures.as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        self._merge_analysis_result(analysis, result)
                except Exception as e:
                    print(f"{Fore.YELLOW}[!] Analysis error: {e}{Style.RESET_ALL}")
        
        # Convert sets to lists for JSON serialization
        analysis['unique_domains'] = list(analysis['unique_domains'])
        analysis['unique_paths'] = list(analysis['unique_paths'])
        analysis['parameters'] = list(analysis['parameters'])
        analysis['technologies'] = list(analysis['technologies'])
        analysis['endpoints'] = list(analysis['endpoints'])
        
        return analysis
    
    def _analyze_single_url(self, url: str) -> Optional[Dict]:
        """Analyze a single URL"""
        try:
            parsed = urlparse(url)
            
            result = {
                'url': url,
                'domain': parsed.netloc,
                'path': parsed.path,
                'parameters': [],
                'technologies': [],
                'status_code': None,
                'is_live': False
            }
            
            # Extract parameters
            if parsed.query:
                params = self._extract_parameters(parsed.query)
                result['parameters'] = params
            
            # Check if URL is live
            if self.config['analysis']['check_live']:
                status_code = self._check_url_status(url)
                result['status_code'] = status_code
                result['is_live'] = status_code in self.config['filters']['status_codes']
            
            # Detect technologies
            if self.config['analysis']['check_technologies']:
                techs = self._detect_technologies(url)
                result['technologies'] = techs
            
            return result
            
        except Exception:
            return None
    
    def _extract_parameters(self, query_string: str) -> List[str]:
        """Extract parameters from query string"""
        parameters = []
        
        for pattern in self.parameter_patterns:
            matches = re.findall(pattern, query_string)
            parameters.extend(matches)
        
        return list(set(parameters))
    
    def _check_url_status(self, url: str) -> Optional[int]:
        """Check if URL is live and get status code"""
        try:
            response = requests.head(url, timeout=10, allow_redirects=True)
            return response.status_code
        except Exception:
            return None
    
    def _detect_technologies(self, url: str) -> List[str]:
        """Detect technologies from URL"""
        technologies = []
        
        for tech, patterns in self.tech_patterns.items():
            for pattern in patterns:
                if re.search(pattern, url, re.IGNORECASE):
                    technologies.append(tech)
                    break
        
        return technologies
    
    def _merge_analysis_result(self, analysis: Dict, result: Dict):
        """Merge single URL analysis result into overall analysis"""
        analysis['unique_domains'].add(result['domain'])
        analysis['unique_paths'].add(result['path'])
        analysis['parameters'].update(result['parameters'])
        analysis['technologies'].update(result['technologies'])
        
        if result['status_code']:
            status = result['status_code']
            analysis['status_codes'][status] = analysis['status_codes'].get(status, 0) + 1
            
            if result['is_live']:
                analysis['live_urls'].append(result['url'])
        
        # Check for interesting URLs
        if self._is_interesting_url(result['url']):
            analysis['interesting_urls'].append(result['url'])
        
        # Extract endpoints
        if self.config['analysis']['check_endpoints']:
            endpoints = self._extract_endpoints(result['url'])
            analysis['endpoints'].update(endpoints)
    
    def _is_interesting_url(self, url: str) -> bool:
        """Check if URL is interesting for further analysis"""
        interesting_patterns = [
            r'admin', r'login', r'config', r'backup', r'test',
            r'api', r'v1', r'v2', r'debug', r'dev',
            r'upload', r'download', r'file', r'dir',
            r'sql', r'db', r'database', r'query'
        ]
        
        url_lower = url.lower()
        return any(re.search(pattern, url_lower) for pattern in interesting_patterns)
    
    def _extract_endpoints(self, url: str) -> Set[str]:
        """Extract API endpoints from URL"""
        endpoints = set()
        
        # Extract path segments that look like endpoints
        parsed = urlparse(url)
        path_segments = parsed.path.strip('/').split('/')
        
        for segment in path_segments:
            if re.match(r'^[a-zA-Z0-9_\-]+$', segment) and len(segment) > 2:
                endpoints.add(segment)
        
        return endpoints
    
    def run_scan(self, target: str) -> Dict:
        """Run complete WaybackURLs scan"""
        print(f"{Fore.BLUE}[*] Starting WaybackURLs scan for {target}{Style.RESET_ALL}")
        
        start_time = time.time()
        
        # Get URLs from Wayback Machine
        urls = self.get_wayback_urls(target)
        if not urls:
            return {'error': 'No URLs found from Wayback Machine'}
        
        # Filter URLs
        filtered_urls = self.filter_urls(urls)
        
        # Analyze URLs
        analysis = self.analyze_urls(filtered_urls)
        
        end_time = time.time()
        duration = end_time - start_time
        
        # Compile results
        results = {
            'target': target,
            'timestamp': datetime.now().isoformat(),
            'duration': duration,
            'total_urls': len(urls),
            'filtered_urls': len(filtered_urls),
            'analysis': analysis,
            'all_urls': urls,
            'filtered_urls_list': filtered_urls
        }
        
        # Save results
        self._save_results(results)
        
        return results
    
    def _save_results(self, results: Dict):
        """Save scan results to file"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        results_file = Path(self.config['output_dir']) / f"waybackurls_{timestamp}.json"
        
        try:
            with open(results_file, 'w') as f:
                json.dump(results, f, indent=2)
            print(f"{Fore.GREEN}[+] Results saved to {results_file}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[-] Error saving results: {e}{Style.RESET_ALL}")
    
    def show_results(self, results: Dict):
        """Display scan results"""
        print(f"\n{Fore.BLUE}╔══════════════════════════════════════════════════════════════════════════╗")
        print(f"║                        WaybackURLs Scan Results                         ║")
        print(f"╚══════════════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}")
        
        print(f"\n{Fore.CYAN}Target:{Style.RESET_ALL} {results.get('target', 'N/A')}")
        print(f"{Fore.CYAN}Duration:{Style.RESET_ALL} {results.get('duration', 0):.2f} seconds")
        print(f"{Fore.CYAN}Total URLs:{Style.RESET_ALL} {results.get('total_urls', 0)}")
        print(f"{Fore.CYAN}Filtered URLs:{Style.RESET_ALL} {results.get('filtered_urls', 0)}")
        
        analysis = results.get('analysis', {})
        
        # Unique domains
        domains = analysis.get('unique_domains', [])
        if domains:
            print(f"\n{Fore.CYAN}Unique Domains Found:{Style.RESET_ALL}")
            for domain in domains[:10]:  # Show first 10
                print(f"  • {domain}")
            if len(domains) > 10:
                print(f"  ... and {len(domains) - 10} more")
        
        # Technologies
        technologies = analysis.get('technologies', [])
        if technologies:
            print(f"\n{Fore.CYAN}Technologies Detected:{Style.RESET_ALL}")
            for tech in technologies:
                print(f"  • {tech}")
        
        # Parameters
        parameters = analysis.get('parameters', [])
        if parameters:
            print(f"\n{Fore.CYAN}Parameters Found:{Style.RESET_ALL}")
            for param in parameters[:20]:  # Show first 20
                print(f"  • {param}")
            if len(parameters) > 20:
                print(f"  ... and {len(parameters) - 20} more")
        
        # Live URLs
        live_urls = analysis.get('live_urls', [])
        if live_urls:
            print(f"\n{Fore.GREEN}Live URLs Found ({len(live_urls)}):{Style.RESET_ALL}")
            for url in live_urls[:10]:  # Show first 10
                print(f"  • {url}")
            if len(live_urls) > 10:
                print(f"  ... and {len(live_urls) - 10} more")
        
        # Interesting URLs
        interesting_urls = analysis.get('interesting_urls', [])
        if interesting_urls:
            print(f"\n{Fore.YELLOW}Interesting URLs Found ({len(interesting_urls)}):{Style.RESET_ALL}")
            for url in interesting_urls[:10]:  # Show first 10
                print(f"  • {url}")
            if len(interesting_urls) > 10:
                print(f"  ... and {len(interesting_urls) - 10} more")
        
        # Status codes
        status_codes = analysis.get('status_codes', {})
        if status_codes:
            print(f"\n{Fore.CYAN}Status Code Distribution:{Style.RESET_ALL}")
            for status, count in sorted(status_codes.items()):
                print(f"  • {status}: {count}")
    
    def generate_report(self, results: Dict) -> str:
        """Generate HTML report"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = Path(self.config['output_dir']) / f"waybackurls_report_{timestamp}.html"
        
        analysis = results.get('analysis', {})
        
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>WaybackURLs Scan Report - {results.get('target', 'N/A')}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .header {{ background: #2c3e50; color: white; padding: 20px; border-radius: 5px; }}
        .stats {{ background: #3498db; color: white; padding: 15px; margin: 10px 0; border-radius: 3px; }}
        .url-list {{ background: #f8f9fa; padding: 15px; margin: 10px 0; border-radius: 3px; }}
        .tech {{ background: #e67e22; color: white; padding: 5px; margin: 2px; border-radius: 3px; display: inline-block; }}
        .param {{ background: #9b59b6; color: white; padding: 5px; margin: 2px; border-radius: 3px; display: inline-block; }}
        table {{ border-collapse: collapse; width: 100%; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #f2f2f2; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>WaybackURLs Scan Report</h1>
        <p>Target: {results.get('target', 'N/A')}</p>
        <p>Scan Date: {results.get('timestamp', 'N/A')}</p>
        <p>Duration: {results.get('duration', 0):.2f} seconds</p>
    </div>
    
    <div class="stats">
        <h2>Statistics</h2>
        <p>Total URLs: {results.get('total_urls', 0)}</p>
        <p>Filtered URLs: {results.get('filtered_urls', 0)}</p>
        <p>Live URLs: {len(analysis.get('live_urls', []))}</p>
        <p>Interesting URLs: {len(analysis.get('interesting_urls', []))}</p>
        <p>Unique Domains: {len(analysis.get('unique_domains', []))}</p>
        <p>Parameters Found: {len(analysis.get('parameters', []))}</p>
    </div>
    
    <h2>Technologies Detected</h2>
    <div>
"""
        
        technologies = analysis.get('technologies', [])
        for tech in technologies:
            html_content += f'<span class="tech">{tech}</span>'
        
        html_content += """
    </div>
    
    <h2>Parameters Found</h2>
    <div>
"""
        
        parameters = analysis.get('parameters', [])
        for param in parameters[:50]:  # Limit to first 50
            html_content += f'<span class="param">{param}</span>'
        
        html_content += """
    </div>
    
    <h2>Live URLs</h2>
    <div class="url-list">
        <ul>
"""
        
        live_urls = analysis.get('live_urls', [])
        for url in live_urls[:100]:  # Limit to first 100
            html_content += f'<li><a href="{url}" target="_blank">{url}</a></li>'
        
        html_content += """
        </ul>
    </div>
    
    <h2>Interesting URLs</h2>
    <div class="url-list">
        <ul>
"""
        
        interesting_urls = analysis.get('interesting_urls', [])
        for url in interesting_urls[:100]:  # Limit to first 100
            html_content += f'<li><a href="{url}" target="_blank">{url}</a></li>'
        
        html_content += """
        </ul>
    </div>
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
    
    def interactive_config(self):
        """Interactive configuration menu"""
        print(f"\n{Fore.CYAN}WaybackURLs Configuration:{Style.RESET_ALL}")
        
        # Threads
        threads = input(f"Number of threads [default: {self.config['threads']}]: ").strip()
        if threads.isdigit():
            self.config['threads'] = int(threads)
        
        # Timeout
        timeout = input(f"Timeout in seconds [default: {self.config['timeout']}]: ").strip()
        if timeout.isdigit():
            self.config['timeout'] = int(timeout)
        
        # Analysis options
        print(f"\n{Fore.YELLOW}Analysis Options:{Style.RESET_ALL}")
        
        check_live = input("Check if URLs are live? (y/n) [default: y]: ").strip().lower()
        if check_live == 'n':
            self.config['analysis']['check_live'] = False
        
        check_params = input("Extract parameters? (y/n) [default: y]: ").strip().lower()
        if check_params == 'n':
            self.config['analysis']['check_parameters'] = False
        
        check_endpoints = input("Extract endpoints? (y/n) [default: y]: ").strip().lower()
        if check_endpoints == 'n':
            self.config['analysis']['check_endpoints'] = False
        
        check_tech = input("Detect technologies? (y/n) [default: y]: ").strip().lower()
        if check_tech == 'n':
            self.config['analysis']['check_technologies'] = False
        
        print(f"\n{Fore.GREEN}[+] Configuration updated{Style.RESET_ALL}")

def run(target: str):
    """Main function to run WaybackURLs scanner"""
    scanner = WaybackURLsScanner()
    scanner.show_banner()
    
    # Interactive configuration
    scanner.interactive_config()
    
    # Run scan
    results = scanner.run_scan(target)
    
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
        print(f"{Fore.RED}[-] Usage: python waybackurls_scanner.py <target_domain>{Style.RESET_ALL}")
