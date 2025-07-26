import re
import json
import base64
import hashlib
import asyncio
import aiohttp
from urllib.parse import urljoin, urlparse, parse_qs
from colorama import Fore, Style
from bs4 import BeautifulSoup
from core.config import Config
from core.engine import make_request
import time
from collections import defaultdict
from typing import Dict, List, Set, Tuple, Optional

# Module description for the framework
description = "Advanced JavaScript file analysis with security vulnerability detection"

# Enhanced regex patterns for comprehensive analysis
PATTERNS = {
    'api_endpoints': re.compile(r'''
        (?:
            [\'\"](https?://[^\'"]+/(?:api|rest|graphql|ajax|json)[^\'"]*)[\'\""]|
            [\'\"](/(?:api|rest|graphql|ajax|json)/[^\'"]*)[\'\""]|
            (?:fetch|axios|XMLHttpRequest)[\s\(][\'\""]([^'\"]+)[\'\""]|
            \.(?:get|post|put|delete|patch)\s*\([\'\""]([^'\"]+)[\'\""]|
            endpoint\s*[:=]\s*[\'\""]([^'\"]+)[\'\""]|
            url\s*[:=]\s*[\'\""]([^'\"]+)[\'\""]
        )
    ''', re.VERBOSE | re.IGNORECASE),
    
    'secrets': re.compile(r'''
        (?:
            (?:apikey|api_key|secret|password|token|auth_token|access_token|private_key|client_secret|oauth_token|bearer_token|jwt_secret|db_password|redis_password|mongo_password|mysql_password|postgres_password|ftp_password|smtp_password|ldap_password|webhook_secret|encryption_key|signing_key|session_secret|cookie_secret|csrf_token|xsrf_token|api_secret|service_key|license_key|registration_key|activation_key|verification_code|reset_token|confirm_token|refresh_token|id_token|nonce|state|code_verifier|code_challenge)\s*[:=]\s*[\'\""]([^'\"]{8,})[\'\""]|
            (?:password|pwd|pass|secret|key|token)\s*[:=]\s*[\'\""]([^'\"]{6,})[\'\""]
        )
    ''', re.VERBOSE | re.IGNORECASE),
    
    'urls': re.compile(r'https?://[^\s\'"<>)}\]]+'),
    
    'jwt': re.compile(r'eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*'),
    
    'sensitive_functions': re.compile(r'''
        (?:
            localStorage\.(?:setItem|getItem|removeItem|clear)|
            sessionStorage\.(?:setItem|getItem|removeItem|clear)|
            document\.cookie|
            XMLHttpRequest|
            fetch\s*\(|
            postMessage\s*\(|
            addEventListener\s*\([\'\""]message[\'\""]|
            window\.name|
            location\.(?:hash|search|href)|
            history\.(?:pushState|replaceState)|
            navigator\.(?:userAgent|platform|language)|
            screen\.(?:width|height|availWidth|availHeight)|
            crypto\.(?:getRandomValues|subtle)|
            btoa\s*\(|
            atob\s*\(|
            JSON\.parse\s*\(|
            JSON\.stringify\s*\(
        )
    ''', re.VERBOSE | re.IGNORECASE),
    
    'dangerous_functions': re.compile(r'''
        (?:
            eval\s*\(|
            Function\s*\(|
            setTimeout\s*\([^,]*[\'\""][^'\"]*[\'\""]|
            setInterval\s*\([^,]*[\'\""][^'\"]*[\'\""]|
            execScript\s*\(|
            innerHTML\s*=|
            outerHTML\s*=|
            document\.write\s*\(|
            document\.writeln\s*\(|
            \.insertAdjacentHTML\s*\(|
            \.createContextualFragment\s*\(|
            new\s+Function\s*\(|
            with\s*\(|
            arguments\.callee|
            \.call\s*\(|
            \.apply\s*\(|
            \.bind\s*\(
        )
    ''', re.VERBOSE | re.IGNORECASE),
    
    'dom_xss_sinks': re.compile(r'''
        (?:
            \.innerHTML\s*=|
            \.outerHTML\s*=|
            \.insertAdjacentHTML\s*\(|
            \.write\s*\(|
            \.writeln\s*\(|
            \.appendChild\s*\(|
            \.insertBefore\s*\(|
            \.replaceChild\s*\(|
            \.setAttribute\s*\([\'\""](?:src|href|action|formaction|data)[\'\""]|
            \.setAttributeNS\s*\(|
            \.createContextualFragment\s*\(|
            location\.(?:href|hash|search|pathname|hostname|protocol|port)|
            history\.(?:pushState|replaceState)|
            document\.(?:URL|documentURI|baseURI)|
            window\.name
        )
    ''', re.VERBOSE | re.IGNORECASE),
    
    'dom_xss_sources': re.compile(r'''
        (?:
            location\.(?:href|hash|search|pathname|hostname|protocol|port)|
            document\.(?:URL|documentURI|baseURI|referrer|cookie)|
            window\.name|
            history\.(?:state|pushState|replaceState)|
            sessionStorage\.getItem\s*\(|
            localStorage\.getItem\s*\(|
            \.postMessage\s*\(|
            \.addEventListener\s*\([\'\""]message[\'\""]|
            \.search|
            \.hash|
            \.pathname|
            \.hostname|
            \.protocol|
            \.port
        )
    ''', re.VERBOSE | re.IGNORECASE),
    
    'hardcoded_credentials': re.compile(r'''
        (?:
            (?:admin|administrator|root|sa|test|guest|demo|user|default)[:=][\'\""]([^'\"]+)[\'\""]|
            (?:username|login|user_name|user_id)\s*[:=]\s*[\'\""]([^'\"]+)[\'\""].*(?:password|pwd|pass)\s*[:=]\s*[\'\""]([^'\"]+)[\'\""]|
            [\'\""](?:admin|administrator|root|sa|test|guest|demo|default|password|123456|admin123|root123|test123)[\'\""]
        )
    ''', re.VERBOSE | re.IGNORECASE),
    
    'crypto_functions': re.compile(r'''
        (?:
            CryptoJS\.|
            crypto\.(?:createHash|createHmac|createCipher|createDecipher|createSign|createVerify|randomBytes|pbkdf2|scrypt)|
            \.(?:encrypt|decrypt|hash|sign|verify|digest|update|final)\s*\(|
            (?:MD5|SHA1|SHA256|SHA512|AES|DES|RSA|HMAC|PBKDF2|bcrypt|scrypt)\s*\(|
            atob\s*\(|
            btoa\s*\(|
            base64|
            Buffer\.from\s*\(
        )
    ''', re.VERBOSE | re.IGNORECASE),
    
    'external_requests': re.compile(r'''
        (?:
            fetch\s*\(\s*[\'\""]?(https://[^'\"]+)[\'\""]?|
            XMLHttpRequest.*open\s*\([^,]*,\s*[\'\""]?(https://[^'\"]+)[\'\""]?|
            axios\.(?:get|post|put|delete|patch)\s*\([\'\""]?(https://[^'\"]+)[\'\""]?|
            \$\.(?:get|post|ajax)\s*\([\'\""]?(https://[^'\"]+)[\'\""]?|
            new\s+Image\s*\(\).*src\s*=\s*[\'\""]?(https://[^'\"]+)[\'\""]?|
            \.src\s*=\s*[\'\""]?(https://[^'\"]+)[\'\""]?|
            \.href\s*=\s*[\'\""]?(https://[^'\"]+)[\'\""]?
        )
    ''', re.VERBOSE | re.IGNORECASE),
    
    'file_paths': re.compile(r'''
        (?:
            [\'\""](?:/[^'\"]*\.(?:php|asp|aspx|jsp|py|rb|pl|cgi|sh|bat|sql|bak|config|conf|ini|xml|json|log|txt))[\'\""]|
            [\'\""](?:\.\.?/[^'\"]*)[\'\""]|
            [\'\""](?:/etc/[^'\"]*)[\'\""]|
            [\'\""](?:/var/[^'\"]*)[\'\""]|
            [\'\""](?:/usr/[^'\"]*)[\'\""]|
            [\'\""](?:/home/[^'\"]*)[\'\""]|
            [\'\""](?:C:\\\\[^'\"]*)[\'\""]
        )
    ''', re.VERBOSE | re.IGNORECASE),
    
    'error_messages': re.compile(r'''
        (?:
            [\'\""](?:error|exception|stack\s+trace|warning|debug|fail|fatal|critical)[^'\"]*[\'\""]|
            console\.(?:error|warn|debug|trace|log)\s*\(|
            throw\s+(?:new\s+)?(?:Error|Exception|TypeError|ReferenceError|SyntaxError)\s*\(|
            try\s*\{.*catch\s*\(|
            \.catch\s*\(|
            Promise\.reject\s*\(
        )
    ''', re.VERBOSE | re.IGNORECASE)
}

# Vulnerability severity levels
SEVERITY = {
    'critical': ['hardcoded_credentials', 'secrets', 'jwt'],
    'high': ['dangerous_functions', 'dom_xss_sinks', 'external_requests'],
    'medium': ['sensitive_functions', 'dom_xss_sources', 'crypto_functions'],
    'low': ['api_endpoints', 'file_paths', 'error_messages']
}

class JSSecurityAnalyzer:
    def __init__(self):
        self.findings = defaultdict(list)
        self.js_files = {}
        self.vulnerabilities = defaultdict(list)
        self.stats = {
            'total_files': 0,
            'total_lines': 0,
            'external_domains': set(),
            'file_sizes': {},
            'execution_time': 0
        }

    def extract_js_urls(self, target: str) -> List[str]:
        """Extract JavaScript file URLs from the target page with enhanced detection"""
        js_urls = set()
        
        try:
            response = make_request(target)
            if not response:
                return []
            
            soup = BeautifulSoup(response.text, 'html.parser')
            base_url = response.url if hasattr(response, 'url') else target
            
            # Find script tags with src attributes
            for script in soup.find_all('script'):
                if script.get('src'):
                    js_url = urljoin(base_url, script.get('src'))
                    js_urls.add(js_url)
            
            # Find link tags pointing to JS files
            for link in soup.find_all('link'):
                href = link.get('href', '')
                if href.endswith(('.js', '.mjs')) or 'javascript' in link.get('type', ''):
                    js_url = urljoin(base_url, href)
                    js_urls.add(js_url)
            
            # Find JS files in inline script content
            inline_scripts = soup.find_all('script', string=True)
            for script in inline_scripts:
                content = script.string
                if content:
                    # Look for dynamic script loading
                    for match in re.finditer(r'''(?:src|href)\s*=\s*['"]([^'"]*\.js[^'"]*)['"]''', content, re.IGNORECASE):
                        js_url = urljoin(base_url, match.group(1))
                        js_urls.add(js_url)

            # Find JS files referenced in CSS imports or other locations
            for match in re.finditer(r'''['"]((?:https?://|/)[^'"]*\.js(?:\?[^'"]*)?)['"]''', response.text):
                js_url = urljoin(base_url, match.group(1))
                js_urls.add(js_url)
                
        except Exception as e:
            print(f"{Fore.YELLOW}[!] Error extracting JS URLs from {target}: {e}{Style.RESET_ALL}")
        
        return sorted(list(js_urls))

    def analyze_js_content(self, content: str, url: str) -> Dict:
        """Comprehensive JavaScript content analysis"""
        findings = {
            'url': url,
            'size': len(content),
            'lines': len(content.split('\n')),
            'hash': hashlib.md5(content.encode()).hexdigest(),
            'vulnerabilities': defaultdict(list),
            'security_issues': [],
            'external_domains': set(),
            'suspicious_patterns': [],
            'minified': self._is_minified(content),
            'obfuscated': self._is_obfuscated(content)
        }
        
        lines = content.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            line_stripped = line.strip()
            if not line_stripped or line_stripped.startswith('//'):
                continue
                
            # Check all patterns
            for pattern_name, pattern in PATTERNS.items():
                matches = pattern.finditer(line)
                for match in matches:
                    full_match = match.group(0)
                    groups = match.groups()
                    
                    # Extract the actual value from groups
                    value = None
                    for group in groups:
                        if group and group.strip():
                            value = group.strip('\'"')
                            break
                    
                    if not value:
                        value = full_match.strip('\'"')
                    
                    finding = {
                        'line': line_num,
                        'content': line_stripped[:100] + ('...' if len(line_stripped) > 100 else ''),
                        'match': value,
                        'pattern': pattern_name,
                        'context': self._get_context(lines, line_num, 2)
                    }
                    
                    findings['vulnerabilities'][pattern_name].append(finding)
                    
                    # Extract external domains
                    if 'https://' in value:
                        try:
                            domain = urlparse(value).netloc
                            if domain:
                                findings['external_domains'].add(domain)
                        except:
                            pass
        
        # Analyze for specific security vulnerabilities
        findings['security_issues'] = self._analyze_security_issues(content, findings)
        
        return findings

    def _is_minified(self, content: str) -> bool:
        """Detect if JavaScript is minified"""
        lines = content.split('\n')
        if len(lines) < 10:
            return False
        
        # Check average line length
        avg_line_length = sum(len(line) for line in lines) / len(lines)
        
        # Check for typical minification indicators
        long_lines = sum(1 for line in lines if len(line) > 500)
        short_var_names = len(re.findall(r'\b[a-z]\b', content))
        
        return avg_line_length > 200 or long_lines > len(lines) * 0.1 or short_var_names > 50

    def _is_obfuscated(self, content: str) -> bool:
        """Detect if JavaScript is obfuscated"""
        obfuscation_patterns = [
            r'\\x[0-9a-fA-F]{2}',  # Hex encoded strings
            r'\\u[0-9a-fA-F]{4}',  # Unicode encoded strings
            r'String\.fromCharCode',  # Character code conversion
            r'eval\s*\(',  # Eval usage
            r'unescape\s*\(',  # Unescape function
            r'decodeURIComponent\s*\(',  # URI decoding
            r'atob\s*\(',  # Base64 decoding
            r'[a-zA-Z_$][a-zA-Z0-9_$]*\[\s*[\'"][a-zA-Z0-9_$]+[\'"]\s*\]',  # Bracket notation for properties
        ]
        
        obfuscation_score = 0
        for pattern in obfuscation_patterns:
            matches = len(re.findall(pattern, content))
            obfuscation_score += matches
        
        return obfuscation_score > 10

    def _get_context(self, lines: List[str], line_num: int, context_size: int = 2) -> List[str]:
        """Get surrounding lines for context"""
        start = max(0, line_num - context_size - 1)
        end = min(len(lines), line_num + context_size)
        context = []
        
        for i in range(start, end):
            prefix = ">>> " if i == line_num - 1 else "    "
            context.append(f"{prefix}{i+1:4d}: {lines[i].strip()}")
        
        return context

    def _analyze_security_issues(self, content: str, findings: Dict) -> List[Dict]:
        """Analyze for specific security vulnerabilities"""
        security_issues = []
        
        # Check for DOM XSS potential
        sources = findings['vulnerabilities'].get('dom_xss_sources', [])
        sinks = findings['vulnerabilities'].get('dom_xss_sinks', [])
        
        if sources and sinks:
            security_issues.append({
                'type': 'Potential DOM XSS',
                'severity': 'high',
                'description': f'Found {len(sources)} XSS sources and {len(sinks)} XSS sinks',
                'recommendation': 'Validate and sanitize all user inputs before using in DOM manipulation'
            })
        
        # Check for insecure cryptographic practices
        if findings['vulnerabilities'].get('crypto_functions'):
            crypto_issues = []
            if 'MD5' in content or 'SHA1' in content:
                crypto_issues.append('Weak hashing algorithms detected (MD5/SHA1)')
            if 'DES' in content:
                crypto_issues.append('Weak encryption algorithm detected (DES)')
            
            if crypto_issues:
                security_issues.append({
                    'type': 'Weak Cryptography',
                    'severity': 'medium',
                    'description': ', '.join(crypto_issues),
                    'recommendation': 'Use strong cryptographic algorithms (SHA-256, AES-256)'
                })
        
        # Check for hardcoded secrets
        if findings['vulnerabilities'].get('secrets') or findings['vulnerabilities'].get('hardcoded_credentials'):
            security_issues.append({
                'type': 'Hardcoded Secrets',
                'severity': 'critical',
                'description': 'Hardcoded credentials or API keys found',
                'recommendation': 'Remove hardcoded secrets and use environment variables or secure vaults'
            })
        
        # Check for dangerous functions
        if findings['vulnerabilities'].get('dangerous_functions'):
            security_issues.append({
                'type': 'Dangerous Functions',
                'severity': 'high',
                'description': 'Usage of potentially dangerous functions like eval(), innerHTML, etc.',
                'recommendation': 'Avoid using eval() and innerHTML with user data. Use safer alternatives'
            })
        
        return security_issues

    def download_and_analyze(self, url: str) -> Optional[Dict]:
        """Download and analyze a JavaScript file with enhanced error handling"""
        try:
            print(f"    {Fore.BLUE}[*] Downloading: {url}{Style.RESET_ALL}")
            response = make_request(url)
            
            if not response:
                return None
            
            if response.status_code != 200:
                print(f"    {Fore.YELLOW}[!] HTTP {response.status_code} for {url}{Style.RESET_ALL}")
                return None
            
            content = response.text
            if len(content) == 0:
                print(f"    {Fore.YELLOW}[!] Empty file: {url}{Style.RESET_ALL}")
                return None
            
            # Check if it's actually JavaScript
            content_type = response.headers.get('content-type', '').lower()
            if 'javascript' not in content_type and 'application/json' not in content_type:
                # Check by file extension or content
                if not (url.endswith(('.js', '.mjs')) or 'function' in content[:1000] or 'var ' in content[:1000]):
                    print(f"    {Fore.YELLOW}[!] Not a JavaScript file: {url}{Style.RESET_ALL}")
                    return None
            
            analysis = self.analyze_js_content(content, url)
            self.stats['file_sizes'][url] = len(content)
            
            return analysis
            
        except Exception as e:
            print(f"    {Fore.YELLOW}[!] Error analyzing {url}: {e}{Style.RESET_ALL}")
            return None

    def generate_detailed_report(self, all_findings: List[Dict]) -> None:
        """Generate a detailed security report"""
        if not all_findings:
            return
        
        print(f"\n{Fore.GREEN}{'='*80}")
        print(f"           DETAILED JAVASCRIPT SECURITY ANALYSIS REPORT")
        print(f"{'='*80}{Style.RESET_ALL}")
        
        # Summary statistics
        total_files = len(all_findings)
        total_lines = sum(f.get('lines', 0) for f in all_findings)
        total_size = sum(f.get('size', 0) for f in all_findings)
        total_vulns = sum(len(f.get('vulnerabilities', {})) for f in all_findings)
        
        print(f"\n{Fore.CYAN}[SUMMARY]{Style.RESET_ALL}")
        print(f"  Files Analyzed: {total_files}")
        print(f"  Total Lines: {total_lines:,}")
        print(f"  Total Size: {total_size:,} bytes ({total_size/1024:.1f} KB)")
        print(f"  Total Findings: {total_vulns}")
        
        # External domains
        all_domains = set()
        for findings in all_findings:
            all_domains.update(findings.get('external_domains', set()))
        
        if all_domains:
            print(f"\n{Fore.CYAN}[EXTERNAL DOMAINS]{Style.RESET_ALL}")
            for domain in sorted(all_domains):
                print(f"  - {domain}")
        
        # Security issues by severity
        all_security_issues = []
        for findings in all_findings:
            all_security_issues.extend(findings.get('security_issues', []))
        
        if all_security_issues:
            print(f"\n{Fore.RED}[SECURITY ISSUES]{Style.RESET_ALL}")
            for severity in ['critical', 'high', 'medium', 'low']:
                issues = [i for i in all_security_issues if i.get('severity') == severity]
                if issues:
                    color = Fore.RED if severity in ['critical', 'high'] else Fore.YELLOW if severity == 'medium' else Fore.WHITE
                    print(f"\n  {color}{severity.upper()} SEVERITY:{Style.RESET_ALL}")
                    for issue in issues:
                        print(f"    • {issue['type']}: {issue['description']}")
                        print(f"      → {issue['recommendation']}")
        
        # Detailed findings per file
        print(f"\n{Fore.CYAN}[DETAILED FINDINGS]{Style.RESET_ALL}")
        
        for findings in all_findings:
            url = findings['url']
            print(f"\n{Fore.YELLOW}File: {url}{Style.RESET_ALL}")
            print(f"  Size: {findings.get('size', 0):,} bytes | Lines: {findings.get('lines', 0):,}")
            
            if findings.get('minified'):
                print(f"  {Fore.BLUE}[INFO] File appears to be minified{Style.RESET_ALL}")
            if findings.get('obfuscated'):
                print(f"  {Fore.RED}[WARNING] File appears to be obfuscated{Style.RESET_ALL}")
            
            vulnerabilities = findings.get('vulnerabilities', {})
            
            for pattern_name, vuln_list in vulnerabilities.items():
                if not vuln_list:
                    continue
                
                # Determine severity and color
                severity_color = Fore.RED
                for sev, patterns in SEVERITY.items():
                    if pattern_name in patterns:
                        if sev == 'critical':
                            severity_color = Fore.RED
                        elif sev == 'high':
                            severity_color = Fore.MAGENTA
                        elif sev == 'medium':
                            severity_color = Fore.YELLOW
                        else:
                            severity_color = Fore.WHITE
                        break
                
                print(f"  {severity_color}[{pattern_name.upper().replace('_', ' ')}] ({len(vuln_list)} findings){Style.RESET_ALL}")
                
                # Show top 5 findings for each pattern
                for vuln in vuln_list[:5]:
                    print(f"    Line {vuln['line']}: {vuln['match']}")
                    if Config().verbose:  # If verbose mode is enabled
                        for context_line in vuln.get('context', [])[:3]:
                            print(f"      {context_line}")
                
                if len(vuln_list) > 5:
                    print(f"    ... and {len(vuln_list) - 5} more")
        
        # Save results to config
        Config().add_result('jsanalyze_advanced', {
            'summary': {
                'files_analyzed': total_files,
                'total_lines': total_lines,
                'total_size': total_size,
                'total_findings': total_vulns
            },
            'security_issues': all_security_issues,
            'external_domains': list(all_domains),
            'detailed_findings': all_findings
        })

def run(target: str):
    """Main execution function for the module"""
    start_time = time.time()
    
    print(f"{Fore.CYAN}[JSAnalyze Advanced] Starting comprehensive JavaScript security analysis on {target}...{Style.RESET_ALL}")
    
    try:
        analyzer = JSSecurityAnalyzer()
        
        # Extract JS file URLs from target page
        print(f"{Fore.BLUE}[*] Discovering JavaScript files...{Style.RESET_ALL}")
        js_urls = analyzer.extract_js_urls(target)
        
        if not js_urls:
            print(f"{Fore.YELLOW}[-] No JavaScript files found on page{Style.RESET_ALL}")
            Config().add_result('jsanalyze_advanced', 'No JavaScript files found')
            return
        
        print(f"{Fore.GREEN}[+] Found {len(js_urls)} JavaScript files to analyze{Style.RESET_ALL}")
        
        # Analyze each JavaScript file
        all_findings = []
        
        for i, url in enumerate(js_urls, 1):
            print(f"\n{Fore.BLUE}[*] Analyzing ({i}/{len(js_urls)}): {url[:80]}{'...' if len(url) > 80 else ''}{Style.RESET_ALL}")
            
            findings = analyzer.download_and_analyze(url)
            if findings:
                all_findings.append(findings)
                
                # Quick summary for each file
                vulns = findings.get('vulnerabilities', {})
                total_findings = sum(len(v) for v in vulns.values())
                security_issues = len(findings.get('security_issues', []))
                
                if total_findings > 0:
                    print(f"    {Fore.GREEN}[+] Found {total_findings} potential issues, {security_issues} security concerns{Style.RESET_ALL}")
                else:
                    print(f"    {Fore.WHITE}[-] No issues found{Style.RESET_ALL}")
        
        # Generate comprehensive report
        if all_findings:
            analyzer.generate_detailed_report(all_findings)
        else:
            print(f"{Fore.YELLOW}[-] No files could be analyzed successfully{Style.RESET_ALL}")
            Config().add_result('jsanalyze_advanced', 'No files could be analyzed')
        
        execution_time = time.time() - start_time
        print(f"\n{Fore.GREEN}[+] JavaScript analysis completed in {execution_time:.2f} seconds{Style.RESET_ALL}")
    
    except Exception as e:
        print(f"{Fore.RED}[-] Error during JavaScript analysis: {e}{Style.RESET_ALL}")
        Config().add_result('jsanalyze_advanced', f'Error during analysis: {str(e)}')

if __name__ == "__main__":
    # For testing purposes
    import sys
    if len(sys.argv) > 1:
        run(sys.argv[1])
    else:
        print("Usage: python jsanalyze.py <target_url>")