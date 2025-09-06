
import os
import threading
import queue
import time
import random
import argparse
from urllib.parse import urljoin, urlparse
from colorama import Fore, Style
from core.engine import make_request
from core.config import Config

# Module metadata
description = "Advanced directory and file brute-forcing with custom wordlists"
author = "LakshmikanthanK (@letchu_pkt)"
version = "2.1"

class WebRaptorDirBuster:
    def __init__(self, config=None):
        self.config = config or Config()
        self.threads = 10
        self.delay = 0
        self.timeout = 10
        self.custom_wordlist = None
        self.extensions = []
        self.recursive = False
        self.max_depth = 3
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0'
        ]
        self.status_codes = [200, 301, 302, 403, 401, 500]
        self.size_filter = None
        self.follow_redirects = True
        self.found_dirs = set()
        self.results = []
        self.lock = threading.Lock()
        self.start_time = None
        self.requests_made = 0
        
    def show_banner(self):
        """Display module banner"""
        banner = f"""
{Fore.CYAN}
╔══════════════════════════════════════════════════════════════╗
║                    {Fore.YELLOW}WebRaptor DirBuster v{version}{Fore.CYAN}                  ║
║              Advanced Directory & File Discovery             ║
║                  Author: LakshmikanthanK                     ║
╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""
        print(banner)
    
    def show_menu(self):
        """Display interactive configuration menu"""
        while True:
            print(f"\n{Fore.CYAN}╭─ DirBuster Configuration Menu ─╮{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}1.{Style.RESET_ALL} Set Threads          : {Fore.GREEN}{self.threads}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}2.{Style.RESET_ALL} Set Delay (seconds)  : {Fore.GREEN}{self.delay}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}3.{Style.RESET_ALL} Custom Wordlist      : {Fore.GREEN}{self.custom_wordlist or 'Default'}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}4.{Style.RESET_ALL} File Extensions      : {Fore.GREEN}{', '.join(self.extensions) if self.extensions else 'None'}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}5.{Style.RESET_ALL} Recursive Scanning   : {Fore.GREEN}{'Yes' if self.recursive else 'No'}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}6.{Style.RESET_ALL} Max Recursive Depth  : {Fore.GREEN}{self.max_depth}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}7.{Style.RESET_ALL} Status Codes Filter  : {Fore.GREEN}{', '.join(map(str, self.status_codes))}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}8.{Style.RESET_ALL} Response Size Filter : {Fore.GREEN}{self.size_filter or 'None'}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}9.{Style.RESET_ALL} Follow Redirects     : {Fore.GREEN}{'Yes' if self.follow_redirects else 'No'}{Style.RESET_ALL}")
            print(f"{Fore.CYAN}╰────────────────────────────────╯{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}s.{Style.RESET_ALL} Start Scanning")
            print(f"{Fore.YELLOW}q.{Style.RESET_ALL} Back to Main Menu")
            
            choice = input(f"{Fore.GREEN}webraptor/dirbuster{Style.RESET_ALL}> ").strip().lower()
            
            if choice == '1':
                try:
                    self.threads = int(input("Enter number of threads (1-50): "))
                    if self.threads < 1 or self.threads > 50:
                        print(f"{Fore.RED}[-] Threads must be between 1 and 50{Style.RESET_ALL}")
                        self.threads = 10
                except ValueError:
                    print(f"{Fore.RED}[-] Invalid input. Using default: 10{Style.RESET_ALL}")
                    
            elif choice == '2':
                try:
                    self.delay = float(input("Enter delay between requests (0-5 seconds): "))
                    if self.delay < 0 or self.delay > 5:
                        print(f"{Fore.RED}[-] Delay must be between 0 and 5 seconds{Style.RESET_ALL}")
                        self.delay = 0
                except ValueError:
                    print(f"{Fore.RED}[-] Invalid input. Using default: 0{Style.RESET_ALL}")
                    
            elif choice == '3':
                wordlist_path = input("Enter path to custom wordlist (or 'default' for built-in): ").strip()
                if wordlist_path.lower() == 'default':
                    self.custom_wordlist = None
                elif os.path.exists(wordlist_path):
                    self.custom_wordlist = wordlist_path
                else:
                    print(f"{Fore.RED}[-] Wordlist file not found{Style.RESET_ALL}")
                    
            elif choice == '4':
                ext_input = input("Enter file extensions (comma-separated, e.g., php,html,txt): ").strip()
                if ext_input:
                    self.extensions = [ext.strip().lstrip('.') for ext in ext_input.split(',') if ext.strip()]
                else:
                    self.extensions = []
                    
            elif choice == '5':
                self.recursive = input("Enable recursive scanning? (y/n): ").strip().lower() == 'y'
                
            elif choice == '6':
                try:
                    self.max_depth = int(input("Enter maximum recursive depth (1-5): "))
                    if self.max_depth < 1 or self.max_depth > 5:
                        print(f"{Fore.RED}[-] Max depth must be between 1 and 5{Style.RESET_ALL}")
                        self.max_depth = 3
                except ValueError:
                    print(f"{Fore.RED}[-] Invalid input. Using default: 3{Style.RESET_ALL}")
                    
            elif choice == '7':
                status_input = input("Enter status codes to include (comma-separated, e.g., 200,403,301): ").strip()
                if status_input:
                    try:
                        self.status_codes = [int(code.strip()) for code in status_input.split(',') if code.strip()]
                    except ValueError:
                        print(f"{Fore.RED}[-] Invalid status codes. Using defaults{Style.RESET_ALL}")
                        
            elif choice == '8':
                size_input = input("Enter size filter (format: min-max, e.g., 100-50000, or 'none'): ").strip()
                if size_input.lower() == 'none':
                    self.size_filter = None
                elif '-' in size_input:
                    try:
                        min_size, max_size = map(int, size_input.split('-'))
                        self.size_filter = {'min': min_size, 'max': max_size}
                    except ValueError:
                        print(f"{Fore.RED}[-] Invalid size filter format{Style.RESET_ALL}")
                        
            elif choice == '9':
                self.follow_redirects = input("Follow redirects? (y/n): ").strip().lower() == 'y'
                
            elif choice == 's':
                return True  # Start scanning
                
            elif choice == 'q':
                return False  # Back to main menu
                
    def load_wordlist(self):
        """Load wordlist from file with fallback options"""
        wordlists = []
        
        # Load custom wordlist if specified
        if self.custom_wordlist and os.path.exists(self.custom_wordlist):
            print(f"{Fore.CYAN}[*] Loading custom wordlist: {self.custom_wordlist}{Style.RESET_ALL}")
            try:
                with open(self.custom_wordlist, 'r', encoding='utf-8', errors='ignore') as f:
                    custom_words = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                    wordlists.extend(custom_words)
                    print(f"{Fore.GREEN}[+] Loaded {len(custom_words)} paths from custom wordlist{Style.RESET_ALL}")
            except Exception as e:
                print(f"{Fore.RED}[-] Error loading custom wordlist: {e}{Style.RESET_ALL}")
        
        # Load default wordlist
        default_wordlist = os.path.join('wordlists', 'dirs.txt')
        if os.path.exists(default_wordlist):
            try:
                with open(default_wordlist, 'r', encoding='utf-8', errors='ignore') as f:
                    default_words = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                    wordlists.extend(default_words)
                    print(f"{Fore.GREEN}[+] Loaded {len(default_words)} paths from default wordlist{Style.RESET_ALL}")
            except Exception as e:
                print(f"{Fore.YELLOW}[!] Error loading default wordlist: {e}{Style.RESET_ALL}")
        
        # Built-in common directories as fallback
        builtin_paths = [
            'admin', 'administrator', 'login', 'panel', 'dashboard', 'api', 'v1', 'v2',
            'backup', 'backups', 'bak', 'old', 'test', 'dev', 'staging', 'tmp', 'temp',
            'uploads', 'upload', 'files', 'file', 'assets', 'static', 'public',
            'css', 'js', 'javascript', 'images', 'img', 'media', 'content',
            'config', 'configuration', 'settings', 'db', 'database', 'data',
            'phpmyadmin', 'pma', 'adminer', 'mysql', 'sql',
            'wp-admin', 'wp-content', 'wp-includes', 'wordpress',
            'drupal', 'joomla', 'magento', 'prestashop',
            'cgi-bin', 'scripts', 'bin', 'sbin', 'usr', 'var', 'etc',
            'logs', 'log', 'error_log', 'access_log',
            'docs', 'documentation', 'doc', 'help', 'support',
            'mail', 'email', 'webmail', 'mx', 'smtp',
            'ftp', 'sftp', 'ssh', 'telnet', 'rdp',
            'security', 'secure', 'ssl', 'tls', 'cert', 'certificate'
        ]
        
        if not wordlists:
            print(f"{Fore.YELLOW}[!] No wordlist files found, using built-in paths{Style.RESET_ALL}")
            wordlists = builtin_paths
        else:
            # Add built-in paths to enhance coverage
            wordlists.extend(builtin_paths)
        
        # Remove duplicates while preserving order
        seen = set()
        unique_wordlist = []
        for word in wordlists:
            if word not in seen:
                seen.add(word)
                unique_wordlist.append(word)
        
        print(f"{Fore.CYAN}[*] Total unique paths loaded: {len(unique_wordlist)}{Style.RESET_ALL}")
        return unique_wordlist
    
    def generate_paths_with_extensions(self, base_paths):
        """Generate paths with file extensions"""
        paths = list(base_paths)  # Include original paths
        
        if self.extensions:
            print(f"{Fore.CYAN}[*] Adding file extensions: {', '.join(self.extensions)}{Style.RESET_ALL}")
            for path in base_paths:
                for ext in self.extensions:
                    if not ext.startswith('.'):
                        ext = '.' + ext
                    paths.append(f"{path}{ext}")
                    # Also try common filename patterns
                    paths.append(f"index{ext}")
                    paths.append(f"default{ext}")
                    paths.append(f"main{ext}")
        
        return paths
    
    def is_valid_response(self, response):
        """Check if response meets filtering criteria"""
        if not response:
            return False
            
        # Status code filter
        if response.status_code not in self.status_codes:
            return False
            
        # Size filter
        if self.size_filter:
            content_length = len(response.content) if hasattr(response, 'content') and response.content else 0
            if 'min' in self.size_filter and content_length < self.size_filter['min']:
                return False
            if 'max' in self.size_filter and content_length > self.size_filter['max']:
                return False
                
        return True
    
    def get_random_user_agent(self):
        """Get random user agent for requests"""
        return random.choice(self.user_agents)
    
    def format_size(self, size_bytes):
        """Format file size in human readable format"""
        if size_bytes < 1024:
            return f"{size_bytes}B"
        elif size_bytes < 1024**2:
            return f"{size_bytes/1024:.1f}KB"
        elif size_bytes < 1024**3:
            return f"{size_bytes/(1024**2):.1f}MB"
        else:
            return f"{size_bytes/(1024**3):.1f}GB"
    
    def dir_worker(self, target, q, depth=0):
        """Worker thread for directory brute-forcing"""
        while not q.empty():
            try:
                path = q.get(timeout=1)
                
                # Apply delay if specified
                if self.delay > 0:
                    time.sleep(self.delay + random.uniform(0, 0.1))
                
                url = urljoin(target.rstrip('/') + '/', path.lstrip('/'))
                
                # Set random user agent
                headers = {'User-Agent': self.get_random_user_agent()}
                
                response = make_request(url, headers=headers, timeout=self.timeout)
                
                with self.lock:
                    self.requests_made += 1
                
                if self.is_valid_response(response):
                    content_length = len(response.content) if hasattr(response, 'content') and response.content else 0
                    size_str = self.format_size(content_length)
                    
                    # Color coding based on status
                    if response.status_code == 200:
                        color = Fore.GREEN
                        status_text = "OK"
                    elif response.status_code in [301, 302]:
                        color = Fore.BLUE
                        status_text = "REDIRECT"
                        if hasattr(response, 'headers') and response.headers.get('Location'):
                            location = response.headers.get('Location', '')[:50]
                            status_text += f" -> {location}"
                    elif response.status_code in [403, 401]:
                        color = Fore.YELLOW
                        status_text = "RESTRICTED"
                    elif response.status_code == 500:
                        color = Fore.MAGENTA
                        status_text = "ERROR"
                    else:
                        color = Fore.CYAN
                        status_text = "FOUND"
                    
                    result_info = {
                        'url': url,
                        'status_code': response.status_code,
                        'size': content_length,
                        'depth': depth,
                        'path': path
                    }
                    
                    with self.lock:
                        self.results.append(result_info)
                        print(f"{color}[+] {url:<60} [{response.status_code}] [{size_str}] {status_text}{Style.RESET_ALL}")
                    
                    # For recursive scanning
                    if (self.recursive and depth < self.max_depth and 
                        response.status_code in [200, 301, 302, 403] and
                        not any(path.endswith(ext) for ext in ['.txt', '.html', '.php', '.asp', '.jsp', '.xml', '.json'])):
                        
                        if url not in self.found_dirs:
                            self.found_dirs.add(url)
                            # Add common subdirectories for recursive scanning
                            common_subdirs = ['admin', 'api', 'backup', 'config', 'test', 'tmp']
                            for subdir in common_subdirs:
                                q.put(f"{path.rstrip('/')}/{subdir}")
                
                q.task_done()
                
            except queue.Empty:
                break
            except Exception as e:
                if "timeout" not in str(e).lower():
                    print(f"{Fore.RED}[-] Error processing {path}: {str(e)}{Style.RESET_ALL}")
                q.task_done()
    
    def print_statistics(self):
        """Print scanning statistics"""
        elapsed_time = time.time() - self.start_time
        requests_per_second = self.requests_made / elapsed_time if elapsed_time > 0 else 0
        
        print(f"\n{Fore.CYAN}{'='*80}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Scan Statistics:{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Total Requests: {self.requests_made}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Total Found: {len(self.results)}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Elapsed Time: {elapsed_time:.2f}s{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Requests/sec: {requests_per_second:.2f}{Style.RESET_ALL}")
        
        # Show breakdown by status code
        status_breakdown = {}
        for result in self.results:
            status = result['status_code']
            status_breakdown[status] = status_breakdown.get(status, 0) + 1
        
        print(f"{Fore.CYAN}[*] Results by Status Code:{Style.RESET_ALL}")
        for status, count in sorted(status_breakdown.items()):
            print(f"    {status}: {count}")
        
        print(f"{Fore.CYAN}{'='*80}{Style.RESET_ALL}")
    
    def save_results(self):
        """Save results to WebRaptor config and files"""
        if not self.results:
            return
            
        # Save to WebRaptor config
        found_urls = [result['url'] for result in self.results]
        self.config.add_result('dirbuster', {
            'found_paths': found_urls,
            'total_found': len(self.results),
            'scan_time': time.time() - self.start_time,
            'target': self.config.target
        })
        
        # Save detailed results to file
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        output_file = f"dirbuster_results_{timestamp}.txt"
        
        try:
            with open(output_file, 'w') as f:
                f.write(f"WebRaptor DirBuster Results\n")
                f.write(f"Target: {self.config.target}\n")
                f.write(f"Scan Time: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Total Found: {len(self.results)}\n")
                f.write("="*80 + "\n\n")
                
                for result in sorted(self.results, key=lambda x: x['status_code']):
                    f.write(f"[{result['status_code']}] {result['url']} ({self.format_size(result['size'])})\n")
            
            print(f"{Fore.GREEN}[+] Results saved to {output_file}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[-] Error saving results: {e}{Style.RESET_ALL}")
    
    def run_scan(self, target):
        """Main scanning function"""
        print(f"\n{Fore.CYAN}[*] Starting DirBuster scan on: {target}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Configuration:{Style.RESET_ALL}")
        print(f"    Threads: {self.threads}")
        print(f"    Extensions: {', '.join(self.extensions) if self.extensions else 'None'}")
        print(f"    Recursive: {'Yes' if self.recursive else 'No'}")
        print(f"    Delay: {self.delay}s")
        print(f"    Status Codes: {', '.join(map(str, self.status_codes))}")
        print(f"{Fore.CYAN}{'='*80}{Style.RESET_ALL}")
        
        self.start_time = time.time()
        
        wordlist = self.load_wordlist()
        if not wordlist:
            print(f"{Fore.RED}[-] No wordlist available{Style.RESET_ALL}")
            return
        
        # Generate paths with extensions
        paths = self.generate_paths_with_extensions(wordlist)
        
        q = queue.Queue()
        
        # Fill the queue with paths to test
        for path in paths:
            q.put(path)
        
        print(f"{Fore.CYAN}[*] Testing {q.qsize()} paths...{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[*] Press Ctrl+C to stop the scan{Style.RESET_ALL}\n")
        
        # Create and start worker threads
        threads = []
        for i in range(self.threads):
            t = threading.Thread(target=self.dir_worker, args=(target, q, 0))
            t.daemon = True
            t.start()
            threads.append(t)
        
        try:
            # Wait for all paths to be processed
            q.join()
            
            # Wait for all threads to complete
            for t in threads:
                t.join()
                
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}[!] Scan interrupted by user{Style.RESET_ALL}")
        
        self.print_statistics()
        self.save_results()
        
        if self.results:
            print(f"\n{Fore.GREEN}[+] DirBuster scan completed! Found {len(self.results)} accessible paths{Style.RESET_ALL}")
        else:
            print(f"\n{Fore.YELLOW}[!] No accessible paths found{Style.RESET_ALL}")

def run(target):
    """Main entry point for WebRaptor framework"""
    try:
        config = Config()
        scanner = WebRaptorDirBuster(config)
        
        scanner.show_banner()
        
        # Show interactive menu for configuration
        if scanner.show_menu():
            scanner.run_scan(target)
        else:
            print(f"{Fore.YELLOW}[!] DirBuster scan cancelled{Style.RESET_ALL}")
            
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Module interrupted by user{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[-] Error in DirBuster module: {e}{Style.RESET_ALL}")

if __name__ == "__main__":
    # For standalone testing
    import sys
    if len(sys.argv) > 1:
        run(sys.argv[1])
    else:
        print("Usage: python dirbuster.py <target_url>")