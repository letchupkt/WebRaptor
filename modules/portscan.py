import socket
import threading
import time
import ssl
import json
import struct
import random
import re
from urllib.parse import urlparse
from colorama import Fore, Style
from core.config import Config
from concurrent.futures import ThreadPoolExecutor, as_completed
import ipaddress
import subprocess
import platform

# Module information
description = "Advanced Port Scanner with service detection, OS fingerprinting, and vulnerability assessment"

class AdvancedPortScanner:
    def __init__(self):
        self.config = Config()
        self.open_ports = {}
        self.host_info = {}
        self.scan_results = {
            'target': '',
            'ip_address': '',
            'hostname': '',
            'ports': {},
            'os_info': {},
            'vulnerabilities': [],
            'scan_stats': {}
        }
        
        # Comprehensive port definitions
        self.port_definitions = {
            # Web services
            80: {'service': 'http', 'description': 'HTTP Web Server', 'category': 'web'},
            443: {'service': 'https', 'description': 'HTTPS Web Server', 'category': 'web'},
            8080: {'service': 'http-alt', 'description': 'HTTP Alternative', 'category': 'web'},
            8443: {'service': 'https-alt', 'description': 'HTTPS Alternative', 'category': 'web'},
            8000: {'service': 'http-alt', 'description': 'HTTP Development', 'category': 'web'},
            8008: {'service': 'http', 'description': 'HTTP Alternative', 'category': 'web'},
            8081: {'service': 'http', 'description': 'HTTP Proxy', 'category': 'web'},
            8090: {'service': 'http', 'description': 'HTTP Alternative', 'category': 'web'},
            8181: {'service': 'http', 'description': 'HTTP Alternative', 'category': 'web'},
            8888: {'service': 'http', 'description': 'HTTP Alternative', 'category': 'web'},
            9000: {'service': 'http', 'description': 'HTTP Development', 'category': 'web'},
            3000: {'service': 'http', 'description': 'Node.js/React Dev', 'category': 'web'},
            4000: {'service': 'http', 'description': 'HTTP Development', 'category': 'web'},
            5000: {'service': 'http', 'description': 'Flask/Python Dev', 'category': 'web'},
            
            # SSH and Remote Access
            22: {'service': 'ssh', 'description': 'SSH Remote Login', 'category': 'remote'},
            23: {'service': 'telnet', 'description': 'Telnet Remote Login', 'category': 'remote'},
            3389: {'service': 'rdp', 'description': 'Remote Desktop Protocol', 'category': 'remote'},
            5900: {'service': 'vnc', 'description': 'VNC Remote Desktop', 'category': 'remote'},
            5901: {'service': 'vnc', 'description': 'VNC Remote Desktop', 'category': 'remote'},
            
            # Database Services
            3306: {'service': 'mysql', 'description': 'MySQL Database', 'category': 'database'},
            5432: {'service': 'postgresql', 'description': 'PostgreSQL Database', 'category': 'database'},
            1433: {'service': 'mssql', 'description': 'Microsoft SQL Server', 'category': 'database'},
            1521: {'service': 'oracle', 'description': 'Oracle Database', 'category': 'database'},
            27017: {'service': 'mongodb', 'description': 'MongoDB Database', 'category': 'database'},
            27018: {'service': 'mongodb', 'description': 'MongoDB Shard', 'category': 'database'},
            28017: {'service': 'mongodb', 'description': 'MongoDB Web Interface', 'category': 'database'},
            6379: {'service': 'redis', 'description': 'Redis Database', 'category': 'database'},
            11211: {'service': 'memcached', 'description': 'Memcached', 'category': 'database'},
            
            # Mail Services
            25: {'service': 'smtp', 'description': 'SMTP Mail Server', 'category': 'mail'},
            110: {'service': 'pop3', 'description': 'POP3 Mail Server', 'category': 'mail'},
            143: {'service': 'imap', 'description': 'IMAP Mail Server', 'category': 'mail'},
            993: {'service': 'imaps', 'description': 'IMAP over SSL', 'category': 'mail'},
            995: {'service': 'pop3s', 'description': 'POP3 over SSL', 'category': 'mail'},
            587: {'service': 'smtp', 'description': 'SMTP Submission', 'category': 'mail'},
            
            # DNS and Network
            53: {'service': 'dns', 'description': 'Domain Name System', 'category': 'network'},
            67: {'service': 'dhcp', 'description': 'DHCP Server', 'category': 'network'},
            68: {'service': 'dhcp', 'description': 'DHCP Client', 'category': 'network'},
            
            # File Services
            21: {'service': 'ftp', 'description': 'File Transfer Protocol', 'category': 'file'},
            69: {'service': 'tftp', 'description': 'Trivial FTP', 'category': 'file'},
            139: {'service': 'netbios-ssn', 'description': 'NetBIOS Session Service', 'category': 'file'},
            445: {'service': 'smb', 'description': 'SMB/CIFS File Sharing', 'category': 'file'},
            2049: {'service': 'nfs', 'description': 'Network File System', 'category': 'file'},
            
            # Security and Authentication
            88: {'service': 'kerberos', 'description': 'Kerberos Authentication', 'category': 'security'},
            389: {'service': 'ldap', 'description': 'LDAP Directory Service', 'category': 'security'},
            636: {'service': 'ldaps', 'description': 'LDAP over SSL', 'category': 'security'},
            1723: {'service': 'pptp', 'description': 'PPTP VPN', 'category': 'security'},
            
            # Application Services
            111: {'service': 'rpcbind', 'description': 'RPC Port Mapper', 'category': 'rpc'},
            135: {'service': 'msrpc', 'description': 'Microsoft RPC', 'category': 'rpc'},
            1099: {'service': 'rmiregistry', 'description': 'Java RMI Registry', 'category': 'application'},
            2375: {'service': 'docker', 'description': 'Docker REST API', 'category': 'application'},
            2376: {'service': 'docker', 'description': 'Docker REST API (SSL)', 'category': 'application'},
            6443: {'service': 'kubernetes', 'description': 'Kubernetes API', 'category': 'application'},
            9200: {'service': 'elasticsearch', 'description': 'Elasticsearch', 'category': 'application'},
            9300: {'service': 'elasticsearch', 'description': 'Elasticsearch Transport', 'category': 'application'},
            
            # Gaming and Media
            25565: {'service': 'minecraft', 'description': 'Minecraft Server', 'category': 'gaming'},
            27015: {'service': 'steam', 'description': 'Steam/Source Engine', 'category': 'gaming'},
            7777: {'service': 'game', 'description': 'Game Server', 'category': 'gaming'},
            
            # Development and Debug
            4444: {'service': 'debug', 'description': 'Debug/Development', 'category': 'development'},
            8009: {'service': 'ajp13', 'description': 'Apache JServ Protocol', 'category': 'development'},
            9001: {'service': 'debug', 'description': 'Debug/Monitoring', 'category': 'development'},
            
            # IoT and Embedded
            1883: {'service': 'mqtt', 'description': 'MQTT IoT Protocol', 'category': 'iot'},
            8883: {'service': 'mqtt', 'description': 'MQTT over SSL', 'category': 'iot'},
            5683: {'service': 'coap', 'description': 'CoAP IoT Protocol', 'category': 'iot'}
        }
        
        # Service fingerprinting patterns
        self.service_banners = {
            'ssh': [b'SSH-', b'OpenSSH'],
            'http': [b'HTTP/', b'Server:', b'<html', b'<HTML'],
            'https': [b'HTTP/', b'Server:'],
            'ftp': [b'220', b'FTP'],
            'smtp': [b'220', b'SMTP', b'ESMTP'],
            'pop3': [b'+OK', b'POP3'],
            'imap': [b'* OK', b'IMAP'],
            'mysql': [b'mysql_native_password', b'Got packets out of order'],
            'postgresql': [b'FATAL', b'PostgreSQL'],
            'redis': [b'-ERR wrong number of arguments', b'+PONG'],
            'mongodb': [b'It looks like you are trying to access MongoDB'],
            'elasticsearch': [b'"cluster_name"', b'"version"'],
            'telnet': [b'Login:', b'Username:', b'Password:']
        }

    def resolve_hostname(self, target):
        """Resolve hostname to IP address with reverse lookup"""
        try:
            parsed = urlparse(target) if target.startswith(('http://', 'https://')) else urlparse(f'http://{target}')
            hostname = parsed.netloc.split(':')[0] if parsed.netloc else target.split(':')[0]
            
            # Get IP address
            ip_address = socket.gethostbyname(hostname)
            
            # Reverse DNS lookup
            try:
                reverse_hostname = socket.gethostbyaddr(ip_address)[0]
            except socket.herror:
                reverse_hostname = hostname
            
            self.scan_results['hostname'] = hostname
            self.scan_results['ip_address'] = ip_address
            
            return hostname, ip_address, reverse_hostname
        
        except socket.gaierror as e:
            raise Exception(f"Could not resolve hostname: {e}")

    def get_port_list(self, target, scan_type='common'):
        """Generate port list based on scan type"""
        parsed = urlparse(target) if target.startswith(('http://', 'https://')) else urlparse(f'http://{target}')
        
        # If specific port in URL, scan that port
        if ':' in parsed.netloc and parsed.netloc.split(':')[1].isdigit():
            return [int(parsed.netloc.split(':')[1])]
        
        if scan_type == 'common':
            return [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 587, 993, 995, 1433, 1521, 1723, 3306, 3389, 5432, 5900, 6379, 8000, 8080, 8443, 8888, 9200, 27017]
        elif scan_type == 'full':
            return list(range(1, 1001))  # First 1000 ports
        elif scan_type == 'top1000':
            # Nmap's top 1000 ports (simplified)
            return list(self.port_definitions.keys()) + list(range(1, 1001))
        else:
            return [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 3306, 3389, 5432, 8080]

    def tcp_connect_scan(self, ip, port, timeout=2):
        """Standard TCP connect scan"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            return result == 0
        except Exception:
            return False

    def syn_scan(self, ip, port):
        """SYN scan (requires root privileges)"""
        try:
            # This is a simplified version - full SYN scan requires raw sockets
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            sock.setblocking(False)
            result = sock.connect_ex((ip, port))
            sock.close()
            return result in [0, 36]  # Connected or in progress
        except Exception:
            return False

    def grab_banner(self, ip, port, timeout=3):
        """Attempt to grab service banner"""
        banner = ""
        service_info = {}
        
        try:
            # Standard banner grabbing
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((ip, port))
            
            # Send appropriate probes based on port
            if port in [21, 22, 23, 25, 110, 143]:
                # Services that send banner immediately
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            elif port in [80, 8080, 8000, 8008, 8081, 8090, 8181, 8888]:
                # HTTP services
                sock.send(b'GET / HTTP/1.1\r\nHost: ' + ip.encode() + b'\r\n\r\n')
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            elif port == 443 or port == 8443:
                # HTTPS services
                try:
                    context = ssl.create_default_context()
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    ssock = context.wrap_socket(sock, server_hostname=ip)
                    ssock.send(b'GET / HTTP/1.1\r\nHost: ' + ip.encode() + b'\r\n\r\n')
                    banner = ssock.recv(1024).decode('utf-8', errors='ignore').strip()
                    
                    # Get SSL certificate info
                    cert = ssock.getpeercert()
                    if cert:
                        service_info['ssl_cert'] = {
                            'subject': cert.get('subject', []),
                            'issuer': cert.get('issuer', []),
                            'version': cert.get('version', ''),
                            'serial_number': cert.get('serialNumber', ''),
                            'not_before': cert.get('notBefore', ''),
                            'not_after': cert.get('notAfter', '')
                        }
                except Exception:
                    pass
            elif port == 3306:
                # MySQL
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            elif port == 5432:
                # PostgreSQL - send startup message
                startup = struct.pack('>II', 196608, 0)  # Protocol version 3.0
                sock.send(struct.pack('>I', len(startup) + 4) + startup)
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            elif port == 6379:
                # Redis
                sock.send(b'INFO\r\n')
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            elif port == 1433:
                # MSSQL - send pre-login packet
                sock.send(b'\x12\x01\x00\x34\x00\x00\x00\x00\x00\x00\x15\x00\x06\x01\x00\x1b\x00\x01\x02\x00\x1c\x00\x0c\x03\x00\x28\x00\x04\xff\x08\x00\x01\x55\x00\x00\x00\x4d\x53\x53\x51\x4c\x53\x65\x72\x76\x65\x72\x00\x48\x0f\x00\x00')
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            else:
                # Generic probe
                sock.send(b'\r\n')
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            
            sock.close()
            
        except Exception as e:
            pass
        
        # Identify service from banner
        service_info['banner'] = banner
        service_info['service'] = self.identify_service_from_banner(port, banner)
        
        return service_info

    def identify_service_from_banner(self, port, banner):
        """Identify service from banner information"""
        banner_lower = banner.lower()
        
        # Check known patterns
        for service, patterns in self.service_banners.items():
            for pattern in patterns:
                if pattern.decode('utf-8', errors='ignore').lower() in banner_lower:
                    return service
        
        # Use port-based identification if banner doesn't match
        if port in self.port_definitions:
            return self.port_definitions[port]['service']
        
        return 'unknown'

    def detect_os_fingerprint(self, ip, open_ports):
        """Attempt OS fingerprinting based on various indicators"""
        os_info = {
            'os_type': 'unknown',
            'confidence': 0,
            'indicators': []
        }
        
        try:
            # TTL-based detection
            if platform.system().lower() != 'windows':
                try:
                    result = subprocess.run(['ping', '-c', '1', ip], 
                                          capture_output=True, text=True, timeout=5)
                    if result.returncode == 0:
                        ttl_match = re.search(r'ttl=(\d+)', result.stdout.lower())
                        if ttl_match:
                            ttl = int(ttl_match.group(1))
                            if ttl <= 64:
                                os_info['os_type'] = 'linux/unix'
                                os_info['confidence'] = 60
                                os_info['indicators'].append(f'TTL={ttl} (Linux/Unix)')
                            elif ttl <= 128:
                                os_info['os_type'] = 'windows'
                                os_info['confidence'] = 60
                                os_info['indicators'].append(f'TTL={ttl} (Windows)')
                except Exception:
                    pass
            
            # Port-based OS detection
            if 3389 in open_ports:
                os_info['os_type'] = 'windows'
                os_info['confidence'] = max(os_info['confidence'], 80)
                os_info['indicators'].append('RDP port open (Windows)')
            
            if 22 in open_ports and 80 in open_ports:
                os_info['os_type'] = 'linux/unix'
                os_info['confidence'] = max(os_info['confidence'], 70)
                os_info['indicators'].append('SSH + HTTP (Linux/Unix)')
            
            if 135 in open_ports and 445 in open_ports:
                os_info['os_type'] = 'windows'
                os_info['confidence'] = max(os_info['confidence'], 85)
                os_info['indicators'].append('SMB + RPC (Windows)')
                
        except Exception as e:
            os_info['indicators'].append(f'Error in OS detection: {str(e)}')
        
        return os_info

    def check_vulnerabilities(self, ip, port, service_info):
        """Check for common vulnerabilities"""
        vulnerabilities = []
        
        try:
            service = service_info.get('service', 'unknown')
            banner = service_info.get('banner', '')
            
            # Anonymous FTP
            if port == 21 and service == 'ftp':
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(5)
                    sock.connect((ip, port))
                    sock.recv(1024)  # Welcome banner
                    sock.send(b'USER anonymous\r\n')
                    response = sock.recv(1024).decode('utf-8', errors='ignore')
                    if '230' in response or '331' in response:
                        vulnerabilities.append({
                            'type': 'Anonymous FTP Access',
                            'severity': 'Medium',
                            'description': 'FTP server allows anonymous login',
                            'port': port
                        })
                    sock.close()
                except Exception:
                    pass
            
            # Open MongoDB
            if port == 27017 and service == 'mongodb':
                vulnerabilities.append({
                    'type': 'Open MongoDB',
                    'severity': 'High',
                    'description': 'MongoDB accessible without authentication',
                    'port': port
                })
            
            # Open Redis
            if port == 6379 and service == 'redis':
                vulnerabilities.append({
                    'type': 'Open Redis',
                    'severity': 'High',
                    'description': 'Redis accessible without authentication',
                    'port': port
                })
            
            # Open Elasticsearch
            if port == 9200 and service == 'elasticsearch':
                vulnerabilities.append({
                    'type': 'Open Elasticsearch',
                    'severity': 'High',
                    'description': 'Elasticsearch accessible without authentication',
                    'port': port
                })
            
            # Telnet service
            if port == 23 and service == 'telnet':
                vulnerabilities.append({
                    'type': 'Telnet Service',
                    'severity': 'Medium',
                    'description': 'Unencrypted Telnet service detected',
                    'port': port
                })
            
            # SSL/TLS issues
            if 'ssl_cert' in service_info:
                cert_info = service_info['ssl_cert']
                # Check for expired certificates, weak algorithms, etc.
                # (This would require more detailed certificate analysis)
            
            # Version-specific vulnerabilities
            if banner:
                # Check for old SSH versions
                if 'ssh' in banner.lower():
                    if 'openssh_4' in banner.lower() or 'openssh_3' in banner.lower():
                        vulnerabilities.append({
                            'type': 'Outdated SSH Version',
                            'severity': 'Medium',
                            'description': f'Old SSH version detected: {banner}',
                            'port': port
                        })
                
                # Check for old web servers
                if 'apache' in banner.lower():
                    version_match = re.search(r'apache/(\d+\.\d+)', banner.lower())
                    if version_match:
                        version = float(version_match.group(1))
                        if version < 2.4:
                            vulnerabilities.append({
                                'type': 'Outdated Apache Version',
                                'severity': 'Medium',
                                'description': f'Old Apache version: {version}',
                                'port': port
                            })
        
        except Exception:
            pass
        
        return vulnerabilities

    def scan_port_advanced(self, ip, port):
        """Advanced port scanning with service detection"""
        result = {
            'port': port,
            'state': 'closed',
            'service': 'unknown',
            'banner': '',
            'vulnerabilities': []
        }
        
        # TCP Connect scan
        if self.tcp_connect_scan(ip, port):
            result['state'] = 'open'
            
            # Get port definition
            if port in self.port_definitions:
                port_def = self.port_definitions[port]
                result['service'] = port_def['service']
                result['description'] = port_def['description']
                result['category'] = port_def['category']
            
            # Banner grabbing and service detection
            service_info = self.grab_banner(ip, port)
            result.update(service_info)
            
            # Vulnerability checking
            result['vulnerabilities'] = self.check_vulnerabilities(ip, port, service_info)
            
            return result
        
        return None

    def run_scan(self, hostname, ip_address, ports, max_threads=100):
        """Run comprehensive port scan"""
        print(f"[*] Scanning {len(ports)} ports on {hostname} ({ip_address})")
        print(f"[*] Using {max_threads} threads for scanning")
        
        start_time = time.time()
        scan_results = []
        
        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            future_to_port = {
                executor.submit(self.scan_port_advanced, ip_address, port): port 
                for port in ports
            }
            
            completed = 0
            for future in as_completed(future_to_port):
                result = future.result()
                if result and result['state'] == 'open':
                    scan_results.append(result)
                    service_name = result.get('service', 'unknown')
                    description = result.get('description', '')
                    category = result.get('category', '')
                    
                    color = Fore.GREEN
                    if result['vulnerabilities']:
                        color = Fore.RED
                    elif category in ['database', 'remote']:
                        color = Fore.YELLOW
                    
                    print(f"{color}[+] {result['port']}/tcp open - {service_name} ({description}){Style.RESET_ALL}")
                    
                    if result['vulnerabilities']:
                        for vuln in result['vulnerabilities']:
                            print(f"    {Fore.RED}→ {vuln['type']} ({vuln['severity']}){Style.RESET_ALL}")
                
                completed += 1
                if completed % 100 == 0:
                    print(f"[*] Progress: {completed}/{len(ports)} ports scanned")
        
        scan_time = time.time() - start_time
        print(f"[*] Scan completed in {scan_time:.2f} seconds")
        
        return scan_results, scan_time

    def generate_report(self, scan_results, scan_time):
        """Generate comprehensive scan report"""
        self.scan_results['ports'] = {str(result['port']): result for result in scan_results}
        self.scan_results['scan_stats'] = {
            'total_ports_scanned': len(self.get_port_list(self.scan_results['target'])),
            'open_ports_found': len(scan_results),
            'scan_duration': scan_time,
            'scan_timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
        }
        
        # OS fingerprinting
        open_ports = [result['port'] for result in scan_results]
        self.scan_results['os_info'] = self.detect_os_fingerprint(
            self.scan_results['ip_address'], open_ports
        )
        
        # Collect all vulnerabilities
        all_vulnerabilities = []
        for result in scan_results:
            all_vulnerabilities.extend(result['vulnerabilities'])
        
        self.scan_results['vulnerabilities'] = all_vulnerabilities
        
        return self.scan_results

def run(target, scan_type='common'):
    """Main execution function"""
    print(f"{Fore.CYAN}[PortScan] Advanced Port Scanning for {target}{Style.RESET_ALL}")
    
    try:
        scanner = AdvancedPortScanner()
        scanner.scan_results['target'] = target
        
        # Resolve hostname
        hostname, ip_address, reverse_hostname = scanner.resolve_hostname(target)
        print(f"[*] Target: {hostname}")
        print(f"[*] IP Address: {ip_address}")
        if reverse_hostname != hostname:
            print(f"[*] Reverse DNS: {reverse_hostname}")
        
        # Get ports to scan
        ports_to_scan = scanner.get_port_list(target, scan_type)
        
        # Run scan
        scan_results, scan_time = scanner.run_scan(hostname, ip_address, ports_to_scan)
        
        # Generate report
        full_report = scanner.generate_report(scan_results, scan_time)
        
        # Display summary
        if scan_results:
            print(f"\n{Fore.GREEN}[+] Scan Summary:{Style.RESET_ALL}")
            print(f"  Open Ports: {len(scan_results)}")
            
            # Group by category
            categories = {}
            for result in scan_results:
                category = result.get('category', 'other')
                if category not in categories:
                    categories[category] = []
                categories[category].append(result['port'])
            
            for category, ports in categories.items():
                print(f"  {category.title()}: {', '.join(map(str, sorted(ports)))}")
            
            # OS Information
            os_info = full_report['os_info']
            if os_info['os_type'] != 'unknown':
                print(f"  Detected OS: {os_info['os_type']} (confidence: {os_info['confidence']}%)")
            
            # Vulnerabilities
            if full_report['vulnerabilities']:
                print(f"  {Fore.RED}Vulnerabilities Found: {len(full_report['vulnerabilities'])}{Style.RESET_ALL}")
            
            # Save results
            ports_str = ", ".join(str(result['port']) for result in scan_results)
            Config().add_result('portscan', f"Open ports ({len(scan_results)}): {ports_str}")
            Config().add_result('portscan_detailed', json.dumps(full_report, indent=2))
            
        else:
            print(f"{Fore.YELLOW}[-] No open ports found{Style.RESET_ALL}")
            Config().add_result('portscan', 'No open ports found')
    
    except Exception as e:
        print(f"{Fore.RED}[-] Error during port scanning: {e}{Style.RESET_ALL}")
        Config().add_result('portscan', f'Error during scanning: {str(e)}')