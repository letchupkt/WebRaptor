#!/usr/bin/env python3
"""
WebRaptor Setup Script
Initialize WebRaptor with proper directory structure and dependencies
"""

import os
import sys
import subprocess
import platform
from pathlib import Path
from colorama import Fore, Style, init

init()

def print_banner():
    """Print setup banner"""
    banner = f"""
{Fore.BLUE}
╔══════════════════════════════════════════════════════════════════════════╗
║                    {Fore.YELLOW}WebRaptor Setup Script v2.1{Fore.BLUE}                    ║
║                    Initialize WebRaptor Environment                      ║
║                        Author: LakshmikanthanK (@letchu_pkt)             ║
║                                                                          ║
╚══════════════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""
    print(banner)

def check_python_version():
    """Check Python version"""
    print(f"{Fore.CYAN}[*] Checking Python version...{Style.RESET_ALL}")
    
    if sys.version_info < (3, 8):
        print(f"{Fore.RED}[-] Python 3.8+ is required. Current version: {sys.version}{Style.RESET_ALL}")
        return False
    
    print(f"{Fore.GREEN}[+] Python version: {sys.version.split()[0]} ✓{Style.RESET_ALL}")
    return True

def check_dependencies():
    """Check system dependencies"""
    print(f"{Fore.CYAN}[*] Checking system dependencies...{Style.RESET_ALL}")
    
    dependencies = {
        'git': 'git --version',
        'curl': 'curl --version',
        'wget': 'wget --version',
        'unzip': 'unzip -v',
        'tar': 'tar --version'
    }
    
    missing_deps = []
    
    for dep, cmd in dependencies.items():
        try:
            result = subprocess.run(cmd.split(), capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                print(f"{Fore.GREEN}[+] {dep} ✓{Style.RESET_ALL}")
            else:
                missing_deps.append(dep)
                print(f"{Fore.RED}[-] {dep} ✗{Style.RESET_ALL}")
        except (subprocess.TimeoutExpired, FileNotFoundError):
            missing_deps.append(dep)
            print(f"{Fore.RED}[-] {dep} ✗{Style.RESET_ALL}")
    
    if missing_deps:
        print(f"{Fore.YELLOW}[!] Missing dependencies: {', '.join(missing_deps)}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[!] Please install them before continuing{Style.RESET_ALL}")
        return False
    
    return True

def check_package_managers():
    """Check available package managers"""
    print(f"{Fore.CYAN}[*] Checking package managers...{Style.RESET_ALL}")
    
    package_managers = []
    
    # Check for apt (Ubuntu/Debian)
    if subprocess.run(['which', 'apt'], capture_output=True).returncode == 0:
        package_managers.append('apt')
        print(f"{Fore.GREEN}[+] apt (Ubuntu/Debian) ✓{Style.RESET_ALL}")
    
    # Check for yum (CentOS/RHEL)
    if subprocess.run(['which', 'yum'], capture_output=True).returncode == 0:
        package_managers.append('yum')
        print(f"{Fore.GREEN}[+] yum (CentOS/RHEL) ✓{Style.RESET_ALL}")
    
    # Check for dnf (Fedora)
    if subprocess.run(['which', 'dnf'], capture_output=True).returncode == 0:
        package_managers.append('dnf')
        print(f"{Fore.GREEN}[+] dnf (Fedora) ✓{Style.RESET_ALL}")
    
    # Check for pacman (Arch)
    if subprocess.run(['which', 'pacman'], capture_output=True).returncode == 0:
        package_managers.append('pacman')
        print(f"{Fore.GREEN}[+] pacman (Arch) ✓{Style.RESET_ALL}")
    
    # Check for brew (macOS)
    if subprocess.run(['which', 'brew'], capture_output=True).returncode == 0:
        package_managers.append('brew')
        print(f"{Fore.GREEN}[+] brew (macOS) ✓{Style.RESET_ALL}")
    
    # Check for choco (Windows)
    if subprocess.run(['which', 'choco'], capture_output=True).returncode == 0:
        package_managers.append('choco')
        print(f"{Fore.GREEN}[+] choco (Windows) ✓{Style.RESET_ALL}")
    
    if not package_managers:
        print(f"{Fore.YELLOW}[!] No package managers found{Style.RESET_ALL}")
        return False
    
    return True

def create_directory_structure():
    """Create WebRaptor directory structure"""
    print(f"{Fore.CYAN}[*] Creating directory structure...{Style.RESET_ALL}")
    
    directories = [
        "output",
        "output/reports",
        "output/reports/html",
        "output/reports/json",
        "output/reports/pdf",
        "output/scans",
        "output/scans/subdomain",
        "output/scans/waybackurls",
        "output/scans/nuclei",
        "output/scans/nikto",
        "output/scans/sqlmap",
        "output/scans/advanced_tools",
        "output/scans/portscan",
        "output/scans/tech_detect",
        "output/scans/xss",
        "output/scans/screenshot",
        "output/logs",
        "output/config",
        "output/config/templates",
        "output/wordlists",
        "output/tools",
        "output/tools/bin",
        "output/temp",
        "output/temp/scans",
        "output/temp/downloads"
    ]
    
    for directory in directories:
        Path(directory).mkdir(parents=True, exist_ok=True)
        print(f"{Fore.GREEN}[+] Created: {directory}{Style.RESET_ALL}")
    
    return True

def install_python_dependencies():
    """Install Python dependencies"""
    print(f"{Fore.CYAN}[*] Installing Python dependencies...{Style.RESET_ALL}")
    
    try:
        result = subprocess.run([
            sys.executable, '-m', 'pip', 'install', '-r', 'requirements.txt'
        ], capture_output=True, text=True, timeout=300)
        
        if result.returncode == 0:
            print(f"{Fore.GREEN}[+] Python dependencies installed successfully{Style.RESET_ALL}")
            return True
        else:
            print(f"{Fore.RED}[-] Failed to install Python dependencies{Style.RESET_ALL}")
            print(f"{Fore.RED}[-] Error: {result.stderr}{Style.RESET_ALL}")
            return False
    except subprocess.TimeoutExpired:
        print(f"{Fore.RED}[-] Installation timeout{Style.RESET_ALL}")
        return False
    except Exception as e:
        print(f"{Fore.RED}[-] Installation error: {e}{Style.RESET_ALL}")
        return False

def create_wordlists():
    """Create basic wordlists"""
    print(f"{Fore.CYAN}[*] Creating basic wordlists...{Style.RESET_ALL}")
    
    # Subdomain wordlist
    subdomain_wordlist = Path("output/wordlists/subdomains.txt")
    subdomain_words = [
        "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "webdisk", "ns2",
        "cpanel", "whm", "autodiscover", "autoconfig", "ns3", "mssql", "mysql", "roundcube",
        "plesk", "panel", "pop3", "imap", "blog", "pop3s", "imaps", "smtp", "smtps", "smtp",
        "dev", "www2", "admin", "forum", "news", "vpn", "ns", "mail2", "new", "mysql", "old",
        "www1", "beta", "shop", "stage", "api", "secure", "demo", "app", "media", "support",
        "test", "docs", "beta", "staging", "cdn", "m", "mx", "default", "com", "org", "net",
        "info", "app", "apps", "cloud", "mail", "email", "web", "www", "ftp", "admin", "root",
        "api", "api1", "api2", "api3", "apis", "app", "app1", "app2", "app3", "apps", "beta",
        "beta1", "beta2", "beta3", "betas", "blog", "blogs", "cdn", "cdn1", "cdn2", "cdn3",
        "cdns", "dev", "dev1", "dev2", "dev3", "devs", "docs", "docs1", "docs2", "docs3",
        "docss", "ftp", "ftps", "git", "git1", "git2", "git3", "gits", "help", "help1",
        "help2", "help3", "helps", "imap", "imaps", "mail", "mail1", "mail2", "mail3",
        "mails", "mx", "mx1", "mx2", "mx3", "mxs", "news", "news1", "news2", "news3",
        "newss", "ns", "ns1", "ns2", "ns3", "nss", "pop", "pop3", "pop3s", "pops", "smtp",
        "smtps", "smtps", "support", "support1", "support2", "support3", "supports", "test",
        "test1", "test2", "test3", "tests", "vpn", "vpn1", "vpn2", "vpn3", "vpns", "web",
        "web1", "web2", "web3", "webs", "www", "www1", "www2", "www3", "wwws"
    ]
    
    with open(subdomain_wordlist, 'w') as f:
        f.write('\n'.join(subdomain_words))
    print(f"{Fore.GREEN}[+] Created: {subdomain_wordlist}{Style.RESET_ALL}")
    
    # Directory wordlist
    directory_wordlist = Path("output/wordlists/directories.txt")
    directory_words = [
        "admin", "administrator", "api", "app", "apps", "backup", "backups", "blog", "blogs",
        "cdn", "config", "configuration", "css", "data", "database", "db", "dev", "development",
        "docs", "documentation", "download", "downloads", "email", "emails", "files", "ftp",
        "git", "help", "images", "img", "js", "javascript", "lib", "library", "libraries",
        "logs", "mail", "media", "mobile", "news", "old", "panel", "php", "private", "public",
        "secure", "security", "server", "servers", "site", "sites", "src", "source", "sources",
        "static", "stats", "statistics", "support", "test", "tests", "testing", "tmp", "temp",
        "upload", "uploads", "user", "users", "v1", "v2", "v3", "version", "versions", "web",
        "webapp", "webapps", "www", "xml", "xsl", "zip", "zips"
    ]
    
    with open(directory_wordlist, 'w') as f:
        f.write('\n'.join(directory_words))
    print(f"{Fore.GREEN}[+] Created: {directory_wordlist}{Style.RESET_ALL}")
    
    # Password wordlist
    password_wordlist = Path("output/wordlists/passwords.txt")
    password_words = [
        "admin", "password", "123456", "123456789", "qwerty", "abc123", "password123",
        "admin123", "root", "toor", "pass", "test", "guest", "user", "administrator",
        "12345", "1234", "123", "111111", "000000", "123123", "654321", "superman",
        "qazwsx", "michael", "football", "jordan", "harley", "ranger", "hunter", "fuck",
        "master", "jennifer", "joshua", "monkey", "shadow", "superman", "qwertyuiop",
        "123qwe", "dragon", "sunshine", "lovely", "654321", "welcome", "princess",
        "master", "hello", "freedom", "whatever", "qazwsx", "trustno1", "dragon",
        "bitch", "jordan", "jennifer", "zxcvbnm", "asdfgh", "qwerty", "1234567890",
        "qwertyuiop", "asdfghjkl", "zxcvbnm", "password", "123456", "123456789",
        "qwerty", "abc123", "password123", "admin123", "root", "toor", "pass"
    ]
    
    with open(password_wordlist, 'w') as f:
        f.write('\n'.join(password_words))
    print(f"{Fore.GREEN}[+] Created: {password_wordlist}{Style.RESET_ALL}")
    
    return True

def create_config_files():
    """Create default configuration files"""
    print(f"{Fore.CYAN}[*] Creating configuration files...{Style.RESET_ALL}")
    
    # Default WebRaptor config
    config_data = {
        "general": {
            "default_timeout": 30,
            "max_threads": 50,
            "output_format": "html",
            "auto_save": True,
            "log_level": "INFO",
            "theme": "dark"
        },
        "tools": {
            "nmap": {
                "timeout": 300,
                "threads": 10,
                "scan_type": "comprehensive",
                "custom_flags": []
            },
            "nuclei": {
                "timeout": 600,
                "threads": 25,
                "rate_limit": 150,
                "templates_path": "nuclei-templates",
                "severity_filter": ["critical", "high", "medium", "low", "info"]
            }
        },
        "api_keys": {
            "shodan": {
                "api_key": "",
                "enabled": False,
                "rate_limit": 1
            },
            "virustotal": {
                "api_key": "",
                "enabled": False,
                "rate_limit": 4
            }
        },
        "scanning": {
            "default_wordlists": {
                "subdomains": "output/wordlists/subdomains.txt",
                "directories": "output/wordlists/directories.txt",
                "passwords": "output/wordlists/passwords.txt"
            },
            "scan_profiles": {
                "quick": {
                    "timeout": 300,
                    "threads": 20,
                    "depth": 1
                },
                "comprehensive": {
                    "timeout": 1800,
                    "threads": 50,
                    "depth": 3
                },
                "stealth": {
                    "timeout": 3600,
                    "threads": 5,
                    "depth": 2
                }
            }
        }
    }
    
    config_file = Path("output/config/webraptor_config.json")
    with open(config_file, 'w') as f:
        import json
        json.dump(config_data, f, indent=2)
    print(f"{Fore.GREEN}[+] Created: {config_file}{Style.RESET_ALL}")
    
    return True

def create_gitignore():
    """Create .gitignore file"""
    print(f"{Fore.CYAN}[*] Creating .gitignore file...{Style.RESET_ALL}")
    
    gitignore_content = """
# WebRaptor Output
output/
*.log
*.session

# Python
__pycache__/
*.py[cod]
*$py.class
*.so
.Python
build/
develop-eggs/
dist/
downloads/
eggs/
.eggs/
lib/
lib64/
parts/
sdist/
var/
wheels/
*.egg-info/
.installed.cfg
*.egg

# Virtual Environment
venv/
env/
ENV/

# IDE
.vscode/
.idea/
*.swp
*.swo

# OS
.DS_Store
Thumbs.db

# Temporary files
*.tmp
*.temp
temp/
tmp/

# Logs
logs/
*.log

# Reports
reports/
*.html
*.pdf
*.json

# Tools
tools/
bin/
"""
    
    with open('.gitignore', 'w') as f:
        f.write(gitignore_content)
    print(f"{Fore.GREEN}[+] Created: .gitignore{Style.RESET_ALL}")
    
    return True

def main():
    """Main setup function"""
    print_banner()
    
    print(f"{Fore.CYAN}[*] Starting WebRaptor setup...{Style.RESET_ALL}")
    
    # Check Python version
    if not check_python_version():
        sys.exit(1)
    
    # Check system dependencies
    if not check_dependencies():
        print(f"{Fore.YELLOW}[!] Some dependencies are missing, but continuing...{Style.RESET_ALL}")
    
    # Check package managers
    if not check_package_managers():
        print(f"{Fore.YELLOW}[!] No package managers found, but continuing...{Style.RESET_ALL}")
    
    # Create directory structure
    if not create_directory_structure():
        print(f"{Fore.RED}[-] Failed to create directory structure{Style.RESET_ALL}")
        sys.exit(1)
    
    # Install Python dependencies
    if not install_python_dependencies():
        print(f"{Fore.RED}[-] Failed to install Python dependencies{Style.RESET_ALL}")
        sys.exit(1)
    
    # Create wordlists
    if not create_wordlists():
        print(f"{Fore.RED}[-] Failed to create wordlists{Style.RESET_ALL}")
        sys.exit(1)
    
    # Create config files
    if not create_config_files():
        print(f"{Fore.RED}[-] Failed to create configuration files{Style.RESET_ALL}")
        sys.exit(1)
    
    # Create .gitignore
    if not create_gitignore():
        print(f"{Fore.RED}[-] Failed to create .gitignore{Style.RESET_ALL}")
        sys.exit(1)
    
    print(f"\n{Fore.GREEN}╔══════════════════════════════════════════════════════════════════════════╗")
    print(f"║                        {Fore.YELLOW}Setup Complete!{Fore.GREEN}                        ║")
    print(f"╚══════════════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}")
    
    print(f"\n{Fore.CYAN}Next steps:{Style.RESET_ALL}")
    print(f"1. Run WebRaptor: {Fore.GREEN}python main.py{Style.RESET_ALL}")
    print(f"2. Set target: {Fore.GREEN}set target example.com{Style.RESET_ALL}")
    print(f"3. Install tools: {Fore.GREEN}tools install{Style.RESET_ALL}")
    print(f"4. Run scan: {Fore.GREEN}auto{Style.RESET_ALL}")
    
    print(f"\n{Fore.CYAN}Documentation:{Style.RESET_ALL}")
    print(f"- README.md: Complete documentation")
    print(f"- GitHub: https://github.com/letchu_pkt/WebRaptor")
    print(f"- Issues: https://github.com/letchu_pkt/WebRaptor/issues")
    
    print(f"\n{Fore.GREEN}[+] WebRaptor is ready to use!{Style.RESET_ALL}")

if __name__ == "__main__":
    main()
