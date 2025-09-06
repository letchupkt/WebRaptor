#!/usr/bin/env python3
"""
WebRaptor Configuration Management System
Advanced configuration management for API keys, tool settings, and user preferences
"""

import os
import sys
import json
import yaml
import base64
from pathlib import Path
from typing import Dict, Any, Optional, List
from colorama import Fore, Style, init
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import getpass

init()

# Module metadata
description = "Advanced configuration management system for API keys, tool settings, and user preferences"
author = "LakshmikanthanK (@letchu_pkt)"
version = "2.1"

class ConfigurationManager:
    """Advanced configuration management system"""
    
    def __init__(self):
        self.config_dir = Path("output/config")
        self.config_file = self.config_dir / "webraptor_config.json"
        self.secrets_file = self.config_dir / "secrets.encrypted"
        self.templates_dir = self.config_dir / "templates"
        
        # Create directories
        self.config_dir.mkdir(parents=True, exist_ok=True)
        self.templates_dir.mkdir(parents=True, exist_ok=True)
        
        # Configuration structure
        self.config_structure = {
            'general': {
                'default_timeout': 30,
                'max_threads': 50,
                'output_format': 'html',
                'auto_save': True,
                'log_level': 'INFO',
                'theme': 'dark'
            },
            'tools': {
                'nmap': {
                    'timeout': 300,
                    'threads': 10,
                    'scan_type': 'comprehensive',
                    'custom_flags': []
                },
                'nuclei': {
                    'timeout': 600,
                    'threads': 25,
                    'rate_limit': 150,
                    'templates_path': 'nuclei-templates',
                    'severity_filter': ['critical', 'high', 'medium', 'low', 'info']
                },
                'nikto': {
                    'timeout': 1800,
                    'user_agent': 'Mozilla/5.0 (compatible; WebRaptor-Scanner/2.1)',
                    'evasion': '1',
                    'tuning': '0'
                },
                'subfinder': {
                    'timeout': 300,
                    'threads': 10,
                    'resolvers': ['8.8.8.8', '1.1.1.1'],
                    'all_sources': True
                },
                'httpx': {
                    'timeout': 10,
                    'threads': 50,
                    'rate_limit': 100,
                    'follow_redirects': True,
                    'tech_detect': True
                }
            },
            'api_keys': {
                'shodan': {
                    'api_key': '',
                    'enabled': False,
                    'rate_limit': 1
                },
                'virustotal': {
                    'api_key': '',
                    'enabled': False,
                    'rate_limit': 4
                },
                'securitytrails': {
                    'api_key': '',
                    'enabled': False,
                    'rate_limit': 1
                },
                'censys': {
                    'api_id': '',
                    'api_secret': '',
                    'enabled': False,
                    'rate_limit': 1
                },
                'github': {
                    'token': '',
                    'enabled': False,
                    'rate_limit': 5000
                }
            },
            'scanning': {
                'default_wordlists': {
                    'subdomains': 'wordlists/subdomains.txt',
                    'directories': 'wordlists/directories.txt',
                    'passwords': 'wordlists/passwords.txt'
                },
                'scan_profiles': {
                    'quick': {
                        'timeout': 300,
                        'threads': 20,
                        'depth': 1
                    },
                    'comprehensive': {
                        'timeout': 1800,
                        'threads': 50,
                        'depth': 3
                    },
                    'stealth': {
                        'timeout': 3600,
                        'threads': 5,
                        'depth': 2
                    }
                }
            },
            'reporting': {
                'default_format': 'html',
                'include_screenshots': True,
                'include_payloads': True,
                'auto_open': False,
                'email_notifications': False,
                'email_recipients': []
            },
            'notifications': {
                'slack': {
                    'webhook_url': '',
                    'enabled': False,
                    'channel': '#security-alerts'
                },
                'discord': {
                    'webhook_url': '',
                    'enabled': False
                },
                'email': {
                    'smtp_server': '',
                    'smtp_port': 587,
                    'username': '',
                    'password': '',
                    'enabled': False
                }
            }
        }
        
        # Load existing configuration
        self.config = self._load_config()
        self.secrets = self._load_secrets()
    
    def show_banner(self):
        """Display configuration manager banner"""
        banner = f"""
{Fore.BLUE}╔══════════════════════════════════════════════════════════════════════════╗
║                {Fore.YELLOW}WebRaptor Configuration Manager v{version}{Fore.BLUE}               ║
║              Advanced Configuration Management & API Key Security      ║
║                        Author: LakshmikanthanK (@letchu_pkt)             ║
║                                                                          ║
╚══════════════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""
        print(banner)
    
    def _load_config(self) -> Dict:
        """Load configuration from file"""
        if self.config_file.exists():
            try:
                with open(self.config_file, 'r') as f:
                    config = json.load(f)
                # Merge with default structure
                return self._merge_config(self.config_structure, config)
            except Exception as e:
                print(f"{Fore.YELLOW}[!] Error loading config: {e}{Style.RESET_ALL}")
        
        return self.config_structure.copy()
    
    def _merge_config(self, default: Dict, loaded: Dict) -> Dict:
        """Merge loaded configuration with defaults"""
        merged = default.copy()
        
        for key, value in loaded.items():
            if key in merged:
                if isinstance(value, dict) and isinstance(merged[key], dict):
                    merged[key] = self._merge_config(merged[key], value)
                else:
                    merged[key] = value
            else:
                merged[key] = value
        
        return merged
    
    def _load_secrets(self) -> Dict:
        """Load encrypted secrets"""
        if self.secrets_file.exists():
            try:
                password = self._get_master_password()
                if password:
                    decrypted_data = self._decrypt_file(self.secrets_file, password)
                    return json.loads(decrypted_data)
            except Exception as e:
                print(f"{Fore.YELLOW}[!] Error loading secrets: {e}{Style.RESET_ALL}")
        
        return {}
    
    def _get_master_password(self) -> Optional[str]:
        """Get master password for encryption"""
        try:
            password = getpass.getpass("Enter master password for secrets: ")
            return password if password else None
        except KeyboardInterrupt:
            return None
    
    def _encrypt_data(self, data: str, password: str) -> bytes:
        """Encrypt data with password"""
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        fernet = Fernet(key)
        
        encrypted_data = fernet.encrypt(data.encode())
        return salt + encrypted_data
    
    def _decrypt_data(self, encrypted_data: bytes, password: str) -> str:
        """Decrypt data with password"""
        salt = encrypted_data[:16]
        encrypted_data = encrypted_data[16:]
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        fernet = Fernet(key)
        
        decrypted_data = fernet.decrypt(encrypted_data)
        return decrypted_data.decode()
    
    def _encrypt_file(self, filepath: Path, data: str, password: str):
        """Encrypt and save data to file"""
        encrypted_data = self._encrypt_data(data, password)
        with open(filepath, 'wb') as f:
            f.write(encrypted_data)
    
    def _decrypt_file(self, filepath: Path, password: str) -> str:
        """Decrypt data from file"""
        with open(filepath, 'rb') as f:
            encrypted_data = f.read()
        return self._decrypt_data(encrypted_data, password)
    
    def save_config(self):
        """Save configuration to file"""
        try:
            with open(self.config_file, 'w') as f:
                json.dump(self.config, f, indent=2)
            print(f"{Fore.GREEN}[+] Configuration saved successfully{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[-] Error saving configuration: {e}{Style.RESET_ALL}")
    
    def save_secrets(self):
        """Save encrypted secrets to file"""
        try:
            password = self._get_master_password()
            if password:
                secrets_data = json.dumps(self.secrets)
                self._encrypt_file(self.secrets_file, secrets_data, password)
                print(f"{Fore.GREEN}[+] Secrets saved successfully{Style.RESET_ALL}")
            else:
                print(f"{Fore.YELLOW}[!] No password provided, secrets not saved{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[-] Error saving secrets: {e}{Style.RESET_ALL}")
    
    def set_api_key(self, service: str, api_key: str, encrypt: bool = True):
        """Set API key for a service"""
        if service not in self.config['api_keys']:
            print(f"{Fore.RED}[-] Unknown service: {service}{Style.RESET_ALL}")
            return
        
        if encrypt:
            self.secrets[f"{service}_api_key"] = api_key
            self.config['api_keys'][service]['enabled'] = True
            print(f"{Fore.GREEN}[+] API key for {service} saved securely{Style.RESET_ALL}")
        else:
            self.config['api_keys'][service]['api_key'] = api_key
            self.config['api_keys'][service]['enabled'] = True
            print(f"{Fore.GREEN}[+] API key for {service} saved{Style.RESET_ALL}")
    
    def get_api_key(self, service: str) -> Optional[str]:
        """Get API key for a service"""
        if service not in self.config['api_keys']:
            return None
        
        # Try encrypted storage first
        encrypted_key = self.secrets.get(f"{service}_api_key")
        if encrypted_key:
            return encrypted_key
        
        # Fall back to plain text storage
        return self.config['api_keys'][service].get('api_key')
    
    def set_tool_config(self, tool: str, config_key: str, value: Any):
        """Set configuration for a specific tool"""
        if tool not in self.config['tools']:
            print(f"{Fore.RED}[-] Unknown tool: {tool}{Style.RESET_ALL}")
            return
        
        self.config['tools'][tool][config_key] = value
        print(f"{Fore.GREEN}[+] Configuration updated for {tool}.{config_key}{Style.RESET_ALL}")
    
    def get_tool_config(self, tool: str, config_key: str = None) -> Any:
        """Get configuration for a specific tool"""
        if tool not in self.config['tools']:
            return None
        
        if config_key:
            return self.config['tools'][tool].get(config_key)
        else:
            return self.config['tools'][tool]
    
    def set_scan_profile(self, profile_name: str, profile_config: Dict):
        """Set a scan profile"""
        self.config['scanning']['scan_profiles'][profile_name] = profile_config
        print(f"{Fore.GREEN}[+] Scan profile '{profile_name}' updated{Style.RESET_ALL}")
    
    def get_scan_profile(self, profile_name: str) -> Optional[Dict]:
        """Get a scan profile"""
        return self.config['scanning']['scan_profiles'].get(profile_name)
    
    def list_scan_profiles(self):
        """List available scan profiles"""
        print(f"\n{Fore.CYAN}Available Scan Profiles:{Style.RESET_ALL}")
        for profile_name, profile_config in self.config['scanning']['scan_profiles'].items():
            print(f"  {Fore.YELLOW}{profile_name}:{Style.RESET_ALL}")
            print(f"    Timeout: {profile_config.get('timeout', 'N/A')}s")
            print(f"    Threads: {profile_config.get('threads', 'N/A')}")
            print(f"    Depth: {profile_config.get('depth', 'N/A')}")
    
    def configure_api_keys(self):
        """Interactive API key configuration"""
        print(f"\n{Fore.CYAN}API Key Configuration:{Style.RESET_ALL}")
        
        for service, config in self.config['api_keys'].items():
            print(f"\n{Fore.YELLOW}{service.upper()}:{Style.RESET_ALL}")
            print(f"  Status: {'Enabled' if config.get('enabled', False) else 'Disabled'}")
            
            if not config.get('enabled', False):
                configure = input(f"Configure {service} API key? (y/n): ").strip().lower()
                if configure == 'y':
                    api_key = getpass.getpass(f"Enter {service} API key: ")
                    if api_key:
                        self.set_api_key(service, api_key)
                        self.save_secrets()
    
    def configure_tools(self):
        """Interactive tool configuration"""
        print(f"\n{Fore.CYAN}Tool Configuration:{Style.RESET_ALL}")
        
        for tool, config in self.config['tools'].items():
            print(f"\n{Fore.YELLOW}{tool.upper()}:{Style.RESET_ALL}")
            for key, value in config.items():
                print(f"  {key}: {value}")
            
            configure = input(f"Configure {tool}? (y/n): ").strip().lower()
            if configure == 'y':
                for key in config.keys():
                    new_value = input(f"Enter new value for {key} (current: {config[key]}): ").strip()
                    if new_value:
                        try:
                            # Try to convert to appropriate type
                            if isinstance(config[key], int):
                                new_value = int(new_value)
                            elif isinstance(config[key], bool):
                                new_value = new_value.lower() in ['true', 'yes', 'y', '1']
                            elif isinstance(config[key], list):
                                new_value = [item.strip() for item in new_value.split(',')]
                            
                            self.set_tool_config(tool, key, new_value)
                        except ValueError:
                            print(f"{Fore.RED}[-] Invalid value for {key}{Style.RESET_ALL}")
    
    def export_config(self, filepath: str, include_secrets: bool = False):
        """Export configuration to file"""
        try:
            export_data = self.config.copy()
            
            if include_secrets:
                export_data['secrets'] = self.secrets
            
            if filepath.endswith('.yaml') or filepath.endswith('.yml'):
                with open(filepath, 'w') as f:
                    yaml.dump(export_data, f, default_flow_style=False)
            else:
                with open(filepath, 'w') as f:
                    json.dump(export_data, f, indent=2)
            
            print(f"{Fore.GREEN}[+] Configuration exported to {filepath}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[-] Error exporting configuration: {e}{Style.RESET_ALL}")
    
    def import_config(self, filepath: str):
        """Import configuration from file"""
        try:
            if filepath.endswith('.yaml') or filepath.endswith('.yml'):
                with open(filepath, 'r') as f:
                    import_data = yaml.safe_load(f)
            else:
                with open(filepath, 'r') as f:
                    import_data = json.load(f)
            
            # Merge imported configuration
            self.config = self._merge_config(self.config, import_data)
            
            if 'secrets' in import_data:
                self.secrets.update(import_data['secrets'])
            
            print(f"{Fore.GREEN}[+] Configuration imported from {filepath}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[-] Error importing configuration: {e}{Style.RESET_ALL}")
    
    def reset_config(self):
        """Reset configuration to defaults"""
        confirm = input("Are you sure you want to reset all configuration? (y/n): ").strip().lower()
        if confirm == 'y':
            self.config = self.config_structure.copy()
            self.secrets = {}
            print(f"{Fore.GREEN}[+] Configuration reset to defaults{Style.RESET_ALL}")
    
    def show_config(self, section: str = None):
        """Show current configuration"""
        if section:
            if section in self.config:
                print(f"\n{Fore.CYAN}{section.upper()} Configuration:{Style.RESET_ALL}")
                print(json.dumps(self.config[section], indent=2))
            else:
                print(f"{Fore.RED}[-] Unknown section: {section}{Style.RESET_ALL}")
        else:
            print(f"\n{Fore.CYAN}Current Configuration:{Style.RESET_ALL}")
            print(json.dumps(self.config, indent=2))
    
    def validate_config(self) -> List[str]:
        """Validate configuration and return any issues"""
        issues = []
        
        # Check API keys
        for service, config in self.config['api_keys'].items():
            if config.get('enabled', False):
                api_key = self.get_api_key(service)
                if not api_key:
                    issues.append(f"API key for {service} is enabled but not configured")
        
        # Check tool configurations
        for tool, config in self.config['tools'].items():
            if 'timeout' in config and config['timeout'] <= 0:
                issues.append(f"Invalid timeout for {tool}")
            if 'threads' in config and config['threads'] <= 0:
                issues.append(f"Invalid thread count for {tool}")
        
        return issues

def main():
    """Main function for configuration manager"""
    manager = ConfigurationManager()
    manager.show_banner()
    
    while True:
        print(f"\n{Fore.YELLOW}Configuration Manager Menu:{Style.RESET_ALL}")
        print("1. Configure API Keys")
        print("2. Configure Tools")
        print("3. Manage Scan Profiles")
        print("4. Show Configuration")
        print("5. Export Configuration")
        print("6. Import Configuration")
        print("7. Validate Configuration")
        print("8. Reset Configuration")
        print("9. Save Configuration")
        print("0. Exit")
        
        choice = input(f"\n{Fore.GREEN}Select option: {Style.RESET_ALL}").strip()
        
        if choice == '1':
            manager.configure_api_keys()
        elif choice == '2':
            manager.configure_tools()
        elif choice == '3':
            manager.list_scan_profiles()
        elif choice == '4':
            section = input("Enter section name (or press Enter for all): ").strip()
            manager.show_config(section if section else None)
        elif choice == '5':
            filepath = input("Enter export filepath: ").strip()
            include_secrets = input("Include secrets? (y/n): ").strip().lower() == 'y'
            manager.export_config(filepath, include_secrets)
        elif choice == '6':
            filepath = input("Enter import filepath: ").strip()
            manager.import_config(filepath)
        elif choice == '7':
            issues = manager.validate_config()
            if issues:
                print(f"\n{Fore.RED}Configuration Issues:{Style.RESET_ALL}")
                for issue in issues:
                    print(f"  • {issue}")
            else:
                print(f"\n{Fore.GREEN}[+] Configuration is valid{Style.RESET_ALL}")
        elif choice == '8':
            manager.reset_config()
        elif choice == '9':
            manager.save_config()
            manager.save_secrets()
        elif choice == '0':
            break
        else:
            print(f"{Fore.RED}[-] Invalid option{Style.RESET_ALL}")

if __name__ == "__main__":
    main()
