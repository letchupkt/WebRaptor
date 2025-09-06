import cmd
import os
import readline
import atexit
import importlib.util
import subprocess
import threading
import time
import json
from pathlib import Path
from colorama import Fore, Style, init
from core.config import Config
from core.tool_manager import ToolManager
from core.config_manager import ConfigurationManager
from datetime import datetime
from typing import List, Dict, Optional

class WebRaptorShell(cmd.Cmd):
    prompt = f"{Fore.GREEN}╭──(letchu@webraptor)-[{Fore.CYAN}~{Fore.GREEN}]\n╰─${Style.RESET_ALL} "
    ruler = "─"
    doc_header = "Available commands (type help <command>):"
    
    def __init__(self):
        super().__init__()
        init()  # Initialize colorama
        self.config = Config()
        self.tool_manager = ToolManager()
        self.config_manager = ConfigurationManager()
        self.session_file = ".webraptor_history"
        self.module_aliases = self._create_aliases()
        self._setup_readline()
        self._load_session()
        self.modules = self._discover_modules()
        self.workflows = self._load_workflows()
        self.active_scans = {}
        self.show_banner()

    def _setup_readline(self):
        """Initialize readline for command history"""
        if os.path.exists(self.session_file):
            readline.read_history_file(self.session_file)
        readline.set_history_length(1000)
        atexit.register(readline.write_history_file, self.session_file)

    def _load_session(self):
        """Load previous session if exists"""
        if os.path.exists("webraptor.session"):
            try:
                with open("webraptor.session", "r") as f:
                    self.config.target = f.read().strip()
                    print(f"[+] Loaded previous target: {self.config.target}")
            except Exception as e:
                print(f"{Fore.YELLOW}[!] Error loading session: {e}{Style.RESET_ALL}")

    def _save_session(self):
        """Save current session"""
        try:
            with open("webraptor.session", "w") as f:
                if self.config.target:
                    f.write(self.config.target)
        except Exception as e:
            print(f"{Fore.YELLOW}[!] Error saving session: {e}{Style.RESET_ALL}")

    def _discover_modules(self) -> Dict[str, str]:
        """Discover and load modules from the modules/ directory"""
        modules = {}
        modules_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "modules")
        
        for filename in os.listdir(modules_dir):
            if filename.endswith(".py") and not filename.startswith("__"):
                module_name = filename[:-3]
                module_path = os.path.join(modules_dir, filename)
                
                try:
                    # Use importlib to load modules from the modules directory
                    spec = importlib.util.spec_from_file_location(f"modules.{module_name}", module_path)
                    module = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(module)
                    
                    # Get module description or use default
                    if hasattr(module, "description"):
                        modules[module_name] = module.description
                    else:
                        modules[module_name] = f"{module_name} module"
                        
                except Exception as e:
                    print(f"{Fore.YELLOW}[!] Failed to load module {module_name}: {e}{Style.RESET_ALL}")
        
        return modules

    def _create_aliases(self) -> Dict[str, str]:
        """Create command aliases"""
        return {
            'ls': 'show modules',
            'scan': 'run',
            'quit': 'exit',
            'clear': 'os.system("clear")',
            'target': 'set target',
            'install': 'tools install',
            'status': 'tools status',
            'workflow': 'run workflow',
            'auto': 'run auto',
            'exploit': 'run exploit',
            'recon': 'run recon',
            'vuln': 'run vuln',
            'settings': 'configure',
            'dashboard': 'run dashboard'
        }
    
    def _load_workflows(self) -> Dict[str, Dict]:
        """Load predefined workflows"""
        workflows_file = Path("workflows.json")
        if workflows_file.exists():
            try:
                with open(workflows_file, 'r') as f:
                    return json.load(f)
            except Exception as e:
                print(f"{Fore.YELLOW}[!] Error loading workflows: {e}{Style.RESET_ALL}")
        
        # Default workflows
        return {
            'full_recon': {
                'name': 'Full Reconnaissance',
                'description': 'Complete reconnaissance workflow',
                'steps': [
                    {'module': 'subenum', 'args': []},
                    {'module': 'portscan', 'args': []},
                    {'module': 'tech_detect', 'args': []},
                    {'module': 'dirbuster', 'args': []},
                    {'module': 'xss', 'args': []},
                    {'module': 'lfi', 'args': []}
                ]
            },
            'quick_scan': {
                'name': 'Quick Scan',
                'description': 'Fast vulnerability scan',
                'steps': [
                    {'module': 'portscan', 'args': ['-F']},
                    {'module': 'tech_detect', 'args': []},
                    {'module': 'xss', 'args': ['--quick']}
                ]
            },
            'web_app': {
                'name': 'Web Application Assessment',
                'description': 'Comprehensive web application testing',
                'steps': [
                    {'module': 'dirbuster', 'args': []},
                    {'module': 'xss', 'args': []},
                    {'module': 'lfi', 'args': []},
                    {'module': 'screenshot', 'args': []},
                    {'module': 'jsanalyse', 'args': []}
                ]
            },
            'bug_bounty': {
                'name': 'Bug Bounty Pipeline',
                'description': 'Complete bug bounty automation',
                'steps': [
                    {'tool': 'subfinder', 'args': ['-d', '{target}', '-o', 'subdomains.txt']},
                    {'tool': 'httpx', 'args': ['-l', 'subdomains.txt', '-o', 'live_hosts.txt']},
                    {'tool': 'nuclei', 'args': ['-l', 'live_hosts.txt', '-t', 'vulnerabilities/']},
                    {'tool': 'gobuster', 'args': ['-u', '{target}', '-w', 'wordlists/common.txt']},
                    {'tool': 'ffuf', 'args': ['-u', '{target}/FUZZ', '-w', 'wordlists/common.txt']}
                ]
            }
        }

    def show_banner(self):
        """Display the WebRaptor banner"""
        banner = f"""
{Fore.CYAN}
 ▄         ▄  ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄   ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄▄ 
▐░▌       ▐░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░▌ ▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌
▐░▌       ▐░▌▐░█▀▀▀▀▀▀▀▀▀ ▐░█▀▀▀▀▀▀▀█░▌▐░█▀▀▀▀▀▀▀█░▌▐░█▀▀▀▀▀▀▀█░▌▐░█▀▀▀▀▀▀▀█░▌ ▀▀▀▀█░█▀▀▀▀ ▐░█▀▀▀▀▀▀▀█░▌▐░█▀▀▀▀▀▀▀█░▌
▐░▌       ▐░▌▐░▌          ▐░▌       ▐░▌▐░▌       ▐░▌▐░▌       ▐░▌▐░▌       ▐░▌     ▐░▌     ▐░▌       ▐░▌▐░▌       ▐░▌
▐░▌   ▄   ▐░▌▐░█▄▄▄▄▄▄▄▄▄ ▐░█▄▄▄▄▄▄▄█░▌▐░█▄▄▄▄▄▄▄█░▌▐░█▄▄▄▄▄▄▄█░▌▐░█▄▄▄▄▄▄▄█░▌     ▐░▌     ▐░▌       ▐░▌▐░█▄▄▄▄▄▄▄█░▌
▐░▌  ▐░▌  ▐░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░▌ ▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌     ▐░▌     ▐░▌       ▐░▌▐░░░░░░░░░░░▌
▐░▌ ▐░▌░▌ ▐░▌▐░█▀▀▀▀▀▀▀▀▀ ▐░█▀▀▀▀▀▀▀█░▌▐░█▀▀▀▀█░█▀▀ ▐░█▀▀▀▀▀▀▀█░▌▐░█▀▀▀▀▀▀▀▀▀      ▐░▌     ▐░▌       ▐░▌▐░█▀▀▀▀█░█▀▀ 
▐░▌▐░▌ ▐░▌▐░▌▐░▌          ▐░▌       ▐░▌▐░▌     ▐░▌  ▐░▌       ▐░▌▐░▌               ▐░▌     ▐░▌       ▐░▌▐░▌     ▐░▌  
▐░▌░▌   ▐░▐░▌▐░█▄▄▄▄▄▄▄▄▄ ▐░█▄▄▄▄▄▄▄█░▌▐░▌      ▐░▌ ▐░▌       ▐░▌▐░▌               ▐░▌     ▐░█▄▄▄▄▄▄▄█░▌▐░▌      ▐░▌ 
▐░░▌     ▐░░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░▌ ▐░▌       ▐░▌▐░▌       ▐░▌▐░▌               ▐░▌     ▐░░░░░░░░░░░▌▐░▌       ▐░▌
 ▀▀       ▀▀  ▀▀▀▀▀▀▀▀▀▀▀  ▀▀▀▀▀▀▀▀▀▀   ▀         ▀  ▀         ▀  ▀                 ▀       ▀▀▀▀▀▀▀▀▀▀▀  ▀         ▀ 
{Fore.YELLOW}
  Automated Web Pentesting Framework | Version 2.1
  Developed by LakshmikanthanK (@letchu_pkt) | {datetime.now().year}
{Style.RESET_ALL}
"""
        print(banner)

    def default(self, line: str):
        """Handle unknown commands and aliases"""
        if line in self.module_aliases:
            self.onecmd(self.module_aliases[line])
        else:
            print(f"{Fore.RED}[-] Unknown command: {line}{Style.RESET_ALL}")

    def emptyline(self):
        """Do nothing on empty input"""
        pass

    def precmd(self, line: str) -> str:
        """Log commands before execution"""
        self._save_session()
        return line

    def completenames(self, text: str, *ignored) -> List[str]:
        """Custom tab completion"""
        commands = [
            'set', 'show', 'run', 'generate', 'tools', 'workflow',
            'credits', 'exit', 'help', 'clear', 'auto', 'exploit',
            'recon', 'vuln', 'status', 'install'
        ]
        return [cmd for cmd in commands if cmd.startswith(text)]

    def complete_run(self, text: str, line: str, begidx: int, endidx: int) -> List[str]:
        """Tab completion for run command"""
        return [mod for mod in self.modules.keys() if mod.startswith(text)]

    def complete_set(self, text: str, line: str, begidx: int, endidx: int) -> List[str]:
        """Tab completion for set command"""
        options = ['target']
        return [opt for opt in options if opt.startswith(text)]

    def do_set(self, arg: str):
        """Set target URL or other options: set target <url>"""
        args = arg.split()
        if len(args) == 2 and args[0] == 'target':
            self.config.target = args[1]
            print(f"{Fore.GREEN}[+] Target set to: {self.config.target}{Style.RESET_ALL}")
            self._save_session()
        else:
            print(f"{Fore.RED}[-] Usage: set target <url>{Style.RESET_ALL}")

    def do_show(self, arg: str):
        """Show available modules or options: show modules"""
        if arg == 'modules':
            print(f"\n{Fore.CYAN}Available modules:{Style.RESET_ALL}")
            for name, desc in self.modules.items():
                print(f"  {Fore.YELLOW}{name.ljust(15)}{Style.RESET_ALL}{desc}")
            print()
        else:
            print(f"{Fore.RED}[-] Usage: show modules{Style.RESET_ALL}")

    def do_run(self, arg: str):
        """Run a module: run <module_name>"""
        if not self.config.target:
            print(f"{Fore.RED}[-] No target set. Use 'set target <url>' first.{Style.RESET_ALL}")
            return
        
        if arg == "dashboard":
            self._run_dashboard()
        elif arg in self.modules:
            try:
                print(f"{Fore.BLUE}[*] Running {arg} module...{Style.RESET_ALL}")
                
                # Dynamically load the module from the modules directory
                modules_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "modules")
                module_path = os.path.join(modules_dir, f"{arg}.py")
                
                spec = importlib.util.spec_from_file_location(f"modules.{arg}", module_path)
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                
                # Execute the module's run function
                if hasattr(module, 'run'):
                    module.run(self.config.target)
                    self.config.last_module = arg
                else:
                    print(f"{Fore.RED}[-] Module {arg} has no run function{Style.RESET_ALL}")
                    
            except Exception as e:
                print(f"{Fore.RED}[-] Error running module {arg}: {e}{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}[-] Module '{arg}' not found.{Style.RESET_ALL}")
            self.do_show('modules')

    def do_generate(self, arg: str):
        """Generate report: generate report [html|pdf|json]"""
        if arg.startswith('report'):
            try:
                # Dynamically load the report module
                modules_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "modules")
                module_path = os.path.join(modules_dir, "report.py")
                
                spec = importlib.util.spec_from_file_location("modules.report", module_path)
                report_module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(report_module)
                
                format = arg.split()[1] if len(arg.split()) > 1 else 'html'
                report_module.generate_report(self.config, format)
                print(f"{Fore.GREEN}[+] Report generated in {format.upper()} format{Style.RESET_ALL}")
            except Exception as e:
                print(f"{Fore.RED}[-] Error generating report: {e}{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}[-] Usage: generate report [html|pdf|json]{Style.RESET_ALL}")

    def do_history(self, arg: str):
        """Show command history: history [clear]"""
        if arg == 'clear':
            readline.clear_history()
            print(f"{Fore.GREEN}[+] Command history cleared{Style.RESET_ALL}")
        else:
            for i in range(1, readline.get_current_history_length() + 1):
                print(f"{i:4d} {readline.get_history_item(i)}")

    def do_credits(self, arg: str):
        """Show developer credits and project information"""
        credits = f"""
{Fore.CYAN}WebRaptor - Automated Web Pentesting Framework{Style.RESET_ALL}
{Fore.YELLOW}Version:{Style.RESET_ALL} 2.1
{Fore.YELLOW}Author:{Style.RESET_ALL} LakshmikanthanK (@letchu_pkt)
{Fore.YELLOW}GitHub:{Style.RESET_ALL} https://github.com/letchupkt
{Fore.YELLOW}Portfolio:{Style.RESET_ALL} https://letchupkt.vgrow.tech
"""
        print(credits)

    def do_exit(self, arg: str):
        """Exit the WebRaptor shell: exit"""
        print(f"{Fore.GREEN}[+] Saving session...{Style.RESET_ALL}")
        self._save_session()
        print(f"{Fore.GREEN}[+] Exiting WebRaptor. Goodbye!{Style.RESET_ALL}")
        return True

    def do_clear(self, arg: str):
        """Clear the terminal: clear"""
        os.system('clear' if os.name == 'posix' else 'cls')

    def do_tools(self, arg: str):
        """Tool management commands: tools <install|status|list>"""
        args = arg.split()
        if not args:
            print(f"{Fore.RED}[-] Usage: tools <install|status|list> [tool_name]{Style.RESET_ALL}")
            return
        
        command = args[0].lower()
        
        if command == 'install':
            if len(args) > 1:
                tool_name = args[1]
                print(f"{Fore.BLUE}[*] Installing {tool_name}...{Style.RESET_ALL}")
                success = self.tool_manager.install_tool(tool_name)
                if success:
                    print(f"{Fore.GREEN}[+] {tool_name} installed successfully{Style.RESET_ALL}")
                else:
                    print(f"{Fore.RED}[-] Failed to install {tool_name}{Style.RESET_ALL}")
            else:
                print(f"{Fore.BLUE}[*] Installing all required tools...{Style.RESET_ALL}")
                results = self.tool_manager.install_all_tools()
                installed = sum(1 for success in results.values() if success)
                total = len(results)
                print(f"{Fore.GREEN}[+] Installed {installed}/{total} tools{Style.RESET_ALL}")
        
        elif command == 'status':
            self.tool_manager.show_tool_status()
        
        elif command == 'list':
            print(f"\n{Fore.CYAN}Available Tools:{Style.RESET_ALL}")
            for name, config in self.tool_manager.tool_definitions.items():
                status = f"{Fore.GREEN}✓{Style.RESET_ALL}" if self.tool_manager.check_tool_installed(name) else f"{Fore.RED}✗{Style.RESET_ALL}"
                required = f"{Fore.YELLOW}(Required){Style.RESET_ALL}" if config.get('required', False) else f"{Fore.WHITE}(Optional){Style.RESET_ALL}"
                print(f"  {status} {config['name']:<20} - {config['description']} {required}")
        
        else:
            print(f"{Fore.RED}[-] Unknown command: {command}{Style.RESET_ALL}")
    
    def do_workflow(self, arg: str):
        """Run predefined workflows: workflow <name>"""
        if not arg:
            print(f"\n{Fore.CYAN}Available Workflows:{Style.RESET_ALL}")
            for name, workflow in self.workflows.items():
                print(f"  {Fore.YELLOW}{name:<15}{Style.RESET_ALL} - {workflow['description']}")
            return
        
        if arg not in self.workflows:
            print(f"{Fore.RED}[-] Unknown workflow: {arg}{Style.RESET_ALL}")
            return
        
        if not self.config.target:
            print(f"{Fore.RED}[-] No target set. Use 'set target <url>' first.{Style.RESET_ALL}")
            return
        
        workflow = self.workflows[arg]
        print(f"{Fore.BLUE}[*] Running workflow: {workflow['name']}{Style.RESET_ALL}")
        
        for i, step in enumerate(workflow['steps'], 1):
            print(f"\n{Fore.CYAN}[{i}/{len(workflow['steps'])}] Executing step...{Style.RESET_ALL}")
            
            if 'module' in step:
                # Run WebRaptor module
                module_name = step['module']
                if module_name in self.modules:
                    try:
                        modules_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "modules")
                        module_path = os.path.join(modules_dir, f"{module_name}.py")
                        
                        spec = importlib.util.spec_from_file_location(f"modules.{module_name}", module_path)
                        module = importlib.util.module_from_spec(spec)
                        spec.loader.exec_module(module)
                        
                        if hasattr(module, 'run'):
                            module.run(self.config.target)
                        else:
                            print(f"{Fore.RED}[-] Module {module_name} has no run function{Style.RESET_ALL}")
                    except Exception as e:
                        print(f"{Fore.RED}[-] Error running module {module_name}: {e}{Style.RESET_ALL}")
                else:
                    print(f"{Fore.RED}[-] Module {module_name} not found{Style.RESET_ALL}")
            
            elif 'tool' in step:
                # Run external tool
                tool_name = step['tool']
                args = step.get('args', [])
                
                # Replace {target} placeholder
                args = [arg.replace('{target}', self.config.target) for arg in args]
                
                if self.tool_manager.check_tool_installed(tool_name):
                    print(f"{Fore.CYAN}[*] Running {tool_name} with args: {' '.join(args)}{Style.RESET_ALL}")
                    success, stdout, stderr = self.tool_manager.run_tool(tool_name, args)
                    if success:
                        print(f"{Fore.GREEN}[+] {tool_name} completed successfully{Style.RESET_ALL}")
                        if stdout:
                            print(f"{Fore.BLUE}Output:{Style.RESET_ALL}\n{stdout}")
                    else:
                        print(f"{Fore.RED}[-] {tool_name} failed: {stderr}{Style.RESET_ALL}")
                else:
                    print(f"{Fore.RED}[-] Tool {tool_name} not installed{Style.RESET_ALL}")
        
        print(f"\n{Fore.GREEN}[+] Workflow '{workflow['name']}' completed{Style.RESET_ALL}")
    
    def do_auto(self, arg: str):
        """Run automated bug bounty pipeline: auto [workflow]"""
        workflow_name = arg if arg else 'bug_bounty'
        print(f"{Fore.BLUE}[*] Starting automated bug bounty pipeline...{Style.RESET_ALL}")
        
        # Check if target is set
        if not self.config.target:
            print(f"{Fore.RED}[-] No target set. Use 'set target <url>' first.{Style.RESET_ALL}")
            return
        
        # Check required tools
        required_tools = ['subfinder', 'httpx', 'nuclei', 'gobuster', 'ffuf']
        missing_tools = [tool for tool in required_tools if not self.tool_manager.check_tool_installed(tool)]
        
        if missing_tools:
            print(f"{Fore.YELLOW}[!] Missing required tools: {', '.join(missing_tools)}{Style.RESET_ALL}")
            install = input("Install missing tools? (y/n): ").strip().lower()
            if install == 'y':
                for tool in missing_tools:
                    self.tool_manager.install_tool(tool)
            else:
                print(f"{Fore.RED}[-] Cannot proceed without required tools{Style.RESET_ALL}")
                return
        
        # Run the workflow
        self.do_workflow(workflow_name)
    
    def do_exploit(self, arg: str):
        """Run exploitation framework: exploit [target]"""
        target = arg if arg else self.config.target
        if not target:
            print(f"{Fore.RED}[-] No target specified{Style.RESET_ALL}")
            return
        
        print(f"{Fore.BLUE}[*] Starting exploitation phase for {target}...{Style.RESET_ALL}")
        
        # Check for metasploit
        if self.tool_manager.check_tool_installed('metasploit'):
            print(f"{Fore.CYAN}[*] Metasploit available - launching exploit framework{Style.RESET_ALL}")
            # This would integrate with metasploit automation
            print(f"{Fore.YELLOW}[!] Metasploit integration coming soon{Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}[!] Metasploit not installed - using basic exploitation{Style.RESET_ALL}")
        
        # Run basic exploitation modules
        exploit_modules = ['xss', 'lfi', 'sqli']
        for module in exploit_modules:
            if module in self.modules:
                print(f"{Fore.CYAN}[*] Running {module} exploitation...{Style.RESET_ALL}")
                try:
                    modules_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "modules")
                    module_path = os.path.join(modules_dir, f"{module}.py")
                    
                    spec = importlib.util.spec_from_file_location(f"modules.{module}", module_path)
                    module_obj = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(module_obj)
                    
                    if hasattr(module_obj, 'run'):
                        module_obj.run(target)
                except Exception as e:
                    print(f"{Fore.RED}[-] Error running {module}: {e}{Style.RESET_ALL}")
    
    def do_recon(self, arg: str):
        """Run reconnaissance phase: recon [target]"""
        target = arg if arg else self.config.target
        if not target:
            print(f"{Fore.RED}[-] No target specified{Style.RESET_ALL}")
            return
        
        print(f"{Fore.BLUE}[*] Starting reconnaissance phase for {target}...{Style.RESET_ALL}")
        
        # Run reconnaissance workflow
        self.do_workflow('full_recon')
    
    def do_vuln(self, arg: str):
        """Run vulnerability scanning: vuln [target]"""
        target = arg if arg else self.config.target
        if not target:
            print(f"{Fore.RED}[-] No target specified{Style.RESET_ALL}")
            return
        
        print(f"{Fore.BLUE}[*] Starting vulnerability scanning for {target}...{Style.RESET_ALL}")
        
        # Check for nuclei
        if self.tool_manager.check_tool_installed('nuclei'):
            print(f"{Fore.CYAN}[*] Running Nuclei vulnerability scanner...{Style.RESET_ALL}")
            success, stdout, stderr = self.tool_manager.run_tool('nuclei', ['-u', target, '-t', 'vulnerabilities/'])
            if success:
                print(f"{Fore.GREEN}[+] Nuclei scan completed{Style.RESET_ALL}")
                if stdout:
                    print(f"{Fore.BLUE}Results:{Style.RESET_ALL}\n{stdout}")
            else:
                print(f"{Fore.RED}[-] Nuclei scan failed: {stderr}{Style.RESET_ALL}")
        
        # Run other vulnerability modules
        vuln_modules = ['xss', 'lfi', 'sqli']
        for module in vuln_modules:
            if module in self.modules:
                print(f"{Fore.CYAN}[*] Running {module} vulnerability scan...{Style.RESET_ALL}")
                try:
                    modules_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "modules")
                    module_path = os.path.join(modules_dir, f"{module}.py")
                    
                    spec = importlib.util.spec_from_file_location(f"modules.{module}", module_path)
                    module_obj = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(module_obj)
                    
                    if hasattr(module_obj, 'run'):
                        module_obj.run(target)
                except Exception as e:
                    print(f"{Fore.RED}[-] Error running {module}: {e}{Style.RESET_ALL}")
    
    def do_status(self, arg: str):
        """Show current status: status"""
        print(f"\n{Fore.BLUE}╔══════════════════════════════════════════════════════════════════════════╗")
        print(f"║                           WEBRAPTOR STATUS                              ║")
        print(f"╚══════════════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}")
        
        # Target status
        target_status = f"{Fore.GREEN}Set{Style.RESET_ALL}" if self.config.target else f"{Fore.RED}Not Set{Style.RESET_ALL}"
        print(f"\n{Fore.CYAN}🎯 Target:{Style.RESET_ALL} {self.config.target or 'None'} ({target_status})")
        
        # Tool status
        required_tools = ['nmap', 'nuclei', 'subfinder', 'httpx', 'gobuster', 'ffuf']
        installed_tools = sum(1 for tool in required_tools if self.tool_manager.check_tool_installed(tool))
        print(f"{Fore.CYAN}🔧 Tools:{Style.RESET_ALL} {installed_tools}/{len(required_tools)} required tools installed")
        
        # Module status
        print(f"{Fore.CYAN}📦 Modules:{Style.RESET_ALL} {len(self.modules)} modules loaded")
        
        # Workflow status
        print(f"{Fore.CYAN}🔄 Workflows:{Style.RESET_ALL} {len(self.workflows)} workflows available")
        
        # Active scans
        if self.active_scans:
            print(f"{Fore.CYAN}⚡ Active Scans:{Style.RESET_ALL} {len(self.active_scans)}")
            for scan_id, scan_info in self.active_scans.items():
                print(f"    {scan_id}: {scan_info.get('status', 'Unknown')}")
        else:
            print(f"{Fore.CYAN}⚡ Active Scans:{Style.RESET_ALL} None")
        
        # Recent results
        if self.config.results:
            total_findings = sum(len(findings) for findings in self.config.results.values())
            print(f"{Fore.CYAN}📊 Results:{Style.RESET_ALL} {total_findings} findings from {len(self.config.results)} modules")
        
        print(f"\n{Fore.BLUE}{'='*80}{Style.RESET_ALL}")

    def do_configure(self, args):
        """Configure WebRaptor settings, API keys, and tool configurations"""
        if not args:
            print(f"{Fore.CYAN}Configuration Options:{Style.RESET_ALL}")
            print("  api-keys     - Configure API keys for external services")
            print("  tools        - Configure tool settings")
            print("  profiles     - Manage scan profiles")
            print("  show         - Show current configuration")
            print("  export       - Export configuration")
            print("  import       - Import configuration")
            print("  validate     - Validate configuration")
            print("  reset        - Reset to defaults")
            return
        
        args = args.split()
        action = args[0]
        
        if action == "api-keys":
            self.config_manager.configure_api_keys()
        elif action == "tools":
            self.config_manager.configure_tools()
        elif action == "profiles":
            self.config_manager.list_scan_profiles()
        elif action == "show":
            section = args[1] if len(args) > 1 else None
            self.config_manager.show_config(section)
        elif action == "export":
            filepath = args[1] if len(args) > 1 else "webraptor_config.json"
            include_secrets = input("Include secrets? (y/n): ").strip().lower() == 'y'
            self.config_manager.export_config(filepath, include_secrets)
        elif action == "import":
            filepath = args[1] if len(args) > 1 else input("Enter filepath: ")
            self.config_manager.import_config(filepath)
        elif action == "validate":
            issues = self.config_manager.validate_config()
            if issues:
                print(f"\n{Fore.RED}Configuration Issues:{Style.RESET_ALL}")
                for issue in issues:
                    print(f"  • {issue}")
            else:
                print(f"\n{Fore.GREEN}[+] Configuration is valid{Style.RESET_ALL}")
        elif action == "reset":
            self.config_manager.reset_config()
        else:
            print(f"{Fore.RED}[-] Unknown configuration action: {action}{Style.RESET_ALL}")
    
    def _run_dashboard(self):
        """Run the interactive dashboard"""
        try:
            import subprocess
            subprocess.run([sys.executable, "dashboard.py"], check=True)
        except subprocess.CalledProcessError:
            print(f"{Fore.RED}[-] Error running dashboard{Style.RESET_ALL}")
        except FileNotFoundError:
            print(f"{Fore.RED}[-] Dashboard not found. Make sure dashboard.py exists{Style.RESET_ALL}")

    def do_config(self, args):
        """Alias for configure command"""
        self.do_configure(args)

    def postcmd(self, stop: bool, line: str) -> bool:
        """Update prompt with current target"""
        target_display = f"{Fore.RED}no-target{Style.RESET_ALL}" if not self.config.target else f"{Fore.CYAN}{self.config.target}{Style.RESET_ALL}"
        self.prompt = f'''{Fore.GREEN}╭──(letchu@webraptor)-[{target_display}]\n╰─${Style.RESET_ALL} '''
        return stop  