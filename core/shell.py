import cmd
import os
import readline
import atexit
import importlib.util
from colorama import Fore, Style, init
from core.config import Config
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
        self.session_file = ".webraptor_history"
        self.module_aliases = self._create_aliases()
        self._setup_readline()
        self._load_session()
        self.modules = self._discover_modules()
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
            'target': 'set target'
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
            'set', 'show', 'run', 'generate', 
            'credits', 'exit', 'help', 'clear'
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
        
        if arg in self.modules:
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

    def postcmd(self, stop: bool, line: str) -> bool:
        """Update prompt with current target"""
        target_display = f"{Fore.RED}no-target{Style.RESET_ALL}" if not self.config.target else f"{Fore.CYAN}{self.config.target}{Style.RESET_ALL}"
        self.prompt = f'''{Fore.GREEN}╭──(letchu@webraptor)-[{target_display}]\n╰─${Style.RESET_ALL} '''
        return stop  