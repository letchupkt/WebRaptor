import datetime
import json
from typing import Dict, List, Optional, Any
import os

class Config:
    def __init__(self):
        # Scan Configuration
        self.target = None
        self.target_ip = None
        self.scan_date = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.scan_start_time = datetime.datetime.now()
        self.scan_end_time = None
        self.scan_duration = None
        
        # Results Storage
        self.results = {}  # {module_name: [findings]}
        self.raw_data = {}  # {module_name: raw_output}
        self.metrics = {}   # {module_name: {metrics}}
        self.modules_used = []
        
        # Output Directory Structure
        self.output_dir = "output"
        self.results_dir = "output/reports"
        self.scans_dir = "output/scans"
        self.logs_dir = "output/logs"
        self.config_dir = "output/config"
        self.wordlists_dir = "output/wordlists"
        self.tools_dir = "output/tools"
        self.temp_dir = "output/temp"
        
        # Create output directories
        self._create_output_directories()
        
        # Report Configuration
        self.report_title = "WebRaptor Security Report"
        self.report_format = "html"
        self.report_level = "detailed"  # quick/detailed/comprehensive
        
        # Scan Options
        self.options = {
            'timeout': 30,
            'threads': 10,
            'depth': 2,
            'verbosity': 2  # 0-3
        }
        
        # Module-specific configurations
        self.module_configs = {
            'subenum': {'wordlist': 'default', 'recursive': True},
            'dirbuster': {'wordlist': 'common.txt', 'extensions': ['php','html']},
            'sqli': {'payloads': 'default', 'risk_level': 2}
        }
        
        # State Tracking
        self.current_module = None
        self.scan_status = "ready"  # ready/running/completed/failed
        self.error_log = []
        
        # User Metadata
        self.user = {
            'name': os.getenv('USER', 'anonymous'),
            'organization': None,
            'contact': None
        }

    def _create_output_directories(self) -> None:
        """
        Create the output directory structure
        """
        import os
        from pathlib import Path
        
        directories = [
            self.output_dir,
            self.results_dir,
            self.scans_dir,
            self.logs_dir,
            self.config_dir,
            self.wordlists_dir,
            self.tools_dir,
            self.temp_dir,
            f"{self.scans_dir}/subdomain",
            f"{self.scans_dir}/waybackurls",
            f"{self.scans_dir}/nuclei",
            f"{self.scans_dir}/nikto",
            f"{self.scans_dir}/sqlmap",
            f"{self.scans_dir}/advanced_tools",
            f"{self.scans_dir}/portscan",
            f"{self.scans_dir}/tech_detect",
            f"{self.scans_dir}/xss",
            f"{self.scans_dir}/screenshot",
            f"{self.results_dir}/html",
            f"{self.results_dir}/json",
            f"{self.results_dir}/pdf",
            f"{self.temp_dir}/scans",
            f"{self.temp_dir}/downloads"
        ]
        
        for directory in directories:
            Path(directory).mkdir(parents=True, exist_ok=True)

    def add_result(self, module: str, result: Any, raw_data: Optional[str] = None, 
                  metrics: Optional[Dict] = None) -> None:
        """
        Add a scan result with optional raw data and metrics
        """
        if module not in self.results:
            self.results[module] = []
            self.raw_data[module] = []
            self.metrics[module] = {}
            self.modules_used.append(module)
            
        self.results[module].append(result)
        
        if raw_data:
            self.raw_data[module].append(raw_data)
            
        if metrics:
            self.metrics[module].update(metrics)

    def set_module_config(self, module: str, config: Dict) -> None:
        """
        Set configuration for a specific module
        """
        self.module_configs[module] = config

    def get_module_config(self, module: str) -> Dict:
        """
        Get configuration for a specific module
        """
        return self.module_configs.get(module, {})

    def log_error(self, error: str, module: Optional[str] = None) -> None:
        """
        Log an error during scanning
        """
        error_entry = {
            'timestamp': datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'module': module or self.current_module,
            'error': error
        }
        self.error_log.append(error_entry)

    def start_scan(self) -> None:
        """
        Mark scan as started
        """
        self.scan_start_time = datetime.datetime.now()
        self.scan_status = "running"
        self.scan_date = self.scan_start_time.strftime("%Y-%m-%d %H:%M:%S")

    def end_scan(self, status: str = "completed") -> None:
        """
        Mark scan as completed/failed
        """
        self.scan_end_time = datetime.datetime.now()
        self.scan_status = status
        self.scan_duration = str(self.scan_end_time - self.scan_start_time)

    def get_stats(self) -> Dict:
        """
        Return scan statistics
        """
        return {
            'target': self.target,
            'modules_run': len(self.modules_used),
            'findings_count': sum(len(v) for v in self.results.values()),
            'start_time': self.scan_start_time.strftime("%Y-%m-%d %H:%M:%S"),
            'duration': self.scan_duration,
            'status': self.scan_status,
            'error_count': len(self.error_log)
        }

    def save_session(self, filepath: str = "webraptor.session") -> bool:
        """
        Save current scan session to file
        """
        try:
            session_data = {
                'config': {
                    'target': self.target,
                    'options': self.options,
                    'module_configs': self.module_configs,
                    'user': self.user
                },
                'state': {
                    'scan_status': self.scan_status,
                    'current_module': self.current_module,
                    'modules_used': self.modules_used
                },
                'results': self.results,
                'metadata': {
                    'version': '2.1',
                    'timestamp': datetime.datetime.now().isoformat()
                }
            }
            
            with open(filepath, 'w') as f:
                json.dump(session_data, f, indent=2)
            return True
        except Exception as e:
            self.log_error(f"Failed to save session: {str(e)}")
            return False

    def load_session(self, filepath: str = "webraptor.session") -> bool:
        """
        Load scan session from file
        """
        try:
            with open(filepath, 'r') as f:
                session_data = json.load(f)
                
            # Restore configuration
            config = session_data.get('config', {})
            self.target = config.get('target')
            self.options = config.get('options', self.options)
            self.module_configs = config.get('module_configs', self.module_configs)
            self.user = config.get('user', self.user)
            
            # Restore state
            state = session_data.get('state', {})
            self.scan_status = state.get('scan_status', 'ready')
            self.current_module = state.get('current_module')
            self.modules_used = state.get('modules_used', [])
            
            # Restore results
            self.results = session_data.get('results', {})
            
            return True
        except Exception as e:
            self.log_error(f"Failed to load session: {str(e)}")
            return False

    def generate_report_metadata(self) -> Dict:
        """
        Generate metadata for reports
        """
        return {
            'title': self.report_title,
            'target': self.target,
            'date': self.scan_date,
            'duration': self.scan_duration,
            'modules': self.modules_used,
            'findings_count': sum(len(v) for v in self.results.values()),
            'scan_status': self.scan_status,
            'generated_by': f"{self.user.get('name', 'anonymous')}",
            'report_version': '2.1'
        }

    def __str__(self) -> str:
        """
        String representation of the current configuration
        """
        stats = self.get_stats()
        return (
            f"WebRaptor Scan Configuration:\n"
            f"Target: {stats['target']}\n"
            f"Status: {stats['status']}\n"
            f"Modules: {len(stats['modules_run'])} executed\n"
            f"Findings: {stats['findings_count']} total\n"
            f"Duration: {stats['duration']}\n"
            f"Errors: {stats['error_count']}"
        )