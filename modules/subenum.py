import datetime
import json
import os
from typing import Dict, List, Optional, Any, Union

class Config:
    def __init__(self):
        # Scan Configuration
        self.target: Optional[str] = None
        self.target_ip: Optional[str] = None
        self.scan_date: str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.scan_start_time: datetime.datetime = datetime.datetime.now()
        self.scan_end_time: Optional[datetime.datetime] = None
        self.scan_duration: Optional[str] = None
        
        # Results Storage
        self.results: Dict[str, List[Any]] = {}  # {module_name: [findings]}
        self.raw_data: Dict[str, List[str]] = {}  # {module_name: raw_output}
        self.metrics: Dict[str, Dict[str, Any]] = {}   # {module_name: {metrics}}
        self.modules_used: List[str] = []
        
        # Report Configuration
        self.report_title: str = "WebRaptor Security Report"
        self.report_format: str = "html"  # html/json/markdown
        self.report_level: str = "detailed"  # quick/detailed/comprehensive
        
        # Scan Options
        self.options: Dict[str, Union[int, bool, str]] = {
            'timeout': 30,
            'threads': 10,
            'depth': 2,
            'verbosity': 2,  # 0-3
            'save_intermediate': True
        }
        
        # Module-specific configurations
        self.module_configs: Dict[str, Dict[str, Any]] = {
            'subenum': {
                'wordlist': 'default', 
                'recursive': True,
                'bruteforce': False
            },
            'dirbuster': {
                'wordlist': 'common.txt', 
                'extensions': ['php','html'],
                'status_codes': [200, 301, 302]
            },
            'sqli': {
                'payloads': 'default', 
                'risk_level': 2,
                'techniques': ['boolean', 'error', 'time']
            }
        }
        
        # State Tracking
        self.current_module: Optional[str] = None
        self.scan_status: str = "ready"  # ready/running/completed/failed
        self.error_log: List[Dict[str, str]] = []
        
        # User Metadata
        self.user: Dict[str, Optional[str]] = {
            'name': os.getenv('USER', 'anonymous'),
            'organization': None,
            'contact': None,
            'client': None
        }

    def add_result(self, module: str, result: Any, raw_data: Optional[str] = None, 
                  metrics: Optional[Dict[str, Any]] = None) -> None:
        """
        Add a scan result with optional raw data and metrics
        
        Args:
            module: Name of the module generating the result
            result: The finding or result to store
            raw_data: Raw output from the module (optional)
            metrics: Performance metrics or statistics (optional)
        """
        if module not in self.results:
            self.results[module] = []
            self.raw_data[module] = []
            self.metrics[module] = {}
            
        self.results[module].append(result)
        self.modules_used.append(module)
        
        if raw_data:
            self.raw_data[module].append(raw_data)
            
        if metrics:
            self.metrics[module].update(metrics)

    def set_module_config(self, module: str, config: Dict[str, Any]) -> None:
        """
        Set configuration for a specific module
        
        Args:
            module: Name of the module
            config: Dictionary of configuration options
        """
        if module not in self.module_configs:
            self.module_configs[module] = {}
        self.module_configs[module].update(config)

    def get_module_config(self, module: str) -> Dict[str, Any]:
        """
        Get configuration for a specific module
        
        Args:
            module: Name of the module
            
        Returns:
            Dictionary of configuration options for the module
        """
        return self.module_configs.get(module, {}).copy()

    def log_error(self, error: str, module: Optional[str] = None) -> None:
        """
        Log an error during scanning
        
        Args:
            error: Error message to log
            module: Name of the module where error occurred (optional)
        """
        error_entry = {
            'timestamp': datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'module': module or self.current_module,
            'error': error
        }
        self.error_log.append(error_entry)

    def start_scan(self) -> None:
        """Mark scan as started and record start time"""
        self.scan_start_time = datetime.datetime.now()
        self.scan_status = "running"
        self.scan_date = self.scan_start_time.strftime("%Y-%m-%d %H:%M:%S")
        self.error_log = []  # Clear previous errors on new scan

    def end_scan(self, status: str = "completed") -> None:
        """
        Mark scan as completed/failed and calculate duration
        
        Args:
            status: Final status of the scan ("completed" or "failed")
        """
        self.scan_end_time = datetime.datetime.now()
        self.scan_status = status
        duration = self.scan_end_time - self.scan_start_time
        self.scan_duration = str(duration)

    def get_stats(self) -> Dict[str, Any]:
        """
        Get scan statistics
        
        Returns:
            Dictionary containing scan statistics
        """
        return {
            'target': self.target,
            'modules_run': len(set(self.modules_used)),  # Unique modules
            'findings_count': sum(len(v) for v in self.results.values()),
            'start_time': self.scan_start_time.strftime("%Y-%m-%d %H:%M:%S"),
            'end_time': self.scan_end_time.strftime("%Y-%m-%d %H:%M:%S") if self.scan_end_time else None,
            'duration': self.scan_duration,
            'status': self.scan_status,
            'error_count': len(self.error_log),
            'report_format': self.report_format
        }

    def save_session(self, filepath: str = "webraptor.session") -> bool:
        """
        Save current scan session to file
        
        Args:
            filepath: Path to save the session file
            
        Returns:
            True if successful, False otherwise
        """
        try:
            session_data = {
                'config': {
                    'target': self.target,
                    'target_ip': self.target_ip,
                    'options': self.options,
                    'module_configs': self.module_configs,
                    'user': self.user,
                    'report_title': self.report_title,
                    'report_format': self.report_format,
                    'report_level': self.report_level
                },
                'state': {
                    'scan_status': self.scan_status,
                    'current_module': self.current_module,
                    'modules_used': list(set(self.modules_used)),  # Deduplicate
                    'scan_date': self.scan_date,
                    'scan_start_time': self.scan_start_time.isoformat(),
                    'scan_end_time': self.scan_end_time.isoformat() if self.scan_end_time else None,
                    'scan_duration': self.scan_duration
                },
                'results': {
                    'summary': {k: len(v) for k, v in self.results.items()},
                    'error_count': len(self.error_log)
                },
                'metadata': {
                    'version': '2.2',
                    'timestamp': datetime.datetime.now().isoformat(),
                    'system': os.name
                }
            }
            
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(session_data, f, indent=2, ensure_ascii=False)
            return True
        except (IOError, TypeError, ValueError) as e:
            self.log_error(f"Failed to save session: {str(e)}")
            return False

    def load_session(self, filepath: str = "webraptor.session") -> bool:
        """
        Load scan session from file
        
        Args:
            filepath: Path to the session file
            
        Returns:
            True if successful, False otherwise
        """
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                session_data = json.load(f)
                
            # Restore configuration
            config = session_data.get('config', {})
            self.target = config.get('target')
            self.target_ip = config.get('target_ip')
            self.options = {**self.options, **config.get('options', {})}
            self.module_configs = {**self.module_configs, **config.get('module_configs', {})}
            self.user = {**self.user, **config.get('user', {})}
            self.report_title = config.get('report_title', self.report_title)
            self.report_format = config.get('report_format', self.report_format)
            self.report_level = config.get('report_level', self.report_level)
            
            # Restore state
            state = session_data.get('state', {})
            self.scan_status = state.get('scan_status', 'ready')
            self.current_module = state.get('current_module')
            self.modules_used = state.get('modules_used', [])
            self.scan_date = state.get('scan_date', self.scan_date)
            
            # Convert string timestamps back to datetime objects
            if state.get('scan_start_time'):
                self.scan_start_time = datetime.datetime.fromisoformat(state['scan_start_time'])
            if state.get('scan_end_time'):
                self.scan_end_time = datetime.datetime.fromisoformat(state['scan_end_time'])
            
            self.scan_duration = state.get('scan_duration')
            
            return True
        except (IOError, json.JSONDecodeError, ValueError) as e:
            self.log_error(f"Failed to load session: {str(e)}")
            return False

    def generate_report_metadata(self) -> Dict[str, Any]:
        """
        Generate metadata for reports
        
        Returns:
            Dictionary containing report metadata
        """
        return {
            'title': self.report_title,
            'target': self.target,
            'target_ip': self.target_ip,
            'date': self.scan_date,
            'duration': self.scan_duration,
            'modules': list(set(self.modules_used)),  # Unique modules
            'findings_count': sum(len(v) for v in self.results.values()),
            'scan_status': self.scan_status,
            'user': self.user.get('name', 'anonymous'),
            'organization': self.user.get('organization'),
            'report_format': self.report_format,
            'report_level': self.report_level,
            'version': '2.2',
            'errors': len(self.error_log)
        }

    def __str__(self) -> str:
        """String representation of the current configuration"""
        stats = self.get_stats()
        return f"""WebRaptor Scan Configuration:
Target: {stats['target']}
Status: {stats['status']}
Modules: {stats['modules_run']} executed
Findings: {stats['findings_count']} total
Started: {stats['start_time']}
Duration: {stats['duration']}
Errors: {stats['error_count']}
Report Format: {stats['report_format']}"""

    def reset(self) -> None:
        """Reset the configuration to default values"""
        self.__init__()
