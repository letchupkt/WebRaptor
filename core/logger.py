#!/usr/bin/env python3
"""
WebRaptor Logging System
Centralized logging for all WebRaptor components
"""

import os
import sys
import logging
import logging.handlers
from pathlib import Path
from datetime import datetime
from typing import Optional
import json

class WebRaptorLogger:
    """Centralized logging system for WebRaptor"""
    
    def __init__(self, log_dir: str = "output/logs"):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        
        # Setup loggers
        self._setup_main_logger()
        self._setup_error_logger()
        self._setup_debug_logger()
        self._setup_scan_logger()
    
    def _setup_main_logger(self):
        """Setup main application logger"""
        self.main_logger = logging.getLogger('webraptor')
        self.main_logger.setLevel(logging.INFO)
        
        # Remove existing handlers
        self.main_logger.handlers.clear()
        
        # File handler
        main_log_file = self.log_dir / "webraptor.log"
        file_handler = logging.handlers.RotatingFileHandler(
            main_log_file, maxBytes=10*1024*1024, backupCount=5
        )
        file_handler.setLevel(logging.INFO)
        
        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        
        # Formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        file_handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)
        
        # Add handlers
        self.main_logger.addHandler(file_handler)
        self.main_logger.addHandler(console_handler)
    
    def _setup_error_logger(self):
        """Setup error logger"""
        self.error_logger = logging.getLogger('webraptor.errors')
        self.error_logger.setLevel(logging.ERROR)
        
        # Remove existing handlers
        self.error_logger.handlers.clear()
        
        # File handler
        error_log_file = self.log_dir / "errors.log"
        error_handler = logging.handlers.RotatingFileHandler(
            error_log_file, maxBytes=5*1024*1024, backupCount=3
        )
        error_handler.setLevel(logging.ERROR)
        
        # Formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        error_handler.setFormatter(formatter)
        
        # Add handler
        self.error_logger.addHandler(error_handler)
    
    def _setup_debug_logger(self):
        """Setup debug logger"""
        self.debug_logger = logging.getLogger('webraptor.debug')
        self.debug_logger.setLevel(logging.DEBUG)
        
        # Remove existing handlers
        self.debug_logger.handlers.clear()
        
        # File handler
        debug_log_file = self.log_dir / "debug.log"
        debug_handler = logging.handlers.RotatingFileHandler(
            debug_log_file, maxBytes=20*1024*1024, backupCount=2
        )
        debug_handler.setLevel(logging.DEBUG)
        
        # Formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s'
        )
        debug_handler.setFormatter(formatter)
        
        # Add handler
        self.debug_logger.addHandler(debug_handler)
    
    def _setup_scan_logger(self):
        """Setup scan-specific logger"""
        self.scan_logger = logging.getLogger('webraptor.scan')
        self.scan_logger.setLevel(logging.INFO)
        
        # Remove existing handlers
        self.scan_logger.handlers.clear()
        
        # File handler
        scan_log_file = self.log_dir / "scans.log"
        scan_handler = logging.handlers.RotatingFileHandler(
            scan_log_file, maxBytes=50*1024*1024, backupCount=3
        )
        scan_handler.setLevel(logging.INFO)
        
        # Formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s'
        )
        scan_handler.setFormatter(formatter)
        
        # Add handler
        self.scan_logger.addHandler(scan_handler)
    
    def info(self, message: str, module: str = None):
        """Log info message"""
        if module:
            message = f"[{module}] {message}"
        self.main_logger.info(message)
    
    def warning(self, message: str, module: str = None):
        """Log warning message"""
        if module:
            message = f"[{module}] {message}"
        self.main_logger.warning(message)
    
    def error(self, message: str, module: str = None, exception: Exception = None):
        """Log error message"""
        if module:
            message = f"[{module}] {message}"
        
        self.main_logger.error(message)
        self.error_logger.error(message)
        
        if exception:
            self.error_logger.exception(exception)
    
    def debug(self, message: str, module: str = None):
        """Log debug message"""
        if module:
            message = f"[{module}] {message}"
        self.debug_logger.debug(message)
    
    def scan_start(self, target: str, module: str):
        """Log scan start"""
        message = f"Starting {module} scan on {target}"
        self.scan_logger.info(f"START - {message}")
        self.info(message, module)
    
    def scan_end(self, target: str, module: str, status: str = "completed"):
        """Log scan end"""
        message = f"Finished {module} scan on {target} - Status: {status}"
        self.scan_logger.info(f"END - {message}")
        self.info(message, module)
    
    def scan_result(self, module: str, result: dict):
        """Log scan result"""
        result_summary = {
            'module': module,
            'timestamp': datetime.now().isoformat(),
            'findings_count': len(result.get('findings', [])),
            'status': result.get('status', 'unknown')
        }
        
        self.scan_logger.info(f"RESULT - {json.dumps(result_summary)}")
    
    def tool_install(self, tool: str, status: str):
        """Log tool installation"""
        message = f"Tool {tool} installation: {status}"
        self.info(message, "tool_manager")
    
    def tool_run(self, tool: str, target: str, status: str):
        """Log tool execution"""
        message = f"Tool {tool} on {target}: {status}"
        self.info(message, "tool_manager")
    
    def config_change(self, setting: str, value: str):
        """Log configuration change"""
        message = f"Configuration changed: {setting} = {value}"
        self.info(message, "config_manager")
    
    def workflow_start(self, workflow: str, target: str):
        """Log workflow start"""
        message = f"Starting workflow {workflow} on {target}"
        self.scan_logger.info(f"WORKFLOW_START - {message}")
        self.info(message, "workflow")
    
    def workflow_end(self, workflow: str, target: str, status: str):
        """Log workflow end"""
        message = f"Finished workflow {workflow} on {target} - Status: {status}"
        self.scan_logger.info(f"WORKFLOW_END - {message}")
        self.info(message, "workflow")
    
    def report_generated(self, report_type: str, filepath: str):
        """Log report generation"""
        message = f"Generated {report_type} report: {filepath}"
        self.info(message, "report")
    
    def get_log_stats(self) -> dict:
        """Get logging statistics"""
        stats = {
            'log_files': [],
            'total_size': 0
        }
        
        for log_file in self.log_dir.glob("*.log"):
            file_stats = {
                'name': log_file.name,
                'size': log_file.stat().st_size,
                'modified': datetime.fromtimestamp(log_file.stat().st_mtime).isoformat()
            }
            stats['log_files'].append(file_stats)
            stats['total_size'] += file_stats['size']
        
        return stats
    
    def cleanup_old_logs(self, days: int = 30):
        """Clean up old log files"""
        import time
        cutoff_time = time.time() - (days * 24 * 60 * 60)
        
        cleaned_files = []
        for log_file in self.log_dir.glob("*.log*"):
            if log_file.stat().st_mtime < cutoff_time:
                log_file.unlink()
                cleaned_files.append(log_file.name)
        
        if cleaned_files:
            self.info(f"Cleaned up old log files: {', '.join(cleaned_files)}", "logger")
        
        return cleaned_files

# Global logger instance
logger = WebRaptorLogger()

def get_logger() -> WebRaptorLogger:
    """Get the global logger instance"""
    return logger
