#!/usr/bin/env python3
"""
WebRaptor Interactive Dashboard
Real-time monitoring and visualization of scanning activities
"""

import os
import sys
import json
import time
import threading
from pathlib import Path
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
from colorama import Fore, Style, init
import curses
from collections import defaultdict, deque
import psutil

init()

# Module metadata
description = "Interactive real-time dashboard for monitoring WebRaptor scanning activities"
author = "LakshmikanthanK (@letchu_pkt)"
version = "2.1"

class DashboardMetrics:
    """Collect and store dashboard metrics"""
    
    def __init__(self):
        self.scan_stats = {
            'total_scans': 0,
            'active_scans': 0,
            'completed_scans': 0,
            'failed_scans': 0
        }
        
        self.findings_stats = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0
        }
        
        self.tool_stats = defaultdict(int)
        self.target_stats = defaultdict(int)
        self.timeline_data = deque(maxlen=100)
        
        # Performance metrics
        self.performance_stats = {
            'cpu_usage': 0.0,
            'memory_usage': 0.0,
            'network_io': {'sent': 0, 'received': 0},
            'disk_io': {'read': 0, 'write': 0}
        }
        
        # Real-time data
        self.recent_activities = deque(maxlen=50)
        self.active_targets = set()
        self.running_tools = set()
    
    def update_scan_stats(self, scan_type: str, status: str):
        """Update scan statistics"""
        self.scan_stats['total_scans'] += 1
        
        if status == 'active':
            self.scan_stats['active_scans'] += 1
        elif status == 'completed':
            self.scan_stats['completed_scans'] += 1
            self.scan_stats['active_scans'] = max(0, self.scan_stats['active_scans'] - 1)
        elif status == 'failed':
            self.scan_stats['failed_scans'] += 1
            self.scan_stats['active_scans'] = max(0, self.scan_stats['active_scans'] - 1)
        
        self.tool_stats[scan_type] += 1
    
    def update_findings(self, severity: str, count: int = 1):
        """Update findings statistics"""
        if severity in self.findings_stats:
            self.findings_stats[severity] += count
    
    def add_activity(self, activity: str, target: str = None, tool: str = None):
        """Add recent activity"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.recent_activities.append({
            'timestamp': timestamp,
            'activity': activity,
            'target': target,
            'tool': tool
        })
    
    def update_performance(self):
        """Update system performance metrics"""
        self.performance_stats['cpu_usage'] = psutil.cpu_percent()
        self.performance_stats['memory_usage'] = psutil.virtual_memory().percent
        
        # Network I/O
        net_io = psutil.net_io_counters()
        self.performance_stats['network_io'] = {
            'sent': net_io.bytes_sent,
            'received': net_io.bytes_recv
        }
        
        # Disk I/O
        disk_io = psutil.disk_io_counters()
        if disk_io:
            self.performance_stats['disk_io'] = {
                'read': disk_io.read_bytes,
                'write': disk_io.write_bytes
            }
    
    def get_summary(self) -> Dict:
        """Get dashboard summary"""
        return {
            'scan_stats': self.scan_stats,
            'findings_stats': self.findings_stats,
            'tool_stats': dict(self.tool_stats),
            'performance': self.performance_stats,
            'recent_activities': list(self.recent_activities),
            'active_targets': list(self.active_targets),
            'running_tools': list(self.running_tools)
        }

class WebRaptorDashboard:
    """Interactive dashboard for WebRaptor"""
    
    def __init__(self):
        self.metrics = DashboardMetrics()
        self.running = False
        self.refresh_rate = 1.0  # seconds
        self.config_file = Path("config/webraptor_config.json")
        self.results_dir = Path("output/reports")
        
        # Load configuration
        self.config = self._load_config()
        
        # Dashboard layout
        self.layout = {
            'header_height': 3,
            'stats_height': 8,
            'activities_height': 10,
            'performance_height': 6,
            'footer_height': 2
        }
    
    def _load_config(self) -> Dict:
        """Load configuration from file"""
        if self.config_file.exists():
            try:
                with open(self.config_file, 'r') as f:
                    return json.load(f)
            except Exception:
                pass
        return {}
    
    def show_banner(self):
        """Display dashboard banner"""
        banner = f"""
{Fore.BLUE}
╔══════════════════════════════════════════════════════════════════════════╗
║                {Fore.YELLOW}WebRaptor Dashboard v{version}{Fore.BLUE}              ║
║                    Real-time Monitoring & Visualization                  ║
║                        Author: LakshmikanthanK (@letchu_pkt)             ║
║                                                                          ║
╚══════════════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""
        print(banner)
    
    def start_monitoring(self):
       
        self.show_banner()
        
        try:
            
            stdscr = curses.initscr()
            curses.noecho()
            curses.cbreak()
            stdscr.keypad(True)
            curses.curs_set(0)
            
            
            self.running = True
            self._monitoring_loop(stdscr)
            
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}[!] Dashboard stopped by user{Style.RESET_ALL}")
        except Exception as e:
            print(f"\n{Fore.RED}[-] Dashboard error: {e}{Style.RESET_ALL}")
        finally:
            
            try:
                curses.nocbreak()
                stdscr.keypad(False)
                curses.echo()
                curses.endwin()
            except:
                pass
    
    def _monitoring_loop(self, stdscr):
        
        while self.running:
            try:
               
                self._update_metrics()
                
                
                stdscr.clear()
                
               
                self._draw_header(stdscr)
                self._draw_stats(stdscr)
                self._draw_activities(stdscr)
                self._draw_performance(stdscr)
                self._draw_footer(stdscr)
                
                # Refresh screen
                stdscr.refresh()
                
                # Handle input
                stdscr.timeout(int(self.refresh_rate * 1000))
                key = stdscr.getch()
                
                if key == ord('q') or key == ord('Q'):
                    self.running = False
                elif key == ord('r') or key == ord('R'):
                    self._refresh_data()
                elif key == ord('h') or key == ord('H'):
                    self._show_help(stdscr)
                
                time.sleep(self.refresh_rate)
                
            except curses.error:
                # Handle curses errors gracefully
                pass
    
    def _draw_header(self, stdscr):
        """Draw dashboard header"""
        height, width = stdscr.getmaxyx()
        
        # Title
        title = "WebRaptor Interactive Dashboard"
        stdscr.addstr(0, (width - len(title)) // 2, title, curses.A_BOLD)
        
        # Status
        status = "RUNNING" if self.running else "STOPPED"
        status_color = curses.color_pair(2) if self.running else curses.color_pair(1)
        stdscr.addstr(1, (width - len(status)) // 2, status, status_color)
        
        # Timestamp
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        stdscr.addstr(2, (width - len(timestamp)) // 2, timestamp)
    
    def _draw_stats(self, stdscr):
        """Draw statistics section"""
        height, width = stdscr.getmaxyx()
        start_y = self.layout['header_height']
        
        # Scan Statistics
        stdscr.addstr(start_y, 2, "SCAN STATISTICS", curses.A_BOLD)
        
        stats = self.metrics.scan_stats
        stdscr.addstr(start_y + 1, 4, f"Total Scans: {stats['total_scans']}")
        stdscr.addstr(start_y + 2, 4, f"Active Scans: {stats['active_scans']}")
        stdscr.addstr(start_y + 3, 4, f"Completed: {stats['completed_scans']}")
        stdscr.addstr(start_y + 4, 4, f"Failed: {stats['failed_scans']}")
        
        # Findings Statistics
        findings_x = width // 2
        stdscr.addstr(start_y, findings_x, "FINDINGS", curses.A_BOLD)
        
        findings = self.metrics.findings_stats
        stdscr.addstr(start_y + 1, findings_x + 2, f"Critical: {findings['critical']}")
        stdscr.addstr(start_y + 2, findings_x + 2, f"High: {findings['high']}")
        stdscr.addstr(start_y + 3, findings_x + 2, f"Medium: {findings['medium']}")
        stdscr.addstr(start_y + 4, findings_x + 2, f"Low: {findings['low']}")
        stdscr.addstr(start_y + 5, findings_x + 2, f"Info: {findings['info']}")
    
    def _draw_activities(self, stdscr):
        """Draw recent activities section"""
        height, width = stdscr.getmaxyx()
        start_y = self.layout['header_height'] + self.layout['stats_height']
        
        stdscr.addstr(start_y, 2, "RECENT ACTIVITIES", curses.A_BOLD)
        
        activities = list(self.metrics.recent_activities)[-8:]  # Show last 8 activities
        for i, activity in enumerate(activities):
            if start_y + 1 + i < height - self.layout['footer_height']:
                activity_text = f"{activity['timestamp']} - {activity['activity']}"
                if activity['target']:
                    activity_text += f" ({activity['target']})"
                stdscr.addstr(start_y + 1 + i, 4, activity_text[:width-8])
    
    def _draw_performance(self, stdscr):
        """Draw performance metrics"""
        height, width = stdscr.getmaxyx()
        start_y = height - self.layout['footer_height'] - self.layout['performance_height']
        
        stdscr.addstr(start_y, 2, "SYSTEM PERFORMANCE", curses.A_BOLD)
        
        perf = self.metrics.performance_stats
        stdscr.addstr(start_y + 1, 4, f"CPU Usage: {perf['cpu_usage']:.1f}%")
        stdscr.addstr(start_y + 2, 4, f"Memory Usage: {perf['memory_usage']:.1f}%")
        
        # Network I/O
        net_io = perf['network_io']
        stdscr.addstr(start_y + 3, 4, f"Network: ↑{self._format_bytes(net_io['sent'])} ↓{self._format_bytes(net_io['received'])}")
        
        # Disk I/O
        disk_io = perf['disk_io']
        stdscr.addstr(start_y + 4, 4, f"Disk: R{self._format_bytes(disk_io['read'])} W{self._format_bytes(disk_io['write'])}")
    
    def _draw_footer(self, stdscr):
        """Draw dashboard footer"""
        height, width = stdscr.getmaxyx()
        start_y = height - self.layout['footer_height']
        
        # Controls
        controls = "Controls: Q-Quit, R-Refresh, H-Help"
        stdscr.addstr(start_y, (width - len(controls)) // 2, controls)
        
        # Refresh rate
        refresh_text = f"Refresh Rate: {self.refresh_rate}s"
        stdscr.addstr(start_y + 1, (width - len(refresh_text)) // 2, refresh_text)
    
    def _format_bytes(self, bytes_value: int) -> str:
        """Format bytes to human readable format"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes_value < 1024.0:
                return f"{bytes_value:.1f}{unit}"
            bytes_value /= 1024.0
        return f"{bytes_value:.1f}PB"
    
    def _update_metrics(self):
        """Update dashboard metrics"""
        # Update performance metrics
        self.metrics.update_performance()
        
        # Load recent scan results
        self._load_recent_results()
        
        # Simulate some activity for demo
        if not self.metrics.recent_activities:
            self.metrics.add_activity("Dashboard started", "system", "dashboard")
    
    def _load_recent_results(self):
        """Load recent scan results from reports directory"""
        if not self.results_dir.exists():
            return
        
        # Find recent report files
        report_files = list(self.results_dir.glob("*.json"))
        report_files.sort(key=lambda x: x.stat().st_mtime, reverse=True)
        
        # Process recent reports
        for report_file in report_files[:5]:  # Process last 5 reports
            try:
                with open(report_file, 'r') as f:
                    report_data = json.load(f)
                
                # Update findings stats
                if 'findings' in report_data:
                    for finding in report_data['findings']:
                        severity = finding.get('severity', 'info').lower()
                        self.metrics.update_findings(severity)
                
                # Add activity
                target = report_data.get('target', 'unknown')
                tool = report_data.get('tool', 'unknown')
                self.metrics.add_activity("Scan completed", target, tool)
                
            except Exception:
                continue
    
    def _refresh_data(self):
        """Manually refresh data"""
        self.metrics.add_activity("Data refreshed", "system", "dashboard")
    
    def _show_help(self, stdscr):
        """Show help information"""
        height, width = stdscr.getmaxyx()
        
        # Clear screen
        stdscr.clear()
        
        help_text = [
            "WebRaptor Dashboard Help",
            "",
            "Controls:",
            "  Q - Quit dashboard",
            "  R - Refresh data",
            "  H - Show this help",
            "",
            "Dashboard Sections:",
            "  - Scan Statistics: Overview of scanning activities",
            "  - Findings: Vulnerability findings by severity",
            "  - Recent Activities: Latest scan activities",
            "  - System Performance: CPU, memory, and I/O usage",
            "",
            "Press any key to return to dashboard..."
        ]
        
        for i, line in enumerate(help_text):
            if i < height - 1:
                stdscr.addstr(i, (width - len(line)) // 2, line)
        
        stdscr.refresh()
        stdscr.getch()
    
    def export_metrics(self, filepath: str):
        """Export dashboard metrics to file"""
        try:
            metrics_data = {
                'timestamp': datetime.now().isoformat(),
                'metrics': self.metrics.get_summary(),
                'config': self.config
            }
            
            with open(filepath, 'w') as f:
                json.dump(metrics_data, f, indent=2)
            
            print(f"{Fore.GREEN}[+] Metrics exported to {filepath}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[-] Error exporting metrics: {e}{Style.RESET_ALL}")

def main():
    """Main function for dashboard"""
    dashboard = WebRaptorDashboard()
    
    if len(sys.argv) > 1:
        command = sys.argv[1]
        
        if command == "export":
            filepath = sys.argv[2] if len(sys.argv) > 2 else "dashboard_metrics.json"
            dashboard.export_metrics(filepath)
        elif command == "help":
            dashboard.show_banner()
            print(f"\n{Fore.CYAN}Usage:{Style.RESET_ALL}")
            print("  python dashboard.py              - Start interactive dashboard")
            print("  python dashboard.py export [file] - Export metrics to file")
            print("  python dashboard.py help         - Show this help")
        else:
            print(f"{Fore.RED}[-] Unknown command: {command}{Style.RESET_ALL}")
    else:
        dashboard.start_monitoring()

if __name__ == "__main__":
    main()
