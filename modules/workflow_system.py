#!/usr/bin/env python3
"""
WebRaptor Automated Workflow System
Complete bug bounty automation pipeline with intelligent decision making
"""

import os
import sys
import json
import time
import asyncio
import threading
from pathlib import Path
from typing import List, Dict, Optional, Any
from colorama import Fore, Style, init
from core.config import Config
from core.tool_manager import ToolManager

init()

# Module metadata
description = "Automated bug bounty workflow system with intelligent pipeline orchestration"
author = "LakshmikanthanK (@letchu_pkt)"
version = "2.1"

class AutomatedWorkflowSystem:
    """Advanced workflow automation system for bug bounty hunting"""
    
    def __init__(self, config: Config = None):
        self.config = config or Config()
        self.tool_manager = ToolManager()
        self.workflows_dir = Path("workflows")
        self.results_dir = Path("reports/workflows")
        
        # Create directories
        self.workflows_dir.mkdir(exist_ok=True)
        self.results_dir.mkdir(parents=True, exist_ok=True)
        
        # Workflow configuration
        self.workflow_config = {
            'parallel_execution': True,
            'max_concurrent_tasks': 5,
            'timeout_per_task': 300,
            'retry_failed_tasks': True,
            'max_retries': 2,
            'intelligent_routing': True,
            'adaptive_timeouts': True
        }
        
        # Predefined workflows
        self.predefined_workflows = {
            'bug_bounty_full': {
                'name': 'Complete Bug Bounty Pipeline',
                'description': 'End-to-end bug bounty automation',
                'phases': [
                    'reconnaissance',
                    'subdomain_enumeration',
                    'port_scanning',
                    'vulnerability_scanning',
                    'web_application_testing',
                    'exploitation',
                    'reporting'
                ],
                'estimated_duration': '2-4 hours',
                'complexity': 'high'
            },
            'quick_assessment': {
                'name': 'Quick Security Assessment',
                'description': 'Fast vulnerability assessment',
                'phases': [
                    'basic_reconnaissance',
                    'port_scanning',
                    'vulnerability_scanning',
                    'reporting'
                ],
                'estimated_duration': '30-60 minutes',
                'complexity': 'low'
            },
            'web_app_focus': {
                'name': 'Web Application Focus',
                'description': 'Comprehensive web application testing',
                'phases': [
                    'subdomain_enumeration',
                    'web_discovery',
                    'vulnerability_scanning',
                    'manual_testing_guidance',
                    'reporting'
                ],
                'estimated_duration': '1-2 hours',
                'complexity': 'medium'
            },
            'network_focus': {
                'name': 'Network Infrastructure Focus',
                'description': 'Network infrastructure assessment',
                'phases': [
                    'network_discovery',
                    'port_scanning',
                    'service_enumeration',
                    'vulnerability_scanning',
                    'exploitation',
                    'reporting'
                ],
                'estimated_duration': '1-3 hours',
                'complexity': 'medium'
            },
            'continuous_monitoring': {
                'name': 'Continuous Monitoring',
                'description': 'Ongoing security monitoring',
                'phases': [
                    'asset_discovery',
                    'change_detection',
                    'vulnerability_monitoring',
                    'alerting'
                ],
                'estimated_duration': 'ongoing',
                'complexity': 'low'
            }
        }
        
        # Phase definitions
        self.phase_definitions = {
            'reconnaissance': {
                'name': 'Intelligence Gathering',
                'tools': ['amass', 'subfinder', 'theharvester'],
                'modules': ['advanced_recon'],
                'parallel': True,
                'timeout': 600
            },
            'subdomain_enumeration': {
                'name': 'Subdomain Discovery',
                'tools': ['subfinder', 'amass', 'httpx'],
                'modules': ['subenum'],
                'parallel': True,
                'timeout': 900
            },
            'port_scanning': {
                'name': 'Port Scanning',
                'tools': ['nmap', 'masscan'],
                'modules': ['portscan'],
                'parallel': False,
                'timeout': 1200
            },
            'vulnerability_scanning': {
                'name': 'Vulnerability Detection',
                'tools': ['nuclei', 'nikto'],
                'modules': ['nuclei_scanner', 'nikto_scanner'],
                'parallel': True,
                'timeout': 1800
            },
            'web_application_testing': {
                'name': 'Web Application Testing',
                'tools': ['gobuster', 'ffuf', 'sqlmap'],
                'modules': ['dirbuster', 'xss', 'lfi', 'sqli'],
                'parallel': True,
                'timeout': 2400
            },
            'exploitation': {
                'name': 'Exploitation',
                'tools': ['metasploit'],
                'modules': ['exploitation_framework'],
                'parallel': False,
                'timeout': 3600
            },
            'reporting': {
                'name': 'Report Generation',
                'tools': [],
                'modules': ['report'],
                'parallel': False,
                'timeout': 300
            }
        }
        
        # Workflow state management
        self.active_workflows = {}
        self.workflow_history = []
    
    def show_banner(self):
        """Display workflow system banner"""
        banner = f"""
{Fore.BLUE}
╔══════════════════════════════════════════════════════════════════════════╗
║                {Fore.YELLOW}WebRaptor Automated Workflow System v{version}{Fore.BLUE}               ║
║              Intelligent Bug Bounty Automation & Orchestration           ║
║                        Author: LakshmikanthanK (@letchu_pkt)             ║
║                                                                          ║
╚══════════════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""
        print(banner)
    
    def list_workflows(self):
        """List available workflows"""
        print(f"\n{Fore.CYAN}Available Workflows:{Style.RESET_ALL}")
        for workflow_id, workflow in self.predefined_workflows.items():
            print(f"\n{Fore.YELLOW}{workflow_id}:{Style.RESET_ALL}")
            print(f"  Name: {workflow['name']}")
            print(f"  Description: {workflow['description']}")
            print(f"  Phases: {', '.join(workflow['phases'])}")
            print(f"  Duration: {workflow['estimated_duration']}")
            print(f"  Complexity: {workflow['complexity']}")
    
    def create_custom_workflow(self, workflow_name: str, phases: List[str]) -> Dict:
        """Create a custom workflow"""
        custom_workflow = {
            'name': workflow_name,
            'description': f'Custom workflow: {workflow_name}',
            'phases': phases,
            'estimated_duration': 'variable',
            'complexity': 'custom'
        }
        
        workflow_id = f"custom_{workflow_name.lower().replace(' ', '_')}"
        self.predefined_workflows[workflow_id] = custom_workflow
        
        # Save custom workflow
        workflow_file = self.workflows_dir / f"{workflow_id}.json"
        with open(workflow_file, 'w') as f:
            json.dump(custom_workflow, f, indent=2)
        
        print(f"{Fore.GREEN}[+] Custom workflow '{workflow_name}' created{Style.RESET_ALL}")
        return custom_workflow
    
    def run_workflow(self, workflow_id: str, target: str, custom_config: Dict = None) -> Dict:
        """Run a complete workflow"""
        if workflow_id not in self.predefined_workflows:
            print(f"{Fore.RED}[-] Unknown workflow: {workflow_id}{Style.RESET_ALL}")
            return {'success': False, 'error': f'Unknown workflow: {workflow_id}'}
        
        workflow = self.predefined_workflows[workflow_id]
        print(f"{Fore.BLUE}[*] Starting workflow: {workflow['name']}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Target: {target}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Phases: {', '.join(workflow['phases'])}{Style.RESET_ALL}")
        
        # Initialize workflow execution
        workflow_execution = {
            'workflow_id': workflow_id,
            'target': target,
            'start_time': time.time(),
            'phases': {},
            'status': 'running',
            'config': custom_config or {}
        }
        
        self.active_workflows[workflow_id] = workflow_execution
        
        try:
            # Execute phases sequentially or in parallel based on configuration
            for phase_id in workflow['phases']:
                print(f"\n{Fore.BLUE}{'='*80}")
                print(f"[*] Executing Phase: {phase_id}")
                print(f"{'='*80}{Style.RESET_ALL}")
                
                phase_result = self._execute_phase(phase_id, target, workflow_execution)
                workflow_execution['phases'][phase_id] = phase_result
                
                if not phase_result.get('success', False):
                    print(f"{Fore.RED}[-] Phase {phase_id} failed{Style.RESET_ALL}")
                    if not self.workflow_config.get('continue_on_failure', True):
                        workflow_execution['status'] = 'failed'
                        break
            
            # Complete workflow
            workflow_execution['end_time'] = time.time()
            workflow_execution['duration'] = workflow_execution['end_time'] - workflow_execution['start_time']
            workflow_execution['status'] = 'completed'
            
            # Generate summary
            summary = self._generate_workflow_summary(workflow_execution)
            workflow_execution['summary'] = summary
            
            # Save results
            self._save_workflow_results(workflow_execution)
            
            # Move to history
            self.workflow_history.append(workflow_execution)
            del self.active_workflows[workflow_id]
            
            print(f"\n{Fore.GREEN}[+] Workflow '{workflow['name']}' completed successfully!{Style.RESET_ALL}")
            print(f"{Fore.GREEN}[+] Duration: {workflow_execution['duration']:.2f} seconds{Style.RESET_ALL}")
            
            return workflow_execution
            
        except Exception as e:
            workflow_execution['status'] = 'error'
            workflow_execution['error'] = str(e)
            print(f"{Fore.RED}[-] Workflow execution failed: {e}{Style.RESET_ALL}")
            return workflow_execution
    
    def _execute_phase(self, phase_id: str, target: str, workflow_execution: Dict) -> Dict:
        """Execute a single workflow phase"""
        if phase_id not in self.phase_definitions:
            return {'success': False, 'error': f'Unknown phase: {phase_id}'}
        
        phase_def = self.phase_definitions[phase_id]
        print(f"{Fore.CYAN}[*] {phase_def['name']}{Style.RESET_ALL}")
        
        phase_result = {
            'phase_id': phase_id,
            'start_time': time.time(),
            'tools_executed': [],
            'modules_executed': [],
            'results': {},
            'success': True
        }
        
        try:
            # Execute tools
            if phase_def.get('tools'):
                tool_results = self._execute_tools(phase_def['tools'], target, phase_def.get('parallel', False))
                phase_result['tools_executed'] = tool_results
            
            # Execute modules
            if phase_def.get('modules'):
                module_results = self._execute_modules(phase_def['modules'], target, phase_def.get('parallel', False))
                phase_result['modules_executed'] = module_results
            
            phase_result['end_time'] = time.time()
            phase_result['duration'] = phase_result['end_time'] - phase_result['start_time']
            
            print(f"{Fore.GREEN}[+] Phase {phase_id} completed in {phase_result['duration']:.2f}s{Style.RESET_ALL}")
            
        except Exception as e:
            phase_result['success'] = False
            phase_result['error'] = str(e)
            print(f"{Fore.RED}[-] Phase {phase_id} failed: {e}{Style.RESET_ALL}")
        
        return phase_result
    
    def _execute_tools(self, tools: List[str], target: str, parallel: bool = False) -> List[Dict]:
        """Execute external tools"""
        results = []
        
        if parallel and len(tools) > 1:
            # Execute tools in parallel
            threads = []
            for tool in tools:
                if self.tool_manager.check_tool_installed(tool):
                    thread = threading.Thread(target=self._run_tool_async, args=(tool, target, results))
                    threads.append(thread)
                    thread.start()
            
            # Wait for all threads to complete
            for thread in threads:
                thread.join()
        else:
            # Execute tools sequentially
            for tool in tools:
                if self.tool_manager.check_tool_installed(tool):
                    result = self._run_tool(tool, target)
                    results.append(result)
                else:
                    print(f"{Fore.YELLOW}[!] Tool {tool} not installed, skipping{Style.RESET_ALL}")
        
        return results
    
    def _run_tool_async(self, tool: str, target: str, results: List[Dict]):
        """Run tool asynchronously"""
        result = self._run_tool(tool, target)
        results.append(result)
    
    def _run_tool(self, tool: str, target: str) -> Dict:
        """Run a single tool"""
        print(f"{Fore.CYAN}[*] Running {tool}...{Style.RESET_ALL}")
        
        # Define tool-specific arguments
        tool_args = self._get_tool_arguments(tool, target)
        
        try:
            success, stdout, stderr = self.tool_manager.run_tool(tool, tool_args, timeout=600)
            
            result = {
                'tool': tool,
                'target': target,
                'success': success,
                'stdout': stdout,
                'stderr': stderr,
                'timestamp': time.time()
            }
            
            if success:
                print(f"{Fore.GREEN}[+] {tool} completed successfully{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}[-] {tool} failed: {stderr}{Style.RESET_ALL}")
            
            return result
            
        except Exception as e:
            print(f"{Fore.RED}[-] Error running {tool}: {e}{Style.RESET_ALL}")
            return {
                'tool': tool,
                'target': target,
                'success': False,
                'error': str(e),
                'timestamp': time.time()
            }
    
    def _get_tool_arguments(self, tool: str, target: str) -> List[str]:
        """Get tool-specific arguments"""
        tool_args_map = {
            'nmap': ['-sS', '-sV', '-sC', '-O', '--open', target],
            'nuclei': ['-u', target, '-t', 'vulnerabilities/', '-json'],
            'nikto': ['-h', target, '-Format', 'json'],
            'subfinder': ['-d', target, '-silent'],
            'amass': ['-passive', '-d', target, '-silent'],
            'httpx': ['-u', target, '-silent', '-json'],
            'gobuster': ['-u', target, '-w', 'wordlists/common.txt', '-q'],
            'ffuf': ['-u', f'{target}/FUZZ', '-w', 'wordlists/common.txt', '-q'],
            'sqlmap': ['-u', target, '--batch', '--level=3', '--risk=2']
        }
        
        return tool_args_map.get(tool, [target])
    
    def _execute_modules(self, modules: List[str], target: str, parallel: bool = False) -> List[Dict]:
        """Execute WebRaptor modules"""
        results = []
        
        for module_name in modules:
            print(f"{Fore.CYAN}[*] Running module {module_name}...{Style.RESET_ALL}")
            
            try:
                # Import and run module
                modules_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "modules")
                module_path = os.path.join(modules_dir, f"{module_name}.py")
                
                if os.path.exists(module_path):
                    import importlib.util
                    spec = importlib.util.spec_from_file_location(f"modules.{module_name}", module_path)
                    module = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(module)
                    
                    if hasattr(module, 'run'):
                        # Capture module output
                        import io
                        import contextlib
                        
                        f = io.StringIO()
                        with contextlib.redirect_stdout(f):
                            module.run(target)
                        
                        output = f.getvalue()
                        
                        result = {
                            'module': module_name,
                            'target': target,
                            'success': True,
                            'output': output,
                            'timestamp': time.time()
                        }
                        
                        print(f"{Fore.GREEN}[+] Module {module_name} completed{Style.RESET_ALL}")
                    else:
                        result = {
                            'module': module_name,
                            'target': target,
                            'success': False,
                            'error': 'No run function found',
                            'timestamp': time.time()
                        }
                        print(f"{Fore.RED}[-] Module {module_name} has no run function{Style.RESET_ALL}")
                else:
                    result = {
                        'module': module_name,
                        'target': target,
                        'success': False,
                        'error': 'Module file not found',
                        'timestamp': time.time()
                    }
                    print(f"{Fore.RED}[-] Module {module_name} not found{Style.RESET_ALL}")
                
                results.append(result)
                
            except Exception as e:
                result = {
                    'module': module_name,
                    'target': target,
                    'success': False,
                    'error': str(e),
                    'timestamp': time.time()
                }
                print(f"{Fore.RED}[-] Error running module {module_name}: {e}{Style.RESET_ALL}")
                results.append(result)
        
        return results
    
    def _generate_workflow_summary(self, workflow_execution: Dict) -> Dict:
        """Generate workflow execution summary"""
        summary = {
            'workflow_id': workflow_execution['workflow_id'],
            'target': workflow_execution['target'],
            'status': workflow_execution['status'],
            'duration': workflow_execution['duration'],
            'phases_completed': len(workflow_execution['phases']),
            'tools_executed': 0,
            'modules_executed': 0,
            'successful_tools': 0,
            'successful_modules': 0,
            'findings_count': 0
        }
        
        for phase_id, phase_result in workflow_execution['phases'].items():
            # Count tools
            tools_executed = phase_result.get('tools_executed', [])
            summary['tools_executed'] += len(tools_executed)
            summary['successful_tools'] += sum(1 for tool in tools_executed if tool.get('success', False))
            
            # Count modules
            modules_executed = phase_result.get('modules_executed', [])
            summary['modules_executed'] += len(modules_executed)
            summary['successful_modules'] += sum(1 for module in modules_executed if module.get('success', False))
        
        return summary
    
    def _save_workflow_results(self, workflow_execution: Dict):
        """Save workflow execution results"""
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        target_clean = workflow_execution['target'].replace('.', '_').replace('/', '_')
        
        # Save detailed results
        results_file = self.results_dir / f"workflow_{workflow_execution['workflow_id']}_{target_clean}_{timestamp}.json"
        with open(results_file, 'w') as f:
            json.dump(workflow_execution, f, indent=2)
        
        print(f"{Fore.GREEN}[+] Workflow results saved to: {results_file}{Style.RESET_ALL}")
    
    def show_workflow_status(self):
        """Show current workflow status"""
        print(f"\n{Fore.BLUE}╔══════════════════════════════════════════════════════════════════════════╗")
        print(f"║                        WORKFLOW STATUS                              ║")
        print(f"╚══════════════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}")
        
        # Active workflows
        if self.active_workflows:
            print(f"\n{Fore.CYAN}⚡ Active Workflows:{Style.RESET_ALL}")
            for workflow_id, workflow in self.active_workflows.items():
                duration = time.time() - workflow['start_time']
                print(f"  {workflow_id}: {workflow['target']} (running for {duration:.0f}s)")
        else:
            print(f"\n{Fore.CYAN}⚡ Active Workflows:{Style.RESET_ALL} None")
        
        # Recent workflow history
        if self.workflow_history:
            print(f"\n{Fore.CYAN}📊 Recent Workflows:{Style.RESET_ALL}")
            for workflow in self.workflow_history[-5:]:  # Show last 5
                status_color = Fore.GREEN if workflow['status'] == 'completed' else Fore.RED
                print(f"  {workflow['workflow_id']}: {workflow['target']} - {status_color}{workflow['status']}{Style.RESET_ALL} ({workflow.get('duration', 0):.0f}s)")
        else:
            print(f"\n{Fore.CYAN}📊 Recent Workflows:{Style.RESET_ALL} None")
    
    def schedule_workflow(self, workflow_id: str, target: str, schedule_time: str):
        """Schedule a workflow for later execution"""
        # This would integrate with a scheduling system
        print(f"{Fore.YELLOW}[!] Workflow scheduling not implemented yet{Style.RESET_ALL}")
        print(f"Would schedule {workflow_id} for {target} at {schedule_time}")

def run(target, workflow_id='bug_bounty_full'):
    """Main entry point for workflow system"""
    try:
        workflow_system = AutomatedWorkflowSystem()
        workflow_system.show_banner()
        
        # Check if target is provided
        if not target:
            print(f"{Fore.RED}[-] No target specified{Style.RESET_ALL}")
            return
        
        # List available workflows if no specific workflow requested
        if workflow_id == 'list':
            workflow_system.list_workflows()
            return
        
        # Run the specified workflow
        result = workflow_system.run_workflow(workflow_id, target)
        
        if result.get('success', False):
            print(f"\n{Fore.GREEN}[+] Workflow execution completed successfully!{Style.RESET_ALL}")
        else:
            print(f"\n{Fore.RED}[-] Workflow execution failed{Style.RESET_ALL}")
        
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Workflow interrupted by user{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[-] Error in workflow execution: {e}{Style.RESET_ALL}")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        target = sys.argv[1]
        workflow_id = sys.argv[2] if len(sys.argv) > 2 else 'bug_bounty_full'
        run(target, workflow_id)
    else:
        print("Usage: python workflow_system.py <target> [workflow_id]")
        print("Available workflows: bug_bounty_full, quick_assessment, web_app_focus, network_focus")
