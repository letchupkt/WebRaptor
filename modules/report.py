#!/usr/bin/env python3
"""
WebRaptor Advanced Reporting System
Comprehensive vulnerability analysis and professional report generation
"""

import os
import sys
import json
import time
from pathlib import Path
from typing import List, Dict, Optional, Any
from colorama import Fore, Style, init
from core.config import Config
from datetime import datetime

init()

# Module metadata
description = "Advanced reporting system with comprehensive vulnerability analysis and professional reports"
author = "LakshmikanthanK (@letchu_pkt)"
version = "2.1"

class AdvancedReportingSystem:
    """Advanced reporting system with multiple output formats and analysis"""
    
    def __init__(self, config: Config = None):
        self.config = config or Config()
        self.reports_dir = Path("output/reports")
        self.html_dir = Path("output/reports/html")
        self.json_dir = Path("output/reports/json")
        self.pdf_dir = Path("output/reports/pdf")
        
        # Create directories
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        self.html_dir.mkdir(parents=True, exist_ok=True)
        self.json_dir.mkdir(parents=True, exist_ok=True)
        self.pdf_dir.mkdir(parents=True, exist_ok=True)
        
        # Report configuration
        self.report_config = {
            'company_name': 'WebRaptor Security Assessment',
            'author_name': 'LakshmikanthanK (@letchu_pkt)',
            'author_email': 'contact@webraptor.com',
            'report_classification': 'Confidential'
        }
        
        # Vulnerability severity mapping
        self.severity_mapping = {
            'critical': {'score': 10, 'color': '#FF0000'},
            'high': {'score': 8, 'color': '#FF6600'},
            'medium': {'score': 6, 'color': '#FFCC00'},
            'low': {'score': 4, 'color': '#00CC00'},
            'info': {'score': 2, 'color': '#0066CC'}
        }
    
    def generate_comprehensive_report(self, target: str, scan_results: Dict, format: str = 'html') -> str:
        """Generate comprehensive security assessment report"""
        print(f"{Fore.BLUE}[*] Generating comprehensive report for {target}...{Style.RESET_ALL}")
        
        # Analyze scan results
        analysis = self._analyze_scan_results(scan_results)
        
        # Generate report based on format
        if format.lower() == 'html':
            report_file = self._generate_html_report(target, scan_results, analysis)
        elif format.lower() == 'json':
            report_file = self._generate_json_report(target, scan_results, analysis)
        else:
            print(f"{Fore.RED}[-] Unsupported format: {format}{Style.RESET_ALL}")
            return None
        
        print(f"{Fore.GREEN}[+] Report generated: {report_file}{Style.RESET_ALL}")
        return report_file
    
    def _analyze_scan_results(self, scan_results: Dict) -> Dict:
        """Analyze scan results and generate insights"""
        analysis = {
            'total_vulnerabilities': 0,
            'severity_distribution': {},
            'risk_score': 0,
            'recommendations': []
        }
        
        # Count vulnerabilities by severity
        for module, results in scan_results.items():
            if isinstance(results, list):
                for finding in results:
                    if isinstance(finding, dict):
                        severity = finding.get('severity', 'info').lower()
                        analysis['severity_distribution'][severity] = analysis['severity_distribution'].get(severity, 0) + 1
                        analysis['total_vulnerabilities'] += 1
        
        # Calculate risk score
        risk_score = 0
        for severity, count in analysis['severity_distribution'].items():
            if severity in self.severity_mapping:
                risk_score += count * self.severity_mapping[severity]['score']
        
        analysis['risk_score'] = min(risk_score, 100)
        analysis['recommendations'] = self._generate_recommendations(analysis)
        
        return analysis
    
    def _generate_recommendations(self, analysis: Dict) -> List[str]:
        """Generate security recommendations"""
        recommendations = []
        
        if analysis['severity_distribution'].get('critical', 0) > 0:
            recommendations.append("Immediately address all critical vulnerabilities")
        
        if analysis['severity_distribution'].get('high', 0) > 0:
            recommendations.append("Prioritize remediation of high-severity vulnerabilities")
        
        recommendations.extend([
            "Establish regular vulnerability scanning",
            "Implement patch management program",
            "Conduct security awareness training",
            "Implement multi-factor authentication"
        ])
        
        return recommendations
    
    def _generate_html_report(self, target: str, scan_results: Dict, analysis: Dict) -> str:
        """Generate HTML report"""
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        report_file = self.reports_dir / f"security_report_{target.replace('.', '_')}_{timestamp}.html"
        
        html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Assessment Report - {target}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 8px; text-align: center; margin-bottom: 20px; }}
        .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 20px 0; }}
        .summary-item {{ background: #f8f9fa; padding: 20px; border-radius: 8px; text-align: center; }}
        .finding {{ background: white; margin: 10px 0; padding: 15px; border-radius: 8px; border-left: 4px solid #007bff; }}
        .critical {{ border-left-color: #dc3545; }}
        .high {{ border-left-color: #fd7e14; }}
        .medium {{ border-left-color: #ffc107; }}
        .low {{ border-left-color: #28a745; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Security Assessment Report</h1>
            <h2>{target}</h2>
            <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>
        
        <div class="summary">
            <div class="summary-item">
                <h3>Risk Score</h3>
                <div style="font-size: 2rem; font-weight: bold; color: #dc3545;">{analysis['risk_score']}/100</div>
            </div>
            <div class="summary-item">
                <h3>Total Vulnerabilities</h3>
                <div style="font-size: 2rem; font-weight: bold; color: #007bff;">{analysis['total_vulnerabilities']}</div>
            </div>
            <div class="summary-item">
                <h3>Critical Findings</h3>
                <div style="font-size: 2rem; font-weight: bold; color: #dc3545;">{analysis['severity_distribution'].get('critical', 0)}</div>
            </div>
        </div>
        
        <h2>Detailed Findings</h2>
        {self._create_findings_html(scan_results)}
        
        <h2>Recommendations</h2>
        <ul>
            {''.join(f'<li>{rec}</li>' for rec in analysis['recommendations'])}
        </ul>
        
        <footer style="margin-top: 40px; padding: 20px; background: #343a40; color: white; text-align: center; border-radius: 8px;">
            <p>Report generated by WebRaptor Security Assessment Framework</p>
        </footer>
    </div>
</body>
</html>
"""
        
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return str(report_file)
    
    def _create_findings_html(self, scan_results: Dict) -> str:
        """Create findings HTML"""
        findings_html = ""
        
        for module, results in scan_results.items():
            if isinstance(results, list):
                for finding in results:
                    if isinstance(finding, dict):
                        severity = finding.get('severity', 'info').lower()
                        title = finding.get('title', finding.get('name', 'Unknown Finding'))
                        description = finding.get('description', finding.get('details', 'No description available'))
                        
                        findings_html += f"""
                        <div class="finding {severity}">
                            <h3>{title}</h3>
                            <p><strong>Severity:</strong> {severity.upper()}</p>
                            <p><strong>Description:</strong> {description}</p>
                        </div>
                        """
        
        return findings_html
    
    def _generate_json_report(self, target: str, scan_results: Dict, analysis: Dict) -> str:
        """Generate JSON report"""
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        report_file = self.reports_dir / f"security_report_{target.replace('.', '_')}_{timestamp}.json"
        
        report_data = {
            'metadata': {
                'target': target,
                'report_date': datetime.now().isoformat(),
                'author': self.report_config['author_name']
            },
            'analysis': analysis,
            'scan_results': scan_results
        }
        
        with open(report_file, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, default=str)
        
        return str(report_file)

def run(target, format='html'):
    """Main entry point for reporting module"""
    try:
        reporting_system = AdvancedReportingSystem()
        
        # Simulate scan results
        scan_results = {
            'nuclei_scanner': [
                {
                    'title': 'SQL Injection Vulnerability',
                    'severity': 'high',
                    'description': 'SQL injection vulnerability detected in login form'
                }
            ],
            'nikto_scanner': [
                {
                    'title': 'Outdated Server Version',
                    'severity': 'low',
                    'description': 'Web server version is outdated'
                }
            ]
        }
        
        # Generate report
        report_file = reporting_system.generate_comprehensive_report(target, scan_results, format)
        
        if report_file:
            print(f"\n{Fore.GREEN}[+] Report generation completed successfully!{Style.RESET_ALL}")
            print(f"{Fore.GREEN}[+] Report saved to: {report_file}{Style.RESET_ALL}")
        
    except Exception as e:
        print(f"{Fore.RED}[-] Error in report generation: {e}{Style.RESET_ALL}")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        target = sys.argv[1]
        format = sys.argv[2] if len(sys.argv) > 2 else 'html'
        run(target, format)
    else:
        print("Usage: python report.py <target> [format]")
        print("Available formats: html, json")
