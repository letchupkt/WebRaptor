import os
import json
from datetime import datetime
from core.config import Config
import plotly.graph_objects as go
from plotly.subplots import make_subplots

timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

def generate_report(config, format='html'):
    """Generate advanced interactive security report in multiple formats"""
    if not os.path.exists('reports'):
        os.makedirs('reports')
    
    
    base_filename = f"webraptor_report_{timestamp}"
    
    if format == 'html':
        _generate_html_report(config, base_filename)
    elif format == 'pdf':
        _generate_pdf_report(config, base_filename)
    elif format == 'json':
        _generate_json_report(config, base_filename)
    else:
        raise ValueError(f"Unsupported report format: {format}")

def _generate_html_report(config, base_filename):
    """Generate cyberpunk/hacker-themed interactive HTML report"""
    report_path = os.path.join('reports', f"{base_filename}.html")
    
    # Generate visualizations
    severity_chart = _generate_severity_chart(config)
    module_stats_chart = _generate_module_stats_chart(config)
    timeline_chart = _generate_timeline_chart(config)
    
    # Generate findings tables
    findings_tables = _generate_findings_tables(config)
    
    html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WebRaptor Report - {config.target}</title>
    <script src="https://cdn.plot.ly/plotly-latest.min.js"></script>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Major+Mono+Display&display=swap');
        
        :root {{
            --matrix-green: #00ff41;
            --cyber-purple: #9d00ff;
            --neon-pink: #ff00a0;
            --electric-blue: #00f0ff;
            --dark-bg: #0d0208;
            --darker-bg: #030303;
        }}
        
        body {{
            font-family: 'Share Tech Mono', monospace;
            background-color: var(--dark-bg);
            color: var(--matrix-green);
            line-height: 1.6;
            overflow-x: hidden;
            background-image: 
                radial-gradient(circle at 10% 20%, rgba(0, 255, 65, 0.05) 0%, transparent 20%),
                radial-gradient(circle at 90% 80%, rgba(157, 0, 255, 0.05) 0%, transparent 20%);
        }}
        
        /* Glitch effect */
        .glitch {{
            position: relative;
            animation: glitch 5s infinite linear;
        }}
        
        @keyframes glitch {{
            0% {{ text-shadow: 0.05em 0 0 #00fffc, -0.05em -0.025em 0 #ff00ff; }}
            14% {{ text-shadow: 0.05em 0 0 #00fffc, -0.05em -0.025em 0 #ff00ff; }}
            15% {{ text-shadow: -0.05em -0.025em 0 #00fffc, 0.025em 0.025em 0 #ff00ff; }}
            49% {{ text-shadow: -0.05em -0.025em 0 #00fffc, 0.025em 0.025em 0 #ff00ff; }}
            50% {{ text-shadow: 0.025em 0.05em 0 #00fffc, 0.05em 0 0 #ff00ff; }}
            99% {{ text-shadow: 0.025em 0.05em 0 #00fffc, 0.05em 0 0 #ff00ff; }}
            100% {{ text-shadow: -0.025em 0 0 #00fffc, -0.025em -0.025em 0 #ff00ff; }}
        }}
        
        /* Scanlines overlay */
        body::before {{
            content: "";
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: 
                linear-gradient(rgba(0, 255, 65, 0.03) 0.1em, transparent 0.1em);
            background-size: 100% 0.2em;
            pointer-events: none;
            z-index: 1000;
            opacity: 0.5;
        }}
        
        .report-header {{
            background: linear-gradient(135deg, var(--darker-bg), var(--dark-bg));
            color: var(--matrix-green);
            padding: 2rem 0;
            margin-bottom: 2rem;
            border-bottom: 1px solid var(--matrix-green);
            position: relative;
            overflow: hidden;
        }}
        
        .report-header::before {{
            content: "";
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: 
                linear-gradient(90deg, 
                    transparent 0%, 
                    rgba(0, 255, 65, 0.1) 50%, 
                    transparent 100%);
            animation: scanline 8s linear infinite;
        }}
        
        @keyframes scanline {{
            0% {{ transform: translateX(-100%); }}
            100% {{ transform: translateX(100%); }}
        }}
        
        h1, h2, h3, h4, h5, h6 {{
            font-family: 'Major Mono Display', monospace;
            text-transform: uppercase;
            letter-spacing: 0.1em;
        }}
        
        .vulnerability-card {{
            background-color: rgba(13, 2, 8, 0.7);
            border-left: 4px solid;
            margin-bottom: 1.5rem;
            box-shadow: 0 0 10px rgba(0, 255, 65, 0.1);
            transition: all 0.3s ease;
            position: relative;
            overflow: hidden;
        }}
        
        .vulnerability-card::before {{
            content: "";
            position: absolute;
            top: 0;
            left: -100%;
            width: 100%;
            height: 100%;
            background: linear-gradient(90deg, 
                transparent, 
                rgba(0, 255, 65, 0.1), 
                transparent);
            transition: all 0.6s ease;
        }}
        
        .vulnerability-card:hover {{
            transform: translateY(-5px);
            box-shadow: 0 5px 15px rgba(0, 255, 65, 0.3);
        }}
        
        .vulnerability-card:hover::before {{
            left: 100%;
        }}
        
        .critical {{
            border-color: var(--neon-pink);
            color: var(--neon-pink);
        }}
        
        .high {{
            border-color: #ff2a6d;
            color: #ff2a6d;
        }}
        
        .medium {{
            border-color: var(--electric-blue);
            color: var(--electric-blue);
        }}
        
        .low {{
            border-color: #05d9e8;
            color: #05d9e8;
        }}
        
        .info {{
            border-color: var(--cyber-purple);
            color: var(--cyber-purple);
        }}
        
        .severity-badge {{
            font-weight: 600;
            padding: 0.25rem 0.5rem;
            border-radius: 4px;
            font-size: 0.75rem;
            text-transform: uppercase;
            background-color: rgba(0, 0, 0, 0.5);
            box-shadow: 0 0 5px currentColor;
        }}
        
        .chart-container {{
            background-color: rgba(13, 2, 8, 0.7);
            border-radius: 8px;
            padding: 1rem;
            margin-bottom: 2rem;
            box-shadow: 0 0 10px rgba(0, 255, 65, 0.1);
            border: 1px solid rgba(0, 255, 65, 0.2);
        }}
        
        .finding-details {{
            display: none;
            padding: 1rem;
            background-color: rgba(3, 3, 3, 0.8);
            border-radius: 4px;
            margin-top: 0.5rem;
            border-left: 2px solid currentColor;
            animation: fadeIn 0.5s ease;
        }}
        
        @keyframes fadeIn {{
            from {{ opacity: 0; }}
            to {{ opacity: 1; }}
        }}
        
        .nav-tabs .nav-link {{
            color: var(--matrix-green);
            border: none;
            position: relative;
        }}
        
        .nav-tabs .nav-link::after {{
            content: "";
            position: absolute;
            bottom: 0;
            left: 0;
            width: 0;
            height: 2px;
            background-color: var(--matrix-green);
            transition: width 0.3s ease;
        }}
        
        .nav-tabs .nav-link:hover::after {{
            width: 100%;
        }}
        
        .nav-tabs .nav-link.active {{
            color: var(--electric-blue);
            background-color: transparent;
        }}
        
        .nav-tabs .nav-link.active::after {{
            width: 100%;
            background-color: var(--electric-blue);
        }}
        
        .card {{
            background-color: rgba(13, 2, 8, 0.7);
            border: 1px solid rgba(0, 255, 65, 0.2);
            box-shadow: 0 0 15px rgba(0, 255, 65, 0.1);
            margin-bottom: 2rem;
        }}
        
        .card-header {{
            background: linear-gradient(90deg, rgba(0, 255, 65, 0.1), rgba(13, 2, 8, 0.7));
            border-bottom: 1px solid rgba(0, 255, 65, 0.3);
        }}
        
        footer {{
            background: linear-gradient(180deg, var(--dark-bg), var(--darker-bg));
            color: var(--matrix-green);
            padding: 2rem 0;
            margin-top: 3rem;
            border-top: 1px solid var(--matrix-green);
            position: relative;
        }}
        
        footer::before {{
            content: "";
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: 
                linear-gradient(90deg, 
                    transparent 0%, 
                    rgba(0, 255, 65, 0.05) 50%, 
                    transparent 100%);
            animation: scanline 10s linear infinite;
        }}
        
        a {{
            color: var(--electric-blue);
            text-decoration: none;
            transition: all 0.3s ease;
            position: relative;
        }}
        
        a::after {{
            content: "";
            position: absolute;
            bottom: -2px;
            left: 0;
            width: 0;
            height: 1px;
            background-color: var(--electric-blue);
            transition: width 0.3s ease;
        }}
        
        a:hover {{
            color: var(--matrix-green);
            text-shadow: 0 0 5px var(--matrix-green);
        }}
        
        a:hover::after {{
            width: 100%;
        }}
        
        .alert {{
            background-color: rgba(3, 3, 3, 0.8);
            border: 1px solid var(--matrix-green);
            color: var(--matrix-green);
            border-radius: 0;
        }}
        
        .btn-link {{
            color: var(--electric-blue);
        }}
        
        .btn-link:hover {{
            color: var(--matrix-green);
        }}
        
        /* Terminal effect */
        .terminal-effect {{
            position: relative;
        }}
        
        .terminal-effect::after {{
            content: ">";
            position: absolute;
            left: -1em;
            color: var(--matrix-green);
            animation: blink 1s step-end infinite;
        }}
        
        @keyframes blink {{
            from, to {{ opacity: 1; }}
            50% {{ opacity: 0; }}
        }}
        
        /* Responsive adjustments */
        @media (max-width: 768px) {{
            .chart-container {{
                padding: 0.5rem;
            }}
            
            .report-header h1 {{
                font-size: 1.5rem;
            }}
        }}
    </style>
</head>
<body>
    <div class="report-header">
        <div class="container">
            <div class="row align-items-center">
                <div class="col-md-8">
                    <h1 class="glitch"><i class="fas fa-shield-alt me-2"></i> WebRaptor Security Report</h1>
                    <p class="lead mb-0 terminal-effect">Comprehensive security assessment report</p>
                </div>
                <div class="col-md-4 text-md-end">
                    <div class="d-inline-block p-2" style="border: 1px solid var(--matrix-green);">
                        <span class="fw-bold">{datetime.now().strftime('%B %d, %Y %H:%M')}</span>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <div class="container">
        <!-- Executive Summary -->
        <div class="row mb-4">
            <div class="col">
                <div class="card">
                    <div class="card-header">
                        <h2 class="h5 mb-0"><i class="fas fa-chart-pie me-2"></i> Executive Summary</h2>
                    </div>
                    <div class="card-body">
                        <div class="row">
                            <div class="col-md-6">
                                <div id="severityChart" class="chart-container"></div>
                            </div>
                            <div class="col-md-6">
                                <div id="moduleStatsChart" class="chart-container"></div>
                            </div>
                        </div>
                        <div class="row mt-3">
                            <div class="col-12">
                                <div class="alert">
                                    <h3 class="h6">Assessment Overview</h3>
                                    <ul class="mb-0">
                                        <li><strong>Target:</strong> {config.target}</li>
                                        <li><strong>Scan Duration:</strong> {getattr(config, 'scan_duration', 'N/A')}</li>
                                        <li><strong>Total Findings:</strong> {sum(len(v) for v in config.results.values()) if config.results else 0}</li>
                                        <li><strong>Modules Executed:</strong> {len(config.results) if config.results else 0}</li>
                                    </ul>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Detailed Findings -->
        <div class="row">
            <div class="col">
                <div class="card">
                    <div class="card-header">
                        <h2 class="h5 mb-0"><i class="fas fa-bug me-2"></i> Detailed Findings</h2>
                    </div>
                    <div class="card-body">
                        <ul class="nav nav-tabs mb-4" id="findingsTab" role="tablist">
                            {_generate_module_tabs(config)}
                        </ul>
                        <div class="tab-content" id="findingsTabContent">
                            {findings_tables}
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Timeline -->
        <div class="row mt-4">
            <div class="col">
                <div class="card">
                    <div class="card-header">
                        <h2 class="h5 mb-0"><i class="fas fa-clock me-2"></i> Activity Timeline</h2>
                    </div>
                    <div class="card-body">
                        <div id="timelineChart" class="chart-container"></div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Recommendations -->
        <div class="row mt-4">
            <div class="col">
                <div class="card">
                    <div class="card-header">
                        <h2 class="h5 mb-0"><i class="fas fa-lightbulb me-2"></i> Security Recommendations</h2>
                    </div>
                    <div class="card-body">
                        {_generate_recommendations(config)}
                    </div>
                </div>
            </div>
        </div>
    </div>

    <footer>
        <div class="container">
            <div class="row">
                <div class="col-md-6">
                    <h3>About WebRaptor</h3>
                    <p>Advanced web application security scanning tool</p>
                </div>
                <div class="col-md-6 text-md-end">
                    <h3>Report Metadata</h3>
                    <ul class="list-unstyled">
                        <li><strong>Report Version:</strong> 2.1</li>
                        <li><strong>Generated By:</strong> WebRaptor Automated Scanner</li>
                        <li><strong>Scan ID:</strong> {os.getpid()}-{timestamp}</li>
                    </ul>
                </div>
            </div>
            <hr style="border-color: rgba(0, 255, 65, 0.3);">
            <div class="row">
                <div class="col-md-6">
                    <p>© {datetime.now().year} LakshmikanthanK (Letchu). All rights reserved.</p>
                </div>
                <div class="col-md-6 text-md-end">
                    <a href="https://github.com/letchupkt" class="me-3"><i class="fab fa-github me-1"></i> GitHub</a>
                    <a href="https://letchupkt.vgrow.tech"><i class="fas fa-globe me-1"></i> Portfolio</a>
                </div>
            </div>
        </div>
    </footer>

    <script>
        // Severity Distribution Chart with cyberpunk theme
        {severity_chart.replace('"marker_colors":', '"marker_colors": ["#ff00a0", "#ff2a6d", "#00f0ff", "#05d9e8", "#9d00ff"],')}
        
        // Module Statistics Chart with cyberpunk theme
        {module_stats_chart.replace('"marker_color":', '"marker_color": "#00f0ff",')}
        
        // Timeline Chart with cyberpunk theme
        {timeline_chart}
        
        // Toggle finding details with animation
        function toggleDetails(button) {{
            const details = button.parentElement.nextElementSibling;
            details.style.display = details.style.display === 'none' ? 'block' : 'none';
            button.innerHTML = details.style.display === 'none' ? 
                '<i class="fas fa-chevron-down me-1"></i> Show Details' : 
                '<i class="fas fa-chevron-up me-1"></i> Hide Details';
            
            // Add pulse effect
            button.classList.add('pulse');
            setTimeout(() => button.classList.remove('pulse'), 300);
        }}
        
        // Add pulse animation
        const style = document.createElement('style');
        style.textContent = `
            .pulse {{
                animation: pulse 0.3s ease;
            }}
            @keyframes pulse {{
                0% {{ transform: scale(1); }}
                50% {{ transform: scale(1.1); }}
                100% {{ transform: scale(1); }}
            }}
        `;
        document.head.appendChild(style);
        
        // Random glitch effect on headings
        setInterval(() => {{
            const headings = document.querySelectorAll('h1, h2, h3, h4, h5, h6');
            headings.forEach(heading => {{
                if (Math.random() > 0.9) {{
                    heading.classList.add('glitch');
                    setTimeout(() => heading.classList.remove('glitch'), 500);
                }}
            }});
        }}, 3000);
        
        // Terminal typing effect
        function typeWriter(element, text, speed = 50) {{
            let i = 0;
            function typing() {{
                if (i < text.length) {{
                    element.innerHTML += text.charAt(i);
                    i++;
                    setTimeout(typing, speed);
                }}
            }}
            element.innerHTML = '';
            typing();
        }}
        
        // Apply to some elements
        document.addEventListener('DOMContentLoaded', () => {{
            const terminalElements = document.querySelectorAll('.terminal-effect');
            terminalElements.forEach(el => {{
                const text = el.textContent;
                typeWriter(el, text);
            }});
            
            // Add scan animation to vulnerability cards
            const cards = document.querySelectorAll('.vulnerability-card');
            cards.forEach(card => {{
                card.addEventListener('mouseenter', () => {{
                    card.style.boxShadow = '0 0 15px currentColor';
                }});
                card.addEventListener('mouseleave', () => {{
                    card.style.boxShadow = '0 0 10px rgba(0, 255, 65, 0.1)';
                }});
            }});
        }});
    </script>
</body>
</html>
"""
    
    with open(report_path, 'w', encoding='utf-8') as f:
        f.write(html)
    
    return report_path

def _generate_module_tabs(config):
    """Generate navigation tabs for each module"""
    if not config.results:
        return ""
    
    tabs = []
    first = True
    for i, module in enumerate(config.results.keys()):
        active = "active" if first else ""
        aria_selected = "true" if first else "false"
        tabs.append(f"""
            <li class="nav-item" role="presentation">
                <button class="nav-link {active}" id="{module}-tab" data-bs-toggle="tab" 
                    data-bs-target="#{module}" type="button" role="tab" 
                    aria-controls="{module}" aria-selected="{aria_selected}">
                    {module.upper()}
                </button>
            </li>
        """)
        first = False
    
    return "\n".join(tabs)

def _generate_findings_tables(config):
    """Generate findings tables for each module"""
    if not config.results:
        return ""
    
    tables = []
    first = True
    for module, findings in config.results.items():
        active = "show active" if first else ""
        first = False
        
        findings_html = []
        for finding in findings:
            # Extract severity if present in the finding string
            severity = "medium"
            if "critical" in finding.lower():
                severity = "critical"
            elif "high" in finding.lower():
                severity = "high"
            elif "low" in finding.lower():
                severity = "low"
            elif "info" in finding.lower():
                severity = "info"
            
            severity_class = severity
            severity_badge = f"""
                <span class="severity-badge bg-{severity} text-white">
                    {severity.upper()}
                </span>
            """
            
            findings_html.append(f"""
                <div class="vulnerability-card {severity_class} p-3">
                    <div class="d-flex justify-content-between align-items-center">
                        <h4 class="h6 mb-0">{finding.split(':', 1)[0] if ':' in finding else finding}</h4>
                        {severity_badge}
                    </div>
                    <button class="btn btn-sm btn-link mt-2 p-0" onclick="toggleDetails(this)">
                        <i class="fas fa-chevron-down me-1"></i> Show Details
                    </button>
                    <div class="finding-details">
                        <p>{finding}</p>
                        <div class="mt-2">
                            <h5 class="h6">Remediation:</h5>
                            <p>{_get_remediation_advice(module, finding)}</p>
                        </div>
                    </div>
                </div>
            """)
        
        tables.append(f"""
            <div class="tab-pane fade {active}" id="{module}" role="tabpanel" aria-labelledby="{module}-tab">
                {''.join(findings_html)}
            </div>
        """)
    
    return "\n".join(tables)

def _generate_severity_chart(config):
    """Generate Plotly severity distribution chart"""
    if not config.results:
        return "{}"
    
    severity_counts = {
        'Critical': 0,
        'High': 0,
        'Medium': 0,
        'Low': 0,
        'Info': 0
    }
    
    for findings in config.results.values():
        for finding in findings:
            if "critical" in finding.lower():
                severity_counts['Critical'] += 1
            elif "high" in finding.lower():
                severity_counts['High'] += 1
            elif "medium" in finding.lower():
                severity_counts['Medium'] += 1
            elif "low" in finding.lower():
                severity_counts['Low'] += 1
            else:
                severity_counts['Info'] += 1
    
    labels = list(severity_counts.keys())
    values = list(severity_counts.values())
    colors = ['#e74c3c', '#e67e22', '#f39c12', '#2ecc71', '#3498db']
    
    fig = go.Figure(data=[go.Pie(
        labels=labels,
        values=values,
        hole=.4,
        marker_colors=colors,
        textinfo='label+percent',
        hoverinfo='label+value'
    )])
    
    fig.update_layout(
        margin=dict(t=0, b=0, l=0, r=0),
        legend=dict(
            orientation="h",
            yanchor="bottom",
            y=1.02,
            xanchor="center",
            x=0.5
        )
    )
    
    return f"Plotly.newPlot('severityChart', {json.dumps(fig.to_dict(), indent=2)});"

def _generate_module_stats_chart(config):
    """Generate Plotly module statistics chart"""
    if not config.results:
        return "{}"
    
    modules = list(config.results.keys())
    counts = [len(findings) for findings in config.results.values()]
    
    fig = go.Figure([go.Bar(
        x=modules,
        y=counts,
        marker_color='#3498db',
        text=counts,
        textposition='auto'
    )])
    
    fig.update_layout(
        margin=dict(t=0, b=0, l=0, r=0),
        xaxis_title="Modules",
        yaxis_title="Number of Findings"
    )
    
    return f"Plotly.newPlot('moduleStatsChart', {json.dumps(fig.to_dict(), indent=2)});"

def _generate_timeline_chart(config):
    """Generate Plotly timeline chart of scan activities"""
    if not hasattr(config, 'timeline_events'):
        return "{}"
    
    events = config.timeline_events if hasattr(config, 'timeline_events') else []
    if not events:
        return "{}"
    
    fig = make_subplots(rows=1, cols=1)
    
    for event in events:
        fig.add_trace(go.Scatter(
            x=[event['timestamp']],
            y=[event['module']],
            mode='markers',
            marker=dict(size=12),
            name=event['module'],
            text=[f"{event['module']}: {event['event']}"],
            hoverinfo='text'
        ))
    
    fig.update_layout(
        margin=dict(t=0, b=0, l=0, r=0),
        xaxis_title="Time",
        yaxis_title="Module",
        showlegend=False
    )
    
    return f"Plotly.newPlot('timelineChart', {json.dumps(fig.to_dict(), indent=2)});"

def _generate_recommendations(config):
    """Generate security recommendations based on findings"""
    if not config.results:
        return "<p>No recommendations available.</p>"
    
    recommendations = {
        'critical': [],
        'high': [],
        'medium': [],
        'low': []
    }
    
    # Analyze findings to generate recommendations
    for module, findings in config.results.items():
        for finding in findings:
            if "SQL injection" in finding:
                recommendations['critical'].append(
                    "Implement prepared statements and input validation for all database queries"
                )
            elif "XSS" in finding:
                recommendations['high'].append(
                    "Implement proper output encoding and Content Security Policy (CSP)"
                )
            elif "LFI" in finding:
                recommendations['high'].append(
                    "Restrict file system access and implement allow lists for file inclusion"
                )
            elif "subdomain" in finding.lower() and "takeover" in finding.lower():
                recommendations['medium'].append(
                    "Claim unused subdomains or remove DNS records for unused services"
                )
    
    # Deduplicate recommendations
    for level in recommendations:
        recommendations[level] = list(set(recommendations[level]))
    
    html = []
    for level in ['critical', 'high', 'medium', 'low']:
        if recommendations[level]:
            html.append(f"""
                <div class="mb-3">
                    <h4 class="h5 text-{level}">{level.title()} Priority</h4>
                    <ul>
                        {''.join([f'<li>{rec}</li>' for rec in recommendations[level]])}
                    </ul>
                </div>
            """)
    
    return "\n".join(html) if html else "<p>No specific recommendations generated.</p>"

def _get_remediation_advice(module, finding):
    """Get specific remediation advice for a finding"""
    advice = {
        'sqli': "Use parameterized queries or prepared statements. Implement input validation and consider using an ORM.",
        'xss': "Implement proper output encoding. Use Content Security Policy (CSP) headers. Sanitize all user input.",
        'lfi': "Restrict file system access. Use allow lists for file inclusion. Avoid using user input in file paths.",
        'subenum': "Review all discovered subdomains. Remove or secure unused subdomains. Implement proper DNS records.",
        'dirbuster': "Remove or protect exposed directories. Implement proper authentication and authorization.",
        'tech_detect': "Keep all components up to date. Remove version information from headers and responses.",
    }
    
    return advice.get(module.lower(), "Review the finding and implement appropriate security controls.")

def _generate_pdf_report(config, base_filename):
    """Generate PDF version of the report"""
    # This would use weasyprint or similar to convert HTML to PDF
    pass

def _generate_json_report(config, base_filename):
    """Generate JSON version of the report data"""
    report_path = os.path.join('reports', f"{base_filename}.json")
    
    report_data = {
        'metadata': {
            'target': config.target,
            'scan_date': getattr(config, 'scan_date', str(datetime.now())),
            'scan_duration': getattr(config, 'scan_duration', 'N/A'),
            'report_version': '2.1'
        },
        'findings': config.results if hasattr(config, 'results') else {},
        'statistics': {
            'total_findings': sum(len(v) for v in config.results.values()) if config.results else 0,
            'modules_executed': len(config.results) if config.results else 0
        }
    }
    
    with open(report_path, 'w') as f:
        json.dump(report_data, f, indent=2)
    
    return report_path 