# WebRaptor - Advanced Bug Bounty Automation Tool

[![Version](https://img.shields.io/badge/version-2.1-blue.svg)](https://github.com/letchu_pkt/WebRaptor)
[![Python](https://img.shields.io/badge/python-3.8+-green.svg)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-red.svg)](LICENSE)
[![Author](https://img.shields.io/badge/author-LakshmikanthanK-orange.svg)](https://github.com/letchu_pkt)

## 🚀 Overview

WebRaptor is a comprehensive, professional-grade bug bounty automation tool that integrates 50+ security tools into a unified platform. It provides automated reconnaissance, vulnerability scanning, exploitation, and reporting capabilities for complete security assessments.

## ✨ Features

### 🔍 **Reconnaissance & Discovery**
- **Subdomain Enumeration**: Advanced subdomain discovery using multiple sources
- **Historical URL Discovery**: Wayback Machine integration for historical data
- **Port Scanning**: Comprehensive port scanning with Nmap and Masscan
- **Technology Detection**: Web technology fingerprinting and identification
- **DNS Enumeration**: DNS reconnaissance and analysis

### 🛡️ **Vulnerability Scanning**
- **Nuclei Integration**: Template-based vulnerability scanning
- **Nikto Integration**: Web server vulnerability scanning
- **SQLMap Integration**: Automated SQL injection testing
- **XSS Testing**: Cross-site scripting vulnerability detection
- **Custom Modules**: Specialized vulnerability detection modules

### 🔧 **Advanced Tools Integration**
- **Directory Bruteforce**: WFuzz, Dirb, Gobuster, FFuF
- **Web Crawling**: Katana, Unfurl, Qsreplace
- **JavaScript Analysis**: LinkFinder, SecretFinder, JSFinder
- **Parameter Discovery**: ParamSpider, Arjun
- **WAF Detection**: WAFW00F integration

### 📊 **Automation & Workflows**
- **Predefined Workflows**: 7 comprehensive automation pipelines
- **Custom Workflows**: Create and manage custom automation sequences
- **Real-time Dashboard**: Interactive monitoring and visualization
- **Configuration Management**: Secure API key and settings management

### 📈 **Reporting & Visualization**
- **HTML Reports**: Comprehensive HTML reports with visualizations
- **JSON Output**: Machine-readable JSON reports
- **Real-time Monitoring**: Live dashboard with system metrics
- **Export Capabilities**: Multiple output formats

## 🛠️ Installation

### Prerequisites

- **Python 3.8+**
- **Git**
- **Go 1.19+** (for Go-based tools)
- **Java 8+** (for Java-based tools)
- **Node.js** (for some tools)

### Quick Installation

```bash
# Clone the repository
git clone https://github.com/letchu_pkt/WebRaptor.git
cd WebRaptor

# Install Python dependencies
pip install -r requirements.txt

# Run WebRaptor
python main.py
```

### Manual Installation

1. **Clone Repository**
```bash
git clone https://github.com/letchu_pkt/WebRaptor.git
cd WebRaptor
```

2. **Install Python Dependencies**
```bash
pip install -r requirements.txt
```

3. **Install System Dependencies**

**Ubuntu/Debian:**
```bash
sudo apt update
sudo apt install -y nmap nikto dirb whatweb masscan
sudo apt install -y golang-go nodejs npm
```

**macOS:**
```bash
brew install nmap nikto dirb whatweb masscan
brew install go node
```

**Windows:**
```bash
# Install using Chocolatey
choco install nmap nikto dirb whatweb masscan
choco install golang nodejs
```

4. **Install Go-based Tools**
```bash
# Install Go tools
go install github.com/tomnomnom/waybackurls@latest
go install github.com/lc/gau@latest
go install github.com/tomnomnom/assetfinder@latest
go install github.com/projectdiscovery/subfinder@latest
go install github.com/projectdiscovery/httpx@latest
go install github.com/projectdiscovery/nuclei@latest
go install github.com/projectdiscovery/katana@latest
go install github.com/projectdiscovery/dnsx@latest
go install github.com/projectdiscovery/shuffledns@latest
go install github.com/projectdiscovery/chaos-client@latest
go install github.com/tomnomnom/unfurl@latest
go install github.com/tomnomnom/qsreplace@latest
go install github.com/ffuf/ffuf@latest
go install github.com/OJ/gobuster@latest
```

5. **Install Python Tools**
```bash
pip install sqlmap wfuzz wafw00f dnsrecon theharvester sublist3r knockpy arjun
```

## 🚀 Quick Start

### 1. Launch WebRaptor
```bash
python main.py
```

### 2. Set Target
```bash
set target example.com
```

### 3. Install Required Tools
```bash
tools install
```

### 4. Run Automated Bug Bounty Pipeline
```bash
auto
```

### 5. Generate Report
```bash
run report
```

## 📖 Usage Guide

### Basic Commands

```bash
# Set target
set target <url>

# Show available modules
show modules

# Run a specific module
run <module_name>

# Run workflow
workflow <workflow_name>

# Show tool status
tools status

# Install tools
tools install

# Configure settings
configure

# Show help
help
```

### Available Modules

#### **Reconnaissance Modules**
- `advanced_subenum` - Advanced subdomain enumeration
- `waybackurls_scanner` - Historical URL discovery
- `portscan` - Port scanning and service detection
- `tech_detect` - Technology detection and fingerprinting

#### **Vulnerability Scanning Modules**
- `nuclei_scanner` - Template-based vulnerability scanning
- `nikto_scanner` - Web server vulnerability scanning
- `sqlmap_scanner` - SQL injection testing
- `xss` - Cross-site scripting testing
- `spli` - SQL injection testing

#### **Advanced Tools Modules**
- `advanced_tools` - Comprehensive tool integration
- `screenshot` - Screenshot capture
- `report` - Report generation

### Predefined Workflows

#### **1. Full Reconnaissance (`full_recon`)**
Complete reconnaissance using all available tools:
- Subdomain enumeration
- Historical URL discovery
- Port scanning
- Technology detection
- Directory bruteforce
- Vulnerability scanning

#### **2. Bug Bounty Pipeline (`bug_bounty`)**
Complete bug bounty automation:
- Subdomain discovery
- Historical URL analysis
- Port scanning
- Web crawling
- Technology fingerprinting
- Vulnerability scanning
- SQL injection testing
- XSS testing
- Report generation

#### **3. Stealth Scan (`stealth_scan`)**
Low-profile scanning to avoid detection:
- Passive subdomain enumeration
- Historical URL analysis
- Light port scanning
- Technology detection

#### **4. Web Application Scan (`web_app_scan`)**
Focused web application security testing:
- Technology detection
- Directory bruteforce
- Parameter discovery
- Vulnerability scanning
- SQL injection testing
- XSS testing
- Screenshot capture

#### **5. API Testing (`api_testing`)**
API endpoint discovery and security testing:
- API endpoint discovery
- Parameter analysis
- Vulnerability scanning
- SQL injection testing

#### **6. Infrastructure Scan (`infrastructure_scan`)**
Infrastructure and network security assessment:
- Subdomain enumeration
- Port scanning
- Service detection
- Vulnerability scanning

#### **7. Comprehensive Scan (`comprehensive_scan`)**
Complete security assessment using all available tools:
- All reconnaissance steps
- All vulnerability scanning
- All testing phases
- Complete reporting

### Advanced Usage

#### **Interactive Dashboard**
```bash
run dashboard
```
- Real-time monitoring
- System performance metrics
- Live scan statistics
- Interactive controls

#### **Configuration Management**
```bash
configure api-keys    # Configure API keys
configure tools       # Configure tool settings
configure profiles    # Manage scan profiles
configure show        # Show current configuration
```

#### **Tool Management**
```bash
tools install         # Install all tools
tools install <tool>  # Install specific tool
tools status          # Show tool status
tools list            # List available tools
```

## 📁 Output Structure

All results are stored in the `output/` directory with the following structure:

```
output/
├── reports/                 # Generated reports
│   ├── html/               # HTML reports
│   ├── json/               # JSON reports
│   └── pdf/                # PDF reports (if enabled)
├── scans/                  # Scan results
│   ├── subdomain/          # Subdomain enumeration results
│   ├── waybackurls/        # Historical URL results
│   ├── nuclei/             # Nuclei scan results
│   ├── nikto/              # Nikto scan results
│   ├── sqlmap/             # SQLMap scan results
│   └── advanced_tools/     # Advanced tools results
├── logs/                   # Application logs
│   ├── webraptor.log       # Main application log
│   ├── errors.log          # Error logs
│   └── debug.log           # Debug logs
├── config/                 # Configuration files
│   ├── webraptor_config.json
│   ├── secrets.encrypted
│   └── templates/
├── wordlists/              # Wordlists
│   ├── subdomains.txt
│   ├── directories.txt
│   └── passwords.txt
├── tools/                  # Installed tools
│   ├── sqlmap/
│   ├── nuclei/
│   └── ...
└── temp/                   # Temporary files
    ├── scans/
    └── downloads/
```

## 🔧 Configuration

### API Keys Configuration

WebRaptor supports multiple API services for enhanced reconnaissance:

```bash
configure api-keys
```

**Supported Services:**
- **Shodan** - Internet-connected device search
- **VirusTotal** - Malware and URL analysis
- **SecurityTrails** - DNS and domain intelligence
- **Censys** - Internet-wide scanning
- **GitHub** - Code repository search

### Tool Configuration

```bash
configure tools
```

**Configurable Parameters:**
- Timeout settings
- Thread counts
- Output formats
- Custom flags
- Rate limiting

### Scan Profiles

```bash
configure profiles
```

**Available Profiles:**
- **Quick** - Fast scanning (5 minutes)
- **Comprehensive** - Complete scanning (30 minutes)
- **Stealth** - Low-profile scanning (60 minutes)

## 🛡️ Security Features

### **Encrypted Storage**
- API keys encrypted with master password
- Secure configuration management
- Encrypted secrets storage

### **Rate Limiting**
- Configurable rate limits for all tools
- API rate limiting
- Request throttling

### **Error Handling**
- Comprehensive error logging
- Graceful failure handling
- Recovery mechanisms

## 📊 Reporting

### **HTML Reports**
- Interactive visualizations
- Charts and graphs
- Detailed findings
- Recommendations

### **JSON Reports**
- Machine-readable format
- API integration ready
- Structured data

### **Real-time Dashboard**
- Live monitoring
- System metrics
- Progress tracking
- Interactive controls

## 🔍 Tool Integration

### **Integrated Tools (50+)**

#### **Reconnaissance Tools**
- Nmap, Masscan, Zmap
- Subfinder, Amass, Assetfinder
- Findomain, Chaos, ShuffleDNS
- DNSx, DNSRecon, TheHarvester
- Sublist3r, Knockpy

#### **Web Application Testing**
- Nuclei, Nikto, SQLMap
- WFuzz, Dirb, Gobuster, FFuF
- WhatWeb, WAFW00F
- LinkFinder, SecretFinder, JSFinder
- ParamSpider, Arjun

#### **Web Crawling & Analysis**
- Katana, Unfurl, Qsreplace
- WaybackURLs, GAU
- Screenshot capture

#### **Vulnerability Scanners**
- OWASP ZAP, Burp Suite
- Custom vulnerability modules
- XSS, SQL injection testing

## 🚨 Troubleshooting

### **Common Issues**

#### **Tool Installation Issues**
```bash
# Check tool status
tools status

# Reinstall specific tool
tools install <tool_name>

# Check system requirements
tools check-requirements
```

#### **Permission Issues**
```bash
# Fix permissions
chmod +x tools/*

# Run with sudo if needed
sudo python main.py
```

#### **API Key Issues**
```bash
# Reconfigure API keys
configure api-keys

# Check API key status
configure show api-keys
```

#### **Memory Issues**
```bash
# Reduce thread count
configure tools

# Use stealth scan profile
workflow stealth_scan
```

### **Log Files**
- Check `output/logs/webraptor.log` for general issues
- Check `output/logs/errors.log` for error details
- Check `output/logs/debug.log` for debugging information

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details.

### **Development Setup**
```bash
# Fork the repository
git clone https://github.com/your-username/WebRaptor.git
cd WebRaptor

# Install development dependencies
pip install -r requirements-dev.txt

# Run tests
python -m pytest tests/

# Run linting
python -m flake8
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **ProjectDiscovery** - For amazing security tools
- **OWASP** - For security testing methodologies
- **Bug Bounty Community** - For feedback and contributions
- **Open Source Community** - For the amazing tools we integrate

## 📞 Support

- **Documentation**: [Wiki](https://github.com/letchu_pkt/WebRaptor/wiki)
- **Issues**: [GitHub Issues](https://github.com/letchu_pkt/WebRaptor/issues)
- **Discussions**: [GitHub Discussions](https://github.com/letchu_pkt/WebRaptor/discussions)
- **Email**: letchupkt.dev@gmail.com

## 🔗 Links

- **GitHub**: https://github.com/letchu_pkt/WebRaptor
- **Website**: https://letchupkt.vgrow.tech
- **LinkedIn**: https://linkedin.com/in/lakshmikanthank
- **Instagram**: https://instagram.com/letchu_pkt
---

**⚠️ Disclaimer**: This tool is for educational and authorized testing purposes only. Users are responsible for complying with applicable laws and regulations. The authors are not responsible for any misuse of this tool.

**Made with ❤️ by [LakshmikanthanK](https://github.com/letchu_pkt)**

