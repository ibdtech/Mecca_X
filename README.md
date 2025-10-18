# Mecca-_X
penetration testing framework with automated vulnerability assessment, exploit validation, network mapping, and continuous monitoring. Parallel processing, real-time threat intelligence, and bug bounty report generation.



# Mecca X - Advanced Penetration Testing Framework

![Version](https://img.shields.io/badge/version-1.0-blue)
![Python](https://img.shields.io/badge/python-3.8+-green)
![License](https://img.shields.io/badge/license-MIT-orange)

> Next-generation penetration testing framework with automated vulnerability assessment, exploit validation, and continuous monitoring - 100% FREE.

## 📸 Screenshots

### Main Menu
![Mecca X Main Menu](screenshots/main_menu.png)
*Clean, organized interface with categorized options*

### Full Menu Options
![Mecca X Full Menu](screenshots/full_menu.png)
*All features: Passive Recon, Active Scanning, Exploitation, Monitoring & Reporting*

## 🎯 What It Does

Mecca X is an innovative all-in-one security testing platform that combines:

- **Passive Reconnaissance** - Discovers hidden subdomains without touching the target
- **Vulnerability Scanning** - Deep scans for security holes with real-time CVE matching
- **Active Exploitation Check** - Validates if vulnerabilities are being exploited in the wild
- **Network Mapping** - Scans entire networks and builds attack graphs showing pivot paths
- **Auto-Exploitation** - Safely validates vulnerabilities with proof-of-concept tests
- **Continuous Monitoring** - Runs scheduled scans and alerts on NEW vulnerabilities
- **Bug Bounty Reports** - Auto-generates professional reports with bounty estimates

## 🚀 Key Features

### Speed & Innovation
- **3-5x faster** than traditional tools using parallel processing
- **50 concurrent DNS checks** for rapid subdomain validation
- **4 data sources** running simultaneously (Subfinder, Amass, crt.sh, HackerTarget)
- **Auto-identifies high-value targets** (admin, api, dev, staging subdomains)

### Intelligence & Automation
- **Real-time threat intelligence** from CISA's Known Exploited Vulnerabilities database
- **Automated exploit matching** to Metasploit modules and Exploit-DB
- **Attack chain detection** showing lateral movement opportunities
- **Smart prioritization** based on exploitability and impact

### Professional Output
- **Executive summaries** for non-technical stakeholders
- **Bug bounty formatted reports** with estimated reward values
- **Continuous monitoring** with change detection and alerts

## 📋 Requirements

### System Requirements
- **OS**: Linux (Kali, Parrot, Ubuntu, Debian)
- **Python**: 3.8 or higher
- **Privileges**: sudo/root access (for nmap scans)

### Required Tools
```bash
# Install system tools
sudo apt update
sudo apt install nmap amass -y

# Install Go (for subfinder)
wget https://go.dev/dl/go1.21.0.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.21.0.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc

# Install subfinder
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
export PATH=$PATH:~/go/bin
echo 'export PATH=$PATH:~/go/bin' >> ~/.bashrc
```

### Optional Tools (Recommended)
```bash
# For exploit database integration
sudo apt install exploitdb -y

# For Metasploit integration
curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall
chmod 755 msfinstall
./msfinstall
```

## 🔧 Installation

### Method 1: Quick Install (Recommended)
```bash
# Clone the repository
git clone https://github.com/ibdtech/mecca-x.git
cd mecca-x

# Install Python dependencies
sudo apt install python3-requests python3-termcolor python3-pyfiglet python3-schedule -y

# Run the tool
python3 mecca_x.py
```

### Method 2: Virtual Environment
```bash
# Clone the repository
git clone https://github.com/ibdtech/mecca-x.git
cd mecca-x

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run the tool
python3 mecca_x.py
```

## 📦 Python Dependencies

Create a `requirements.txt` file:
```
requests>=2.28.0
termcolor>=2.0.0
pyfiglet>=0.8.0
schedule>=1.1.0
```

## 🎮 Usage

### Basic Usage
```bash
python3 mecca_x.py
```

### Menu Options

**1. Subdomain Enumeration (PASSIVE)**
```
Discovers subdomains using 4 parallel sources
- No direct contact with target
- 3-minute timeout per tool
- Auto-identifies high-value targets
```

**2. Vulnerability Scan (ACTIVE)**
```
Deep vulnerability assessment with:
- Nmap service detection
- CVE database matching
- Active exploitation checks
- Exploit availability verification
```

**3. Network Mapping (ACTIVE)**
```
Full network reconnaissance:
- Live host discovery
- Service enumeration
- Attack graph generation
- Lateral movement paths
```

**4. Auto-Exploitation (SAFE MODE)**
```
Non-destructive validation:
- Proof-of-concept testing
- Banner grabbing
- Service verification
- Exploitation confirmation
```

**5. Continuous Monitoring**
```
Scheduled scanning:
- Automated periodic scans
- Change detection
- New vulnerability alerts
- Historical tracking
```

**6. Bug Bounty Report Generation**
```
Professional reports with:
- CVSS-based severity ratings
- Exploitation steps
- Remediation guidance
- Bounty estimates
```

## 📖 Examples

### Example 1: Subdomain Enumeration
```bash
python3 mecca_x.py
# Choose option 1
# Enter domain: example.com
# Results saved to: subdomains.txt & live_subdomains.txt
```

### Example 2: Vulnerability Scan
```bash
python3 mecca_x.py
# Choose option 2
# Enter target: 192.168.1.100
# Results saved to: vuln_scan_results.txt
```

### Example 3: Network Mapping
```bash
python3 mecca_x.py
# Choose option 3
# Enter range: 192.168.1.0/24
# Results saved to: network_map.json
```

### Example 4: Continuous Monitoring
```bash
python3 mecca_x.py
# Choose option 5
# Enter target: example.com
# Enter interval: 24 (hours)
# Scans will run automatically every 24 hours
```

## 📂 Output Files

| File | Description |
|------|-------------|
| `subdomains.txt` | All discovered subdomains |
| `live_subdomains.txt` | Live subdomains with IP addresses |
| `vuln_scan_results.txt` | Detailed vulnerability report |
| `vuln_scan_results.json` | Machine-readable vulnerability data |
| `network_map.json` | Network topology and attack graphs |
| `exploitation_results.json` | Validated exploits with proof |
| `bug_bounty_report.md` | Professional bug bounty submission |

## ⚠️ Legal Disclaimer

**IMPORTANT:** This tool is for educational and authorized security testing only.

- ✅ **DO**: Use on systems you own or have explicit written permission to test
- ✅ **DO**: Use for authorized penetration testing engagements
- ✅ **DO**: Use for bug bounty programs with proper scope
- ❌ **DON'T**: Use on systems without authorization
- ❌ **DON'T**: Use for illegal activities
- ❌ **DON'T**: Use to cause harm or damage

**You are responsible for your actions. Unauthorized access to computer systems is illegal.**

## 🛡️ Responsible Disclosure

If you discover vulnerabilities using this tool:
1. Report to the organization's security team first
2. Allow reasonable time for patching (90 days standard)
3. Do not publicly disclose until patched
4. Follow bug bounty program rules if applicable

## 🔒 Safety Features

- **Safe Mode Exploitation** - Non-destructive validation only
- **Timeout Controls** - Prevents hanging on unresponsive targets
- **Error Handling** - Graceful failure without system impact
- **Rate Limiting** - Respects target resources

## 🤝 Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📝 Roadmap

- [ ] Web interface dashboard
- [ ] Docker containerization
- [ ] Additional CVE database sources
- [ ] AI-powered vulnerability analysis
- [ ] Integration with security SIEM tools
- [ ] Mobile app for monitoring

## 🐛 Known Issues

- Amass may be slow on first run (building database)
- Some CVE APIs rate-limit requests
- Nmap requires root/sudo privileges

## 💬 Support

- **Issues**: [GitHub Issues](https://github.com/ibdtech/mecca-x/issues)
- **Discussions**: [GitHub Discussions](https://github.com/ibdtech/mecca-x/discussions)

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **ProjectDiscovery** - Subfinder tool
- **OWASP** - Amass tool
- **NIST** - National Vulnerability Database
- **CISA** - Known Exploited Vulnerabilities catalog
- **Offensive Security** - Exploit Database

## 📊 Why Mecca X?

### Innovation
- First free tool combining real-time threat intelligence with automated exploit validation
- Parallel processing for 3-5x speed improvement
- Smart target prioritization based on exploitability

### Accuracy
- Multiple data sources for comprehensive coverage
- Cross-references 4+ vulnerability databases
- Active exploitation status from CISA KEV

### Professional Grade
- Enterprise-level reporting
- Bug bounty ready output
- Continuous monitoring capabilities

---

**Made with ❤️ for the security community**

*Star ⭐ this repository if you find it useful!*
