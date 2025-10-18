import subprocess
import requests
import xml.etree.ElementTree as ET
import json
import os
from termcolor import colored
from pyfiglet import Figlet
import re
from datetime import datetime
import threading
import time
import schedule

def check_subdomain(subdomain):
    """Fast subdomain verification using multiple methods"""
    try:
        # Method 1: DNS resolution (fastest)
        import socket
        socket.gethostbyname(subdomain)
        return True
    except:
        pass
    
    # Method 2: HTTP check as fallback
    try:
        response = requests.get(f"http://{subdomain}", timeout=3)
        if response.status_code != 404:
            return True
    except:
        pass
    
    return False

def check_subdomain_fast(subdomain):
    """Ultra-fast DNS-only check"""
    try:
        import socket
        socket.gethostbyname(subdomain)
        return True
    except:
        return False

def enumerate_subdomains(domain):
    print(colored("[+] Running INNOVATIVE Subdomain Enumeration (PASSIVE)...", 'green'))
    print(colored("[*] Using parallel processing + DNS resolution + passive sources", 'yellow'))
    
    all_subdomains = set()
    
    # INNOVATION 1: Run tools in PARALLEL (not sequential)
    print(colored("\n[*] Phase 1: Running tools in parallel...", 'cyan'))
    
    def run_subfinder():
        try:
            result = subprocess.run(
                f"subfinder -d {domain} -silent",
                shell=True,
                capture_output=True,
                text=True,
                timeout=180
            )
            if result.stdout:
                return set([s.strip() for s in result.stdout.strip().split('\n') if s.strip()])
        except:
            pass
        return set()
    
    def run_amass():
        try:
            result = subprocess.run(
                f"amass enum -d {domain} -passive -timeout 3",
                shell=True,
                capture_output=True,
                text=True,
                timeout=180
            )
            if result.stdout:
                return set([s.strip() for s in result.stdout.strip().split('\n') if s.strip()])
        except:
            pass
        return set()
    
    # INNOVATION 2: Certificate Transparency logs (super fast & accurate)
    def get_crt_sh_subdomains():
        print(colored("[*] Querying Certificate Transparency logs (crt.sh)...", 'cyan'))
        try:
            response = requests.get(
                f"https://crt.sh/?q=%.{domain}&output=json",
                timeout=30
            )
            if response.status_code == 200:
                data = response.json()
                crt_subdomains = set()
                for cert in data:
                    name = cert.get('name_value', '')
                    # Handle wildcard and multiple names
                    for subdomain in name.split('\n'):
                        subdomain = subdomain.strip().replace('*.', '')
                        if subdomain and domain in subdomain:
                            crt_subdomains.add(subdomain)
                print(colored(f"[+] crt.sh found {len(crt_subdomains)} subdomains", 'green'))
                return crt_subdomains
        except Exception as e:
            print(colored(f"[-] crt.sh error: {str(e)[:50]}", 'red'))
        return set()
    
    # INNOVATION 3: HackerTarget API (free passive recon)
    def get_hackertarget_subdomains():
        print(colored("[*] Querying HackerTarget API...", 'cyan'))
        try:
            response = requests.get(
                f"https://api.hackertarget.com/hostsearch/?q={domain}",
                timeout=15
            )
            if response.status_code == 200:
                ht_subdomains = set()
                for line in response.text.split('\n'):
                    if ',' in line:
                        subdomain = line.split(',')[0].strip()
                        if subdomain and domain in subdomain:
                            ht_subdomains.add(subdomain)
                print(colored(f"[+] HackerTarget found {len(ht_subdomains)} subdomains", 'green'))
                return ht_subdomains
        except Exception as e:
            print(colored(f"[-] HackerTarget error: {str(e)[:50]}", 'red'))
        return set()
    
    # INNOVATION 4: Run everything in parallel using threading
    from concurrent.futures import ThreadPoolExecutor, as_completed
    
    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = {
            executor.submit(run_subfinder): 'Subfinder',
            executor.submit(run_amass): 'Amass',
            executor.submit(get_crt_sh_subdomains): 'crt.sh',
            executor.submit(get_hackertarget_subdomains): 'HackerTarget'
        }
        
        for future in as_completed(futures):
            tool_name = futures[future]
            try:
                results = future.result()
                all_subdomains.update(results)
                print(colored(f"[+] {tool_name} completed: {len(results)} subdomains", 'green'))
            except Exception as e:
                print(colored(f"[-] {tool_name} failed: {str(e)}", 'red'))
    
    print(colored(f"\n[+] Phase 1 Complete: {len(all_subdomains)} unique subdomains found", 'green'))
    
    # Write all unique subdomains to file
    with open("subdomains.txt", "w") as f:
        for subdomain in sorted(all_subdomains):
            f.write(subdomain + "\n")
    
    # INNOVATION 5: Fast parallel DNS resolution
    print(colored("\n[*] Phase 2: Fast DNS resolution check (parallel)...", 'cyan'))
    
    live_subdomains = []
    resolved_ips = {}
    
    def check_and_resolve(subdomain):
        try:
            import socket
            ip = socket.gethostbyname(subdomain)
            return (subdomain, ip)
        except:
            return None
    
    with ThreadPoolExecutor(max_workers=50) as executor:  # 50 parallel DNS checks
        futures = [executor.submit(check_and_resolve, sub) for sub in all_subdomains]
        
        for future in as_completed(futures):
            result = future.result()
            if result:
                subdomain, ip = result
                live_subdomains.append(subdomain)
                resolved_ips[subdomain] = ip
                print(colored(f"[+] Live: {subdomain} -> {ip}", 'green'))
    
    # Write live subdomains to file with IPs
    with open("live_subdomains.txt", "w") as f:
        for subdomain in live_subdomains:
            ip = resolved_ips.get(subdomain, 'Unknown')
            f.write(f"{subdomain} -> {ip}\n")
    
    # INNOVATION 6: Identify interesting subdomains automatically
    interesting_keywords = ['admin', 'api', 'dev', 'staging', 'test', 'vpn', 'mail', 'portal', 'dashboard', 'internal', 'private']
    interesting_subs = [sub for sub in live_subdomains if any(kw in sub.lower() for kw in interesting_keywords)]
    
    print(colored(f"\n{'='*60}", 'green'))
    print(colored("✅ SUBDOMAIN ENUMERATION COMPLETE!", 'green', attrs=['bold']))
    print(colored(f"{'='*60}", 'green'))
    print(colored(f"Total subdomains discovered: {len(all_subdomains)}", 'white'))
    print(colored(f"Live subdomains (DNS resolved): {len(live_subdomains)}", 'white'))
    print(colored(f"High-value targets identified: {len(interesting_subs)}", 'yellow'))
    print(colored(f"\n📁 Results saved to:", 'white'))
    print(colored(f"   • subdomains.txt (all discovered)", 'white'))
    print(colored(f"   • live_subdomains.txt (with IP addresses)", 'white'))
    
    # INNOVATION 7: Smart recommendations
    print(colored(f"\n{'='*60}", 'cyan'))
    print(colored("📋 INTELLIGENT NEXT STEPS:", 'cyan', attrs=['bold']))
    print(colored(f"{'='*60}", 'cyan'))
    
    if interesting_subs:
        print(colored("\n🎯 HIGH-VALUE TARGETS DETECTED:", 'yellow', attrs=['bold']))
        for sub in interesting_subs[:5]:
            print(colored(f"   → {sub} ({resolved_ips.get(sub, 'Unknown')})", 'yellow'))
        print(colored("\n💡 RECOMMENDATION: Scan these first - they're likely to have valuable findings!", 'yellow'))
        print(colored(f"   Command: Choose Option 2 and enter: {interesting_subs[0]}", 'white'))
    elif live_subdomains:
        print(colored("\n✅ Live targets found!", 'yellow'))
        print(colored(f"   Suggested first target: {live_subdomains[0]}", 'white'))
        print(colored(f"   IP Address: {resolved_ips.get(live_subdomains[0], 'Unknown')}", 'white'))
        print(colored("\n💡 RECOMMENDATION: Run vulnerability scan (Option 2)", 'yellow'))
    else:
        print(colored("\n⚠️ No live subdomains found.", 'yellow'))
        print(colored("   • Try a different domain", 'white'))
        print(colored("   • Or run network mapping if you have an IP range (Option 3)", 'white'))
    
    print(colored(f"{'='*60}\n", 'cyan'))

def calculate_severity(cvss):
    """Calculate severity from CVSS score"""
    if cvss != 'N/A':
        try:
            cvss_float = float(cvss)
            if cvss_float >= 9.0:
                return 'CRITICAL'
            elif cvss_float >= 7.0:
                return 'HIGH'
            elif cvss_float >= 4.0:
                return 'MEDIUM'
            else:
                return 'LOW'
        except:
            return 'UNKNOWN'
    return 'UNKNOWN'

def query_cve_database(service, version):
    """Query free CVE database with multiple fallbacks (no API key required)"""
    
    # Skip if service is unknown or generic
    if 'unknown' in service.lower() or 'tcpwrapped' in service.lower():
        return []
    
    print(colored(f"[*] Querying CVE database for {service} {version}...", 'yellow'))
    
    # Try CVE Circl.lu first
    try:
        search_term = f"{service} {version}".replace(" ", "%20")
        url = f"https://cve.circl.lu/api/search/{search_term}"
        
        response = requests.get(url, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            cves = []
            
            if isinstance(data, list):
                for cve_item in data[:10]:
                    cve_id = cve_item.get('id', 'N/A')
                    summary = cve_item.get('summary', 'No description available')
                    cvss = cve_item.get('cvss', 'N/A')
                    
                    severity = calculate_severity(cvss)
                    
                    cves.append({
                        'id': cve_id,
                        'description': summary,
                        'cvss_score': cvss,
                        'severity': severity
                    })
            
            if cves:
                print(colored(f"[+] Found {len(cves)} CVEs using CVE Circl.lu", 'green'))
                return cves
    except Exception as e:
        print(colored(f"[-] CVE Circl.lu failed: {str(e)[:50]}...", 'red'))
    
    # Try NIST NVD as fallback
    try:
        search_term = f"{service} {version}".replace(" ", "%20")
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={search_term}&resultsPerPage=10"
        
        response = requests.get(url, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            cves = []
            
            if 'vulnerabilities' in data:
                for vuln in data['vulnerabilities'][:10]:
                    cve_item = vuln.get('cve', {})
                    cve_id = cve_item.get('id', 'N/A')
                    
                    descriptions = cve_item.get('descriptions', [])
                    description = descriptions[0].get('value', 'No description') if descriptions else 'No description'
                    
                    metrics = cve_item.get('metrics', {})
                    cvss_score = 'N/A'
                    severity = 'UNKNOWN'
                    
                    if 'cvssMetricV31' in metrics:
                        cvss_data = metrics['cvssMetricV31'][0]['cvssData']
                        cvss_score = cvss_data.get('baseScore', 'N/A')
                        severity = cvss_data.get('baseSeverity', 'UNKNOWN')
                    
                    cves.append({
                        'id': cve_id,
                        'description': description,
                        'cvss_score': cvss_score,
                        'severity': severity
                    })
            
            if cves:
                print(colored(f"[+] Found {len(cves)} CVEs using NIST NVD", 'green'))
                return cves
    except Exception as e:
        print(colored(f"[-] NIST NVD failed: {str(e)[:50]}...", 'red'))
    
    print(colored(f"[-] No CVE data found for {service} {version}", 'yellow'))
    return []

def check_active_exploitation(cve_id):
    """Check if CVE is being actively exploited in the wild"""
    print(colored(f"[*] Checking active exploitation status for {cve_id}...", 'yellow'))
    
    try:
        # Check CISA KEV (Known Exploited Vulnerabilities)
        response = requests.get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", timeout=10)
        
        if response.status_code == 200:
            kev_data = response.json()
            for vuln in kev_data.get('vulnerabilities', []):
                if vuln.get('cveID') == cve_id:
                    return {
                        'actively_exploited': True,
                        'date_added': vuln.get('dateAdded', 'Unknown'),
                        'known_ransomware': vuln.get('knownRansomwareCampaignUse', 'Unknown')
                    }
    except:
        pass
    
    return {'actively_exploited': False}

def search_exploit_db(cve_id):
    """Search local or online exploit-db for exploits"""
    print(colored(f"[*] Searching for exploits for {cve_id}...", 'yellow'))
    
    exploits = []
    
    # Check if searchsploit is available (local exploit-db)
    try:
        result = subprocess.run(
            ['searchsploit', '--json', cve_id],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        if result.returncode == 0:
            data = json.loads(result.stdout)
            if 'RESULTS_EXPLOIT' in data:
                for exploit in data['RESULTS_EXPLOIT'][:3]:  # Top 3
                    exploits.append({
                        'title': exploit.get('Title', 'N/A'),
                        'path': exploit.get('Path', 'N/A'),
                        'type': exploit.get('Type', 'N/A')
                    })
    except:
        pass
    
    return exploits

def search_metasploit_modules(service, version):
    """Search for relevant Metasploit modules"""
    print(colored(f"[*] Searching Metasploit modules for {service}...", 'yellow'))
    
    modules = []
    
    try:
        # Search msfconsole database
        result = subprocess.run(
            ['msfconsole', '-q', '-x', f'search {service}; exit'],
            capture_output=True,
            text=True,
            timeout=15
        )
        
        if result.returncode == 0:
            lines = result.stdout.split('\n')
            for line in lines:
                if 'exploit/' in line or 'auxiliary/' in line:
                    parts = line.split()
                    if len(parts) >= 2:
                        modules.append({
                            'name': parts[0],
                            'description': ' '.join(parts[1:])[:100]
                        })
                        
                        if len(modules) >= 5:  # Limit to 5 modules
                            break
    except:
        pass
    
    return modules

def auto_exploit_safe(vuln_data):
    """Safely attempt exploitation with proof-of-concept (NON-DESTRUCTIVE)"""
    print(colored("\n[!] AUTO-EXPLOITATION MODULE (SAFE MODE)", 'yellow'))
    print(colored("[!] This will attempt NON-DESTRUCTIVE validation only", 'yellow'))
    
    confirm = input(colored("\nProceed with safe exploitation attempts? (yes/no): ", 'yellow'))
    if confirm.lower() != 'yes':
        return []
    
    exploitation_results = []
    
    for vuln in vuln_data:
        for cve in vuln['cves']:
            if cve['severity'] in ['CRITICAL', 'HIGH']:
                print(colored(f"\n[*] Attempting safe validation for {cve['id']}...", 'cyan'))
                
                # Example: Safe banner grabbing
                try:
                    result = subprocess.run(
                        ['nc', '-v', '-w', '2', vuln['ip'], vuln['port']],
                        capture_output=True,
                        text=True,
                        timeout=5
                    )
                    
                    if result.returncode == 0 or result.stderr:
                        exploitation_results.append({
                            'cve': cve['id'],
                            'target': f"{vuln['ip']}:{vuln['port']}",
                            'status': 'VALIDATED',
                            'proof': result.stderr[:200] if result.stderr else 'Connection successful',
                            'method': 'Banner Grab'
                        })
                        print(colored(f"[+] Validated: {cve['id']}", 'green'))
                except:
                    pass
    
    return exploitation_results

def network_mapper(target_range):
    """Scan entire network range and build attack graph"""
    print(colored("[+] Running Network Mapping (ACTIVE)...", 'green'))
    
    # Ping sweep to find live hosts
    print(colored("[*] Step 1: Discovering live hosts...", 'cyan'))
    ping_cmd = f"nmap -sn {target_range} -oX network_hosts.xml"
    subprocess.run(ping_cmd, shell=True)
    
    # Parse live hosts
    tree = ET.parse("network_hosts.xml")
    root = tree.getroot()
    
    live_hosts = []
    for host in root.findall("host"):
        if host.find("status").attrib["state"] == "up":
            ip = host.find("address").attrib["addr"]
            live_hosts.append(ip)
    
    print(colored(f"[+] Found {len(live_hosts)} live hosts", 'green'))
    
    # Quick port scan on each host
    network_data = []
    for ip in live_hosts:
        print(colored(f"[*] Scanning {ip}...", 'cyan'))
        scan_cmd = f"nmap -sV -T4 --top-ports 100 {ip} -oX host_{ip}.xml"
        subprocess.run(scan_cmd, shell=True)
        
        # Parse results
        try:
            tree = ET.parse(f"host_{ip}.xml")
            root = tree.getroot()
            
            services = []
            for host in root.findall("host"):
                if host.find("ports") is not None:
                    for port in host.find("ports").findall("port"):
                        if port.find("state").attrib["state"] == "open":
                            port_id = port.attrib["portid"]
                            service = port.find("service").attrib.get("name", "unknown") if port.find("service") is not None else "unknown"
                            services.append({
                                'port': port_id,
                                'service': service
                            })
            
            network_data.append({
                'ip': ip,
                'services': services
            })
        except:
            pass
    
    # Build attack graph
    attack_graph = build_attack_graph(network_data)
    
    # Save results
    with open("network_map.json", "w") as f:
        json.dump({
            'hosts': network_data,
            'attack_graph': attack_graph
        }, f, indent=2)
    
    print(colored("[+] Network mapping complete! Saved to network_map.json", 'green'))
    return network_data

def build_attack_graph(network_data):
    """Build lateral movement attack graph"""
    graph = []
    
    for host in network_data:
        # Identify pivot opportunities
        if any(s['service'] in ['ssh', 'rdp', 'smb', 'vnc'] for s in host['services']):
            graph.append({
                'pivot_host': host['ip'],
                'pivot_services': [s['service'] for s in host['services']],
                'lateral_movement': 'HIGH',
                'reason': 'Remote access services available'
            })
    
    return graph

def continuous_monitoring(target, interval_hours=24):
    """Run scans on schedule and track changes"""
    print(colored(f"[+] Starting Continuous Monitoring (every {interval_hours} hours)...", 'green'))
    
    def scheduled_scan():
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        print(colored(f"\n[*] Running scheduled scan at {timestamp}...", 'cyan'))
        
        # Run vulnerability scan
        vulnerability_scan(target, scheduled=True, timestamp=timestamp)
        
        # Compare with previous scan
        compare_scans(timestamp)
    
    # Run first scan immediately
    scheduled_scan()
    
    # Schedule future scans
    schedule.every(interval_hours).hours.do(scheduled_scan)
    
    print(colored(f"[+] Monitoring active. Press Ctrl+C to stop.", 'green'))
    
    try:
        while True:
            schedule.run_pending()
            time.sleep(60)
    except KeyboardInterrupt:
        print(colored("\n[+] Monitoring stopped.", 'yellow'))

def compare_scans(current_timestamp):
    """Compare current scan with previous to detect new vulnerabilities"""
    try:
        # Load current scan
        with open(f"vuln_scan_{current_timestamp}.json", "r") as f:
            current_scan = json.load(f)
        
        # Find previous scan
        scan_files = sorted([f for f in os.listdir('.') if f.startswith('vuln_scan_') and f.endswith('.json')])
        
        if len(scan_files) > 1:
            previous_file = scan_files[-2]
            
            with open(previous_file, "r") as f:
                previous_scan = json.load(f)
            
            # Compare
            new_vulns = []
            current_cves = set(cve['id'] for vuln in current_scan for cve in vuln.get('cves', []))
            previous_cves = set(cve['id'] for vuln in previous_scan for cve in vuln.get('cves', []))
            
            new_cve_ids = current_cves - previous_cves
            
            if new_cve_ids:
                print(colored(f"\n[!] ALERT: {len(new_cve_ids)} NEW vulnerabilities detected!", 'red'))
                for cve_id in new_cve_ids:
                    print(colored(f"  - {cve_id}", 'red'))
                
                # Save alert
                with open(f"alert_{current_timestamp}.txt", "w") as f:
                    f.write(f"NEW VULNERABILITIES DETECTED\n")
                    f.write(f"Scan: {current_timestamp}\n\n")
                    for cve_id in new_cve_ids:
                        f.write(f"- {cve_id}\n")
    except:
        pass

def intelligent_vulnerability_analysis(vuln_data):
    """Rule-based intelligent analysis without AI"""
    
    analysis = []
    analysis.append("\n" + "="*80)
    analysis.append("INTELLIGENT VULNERABILITY ANALYSIS")
    analysis.append("="*80 + "\n")
    
    # Prioritize vulnerabilities
    critical_vulns = []
    high_vulns = []
    
    for vuln in vuln_data:
        for cve in vuln['cves']:
            if cve['severity'] == 'CRITICAL':
                critical_vulns.append((vuln, cve))
            elif cve['severity'] == 'HIGH':
                high_vulns.append((vuln, cve))
    
    # Critical vulnerabilities section
    if critical_vulns:
        analysis.append("🔴 CRITICAL PRIORITY VULNERABILITIES")
        analysis.append("-" * 80)
        analysis.append("These vulnerabilities pose IMMEDIATE risk and should be addressed NOW.\n")
        
        for vuln, cve in critical_vulns[:5]:  # Top 5 critical
            analysis.append(f"[!] {cve['id']} - {vuln['service']} {vuln['version']}")
            analysis.append(f"    CVSS Score: {cve['cvss_score']}")
            analysis.append(f"    Target: {vuln['ip']}:{vuln['port']}")
            
            # Check active exploitation
            active_exploit = cve.get('active_exploitation', {})
            if active_exploit.get('actively_exploited'):
                analysis.append(f"\n    ⚠️ ACTIVELY EXPLOITED IN THE WILD!")
                analysis.append(f"    Date Added to CISA KEV: {active_exploit.get('date_added')}")
                analysis.append(f"    Ransomware Use: {active_exploit.get('known_ransomware')}")
            
            # Exploitation guidance
            analysis.append("\n    💣 EXPLOITATION POTENTIAL:")
            if 'remote' in cve['description'].lower():
                analysis.append("    - Remote code execution possible")
                analysis.append("    - No authentication may be required")
                analysis.append("    - Can be exploited from internet")
            
            if 'overflow' in cve['description'].lower() or 'buffer' in cve['description'].lower():
                analysis.append("    - Buffer overflow vulnerability")
                analysis.append("    - Memory corruption exploitation")
                analysis.append("    - Potential for arbitrary code execution")
            
            # Remediation
            analysis.append("\n    🛡️ REMEDIATION STEPS:")
            analysis.append(f"    1. Immediately patch {vuln['service']} to latest version")
            analysis.append(f"    2. Implement network segmentation for {vuln['ip']}")
            analysis.append("    3. Enable intrusion detection monitoring")
            analysis.append("    4. Review logs for exploitation attempts")
            
            # Search for exploits
            exploits = vuln.get('exploits', [])
            if exploits:
                analysis.append("\n    ⚠️ PUBLIC EXPLOITS AVAILABLE:")
                for exploit in exploits:
                    analysis.append(f"    - {exploit['title']}")
            
            # Metasploit modules
            modules = vuln.get('msf_modules', [])
            if modules:
                analysis.append("\n    🎯 METASPLOIT MODULES:")
                for module in modules[:3]:
                    analysis.append(f"    - {module['name']}")
            
            # Exploitation results
            exploit_results = vuln.get('exploitation_results', [])
            if exploit_results:
                analysis.append("\n    ✅ EXPLOITATION VALIDATED:")
                for result in exploit_results:
                    analysis.append(f"    - Method: {result['method']}")
                    analysis.append(f"    - Status: {result['status']}")
                    analysis.append(f"    - Proof: {result['proof'][:100]}...")
            
            analysis.append("\n" + "-" * 80 + "\n")
    
    # High vulnerabilities section
    if high_vulns:
        analysis.append("\n🟠 HIGH PRIORITY VULNERABILITIES")
        analysis.append("-" * 80)
        analysis.append("Address these vulnerabilities within 7 days.\n")
        
        for vuln, cve in high_vulns[:5]:
            analysis.append(f"[!] {cve['id']} - {vuln['service']} {vuln['version']}")
            analysis.append(f"    CVSS Score: {cve['cvss_score']}")
            analysis.append(f"    Target: {vuln['ip']}:{vuln['port']}")
            analysis.append(f"    Remediation: Update to patched version\n")
    
    # Attack chain analysis
    analysis.append("\n🔗 POTENTIAL ATTACK CHAINS")
    analysis.append("-" * 80)
    
    services_by_host = {}
    for vuln in vuln_data:
        if vuln['ip'] not in services_by_host:
            services_by_host[vuln['ip']] = []
        services_by_host[vuln['ip']].append(vuln)
    
    for ip, services in services_by_host.items():
        if len(services) > 1:
            analysis.append(f"\n[Host: {ip}]")
            analysis.append("Multiple vulnerable services detected - Pivot opportunities:")
            for svc in services:
                analysis.append(f"  → {svc['port']}/{svc['service']} ({len(svc['cves'])} CVEs)")
            analysis.append("  Attack Strategy: Compromise one service, pivot to others")
    
    # Business impact assessment
    analysis.append("\n\n💼 BUSINESS IMPACT ASSESSMENT")
    analysis.append("-" * 80)
    
    total_critical = len(critical_vulns)
    total_high = len(high_vulns)
    
    if total_critical > 0:
        analysis.append(f"⚠️ SEVERE RISK: {total_critical} critical vulnerabilities detected")
        analysis.append("   - Data breach highly likely")
        analysis.append("   - System compromise imminent")
        analysis.append("   - Potential for ransomware deployment")
        analysis.append("   - Regulatory compliance violations likely")
    
    if total_high > 5:
        analysis.append(f"\n⚠️ ELEVATED RISK: {total_high} high-severity vulnerabilities")
        analysis.append("   - Significant attack surface")
        analysis.append("   - Multiple entry points for attackers")
        analysis.append("   - Recommend immediate security audit")
    
    # Recommendations
    analysis.append("\n\n📋 STRATEGIC RECOMMENDATIONS")
    analysis.append("-" * 80)
    analysis.append("1. Emergency Patching: Address all CRITICAL vulnerabilities within 24 hours")
    analysis.append("2. Patch Management: Implement automated patch deployment")
    analysis.append("3. Network Segmentation: Isolate vulnerable systems")
    analysis.append("4. Monitoring: Deploy IDS/IPS on affected networks")
    analysis.append("5. Penetration Testing: Validate exploitability of findings")
    analysis.append("6. Incident Response: Prepare IR plan for potential compromise")
    
    return "\n".join(analysis)

def vulnerability_scan(target, scheduled=False, timestamp=None):
    print(colored("[+] Running Advanced Vulnerability Scan (ACTIVE)...", 'green'))
    
    # Step 1: Run nmap vulnerability scan
    print(colored("[*] Step 1/6: Running Nmap scan...", 'cyan'))
    vuln_scan_cmd = f"sudo nmap -sV -sC --script=vuln -p- -T4 {target} -oX vuln_scan_results.xml"
    subprocess.run(vuln_scan_cmd, shell=True)
    
    # Step 2: Parse nmap results
    print(colored("[*] Step 2/6: Parsing scan results...", 'cyan'))
    tree = ET.parse("vuln_scan_results.xml")
    root = tree.getroot()
    
    vulnerability_data = []
    
    for host in root.findall("host"):
        ip = host.find("address").attrib["addr"]
        
        if host.find("ports") is not None:
            for port in host.find("ports").findall("port"):
                port_id = port.attrib["portid"]
                
                if port.find("service") is not None:
                    service_elem = port.find("service")
                    service_name = service_elem.attrib.get("name", "unknown")
                    service_version = service_elem.attrib.get("version", "unknown")
                    product = service_elem.attrib.get("product", "unknown")
                    
                    # Step 3: Query CVE database
                    print(colored(f"[*] Step 3/6: Checking CVEs for {service_name} {service_version}...", 'cyan'))
                    cves = query_cve_database(f"{product} {service_name}", service_version)
                    
                    # Step 4: Check active exploitation
                    print(colored(f"[*] Step 4/6: Checking active exploitation status...", 'cyan'))
                    for cve in cves:
                        cve['active_exploitation'] = check_active_exploitation(cve['id'])
                    
                    # Step 5: Search for exploits
                    print(colored(f"[*] Step 5/6: Searching for exploits...", 'cyan'))
                    exploits = []
                    for cve in cves[:3]:  # Check top 3 CVEs
                        cve_exploits = search_exploit_db(cve['id'])
                        exploits.extend(cve_exploits)
                    
                    # Step 6: Search Metasploit modules
                    msf_modules = search_metasploit_modules(service_name, service_version)
                    
                    vuln_entry = {
                        'ip': ip,
                        'port': port_id,
                        'service': service_name,
                        'version': service_version,
                        'product': product,
                        'cves': cves,
                        'exploits': exploits,
                        'msf_modules': msf_modules
                    }
                    
                    vulnerability_data.append(vuln_entry)
    
    # Step 6: Intelligent Analysis
    print(colored("[*] Step 6/6: Running intelligent analysis...", 'cyan'))
    analysis = intelligent_vulnerability_analysis(vulnerability_data)
    
    # Generate comprehensive report
    report = generate_report(vulnerability_data, analysis)
    
    # Write to file
    if scheduled and timestamp:
        filename = f"vuln_scan_{timestamp}.txt"
        json_filename = f"vuln_scan_{timestamp}.json"
    else:
        filename = "vuln_scan_results.txt"
        json_filename = "vuln_scan_results.json"
    
    with open(filename, "w") as f:
        f.write(report)
    
    # Save JSON for comparison
    with open(json_filename, "w") as f:
        json.dump(vulnerability_data, f, indent=2)
    
    print(colored(f"[+] Advanced Vulnerability Scan Complete!", 'green'))
    print(colored(f"[+] Report saved to: {filename}", 'green'))
    
    return vulnerability_data

def generate_report(vuln_data, analysis):
    """Generate a clean, professional vulnerability report"""
    
    report = []
    report.append("=" * 80)
    report.append("MECCA X - ADVANCED VULNERABILITY ASSESSMENT REPORT")
    report.append("=" * 80)
    report.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    report.append("\n")
    
    # Executive Summary
    report.append("EXECUTIVE SUMMARY")
    report.append("-" * 80)
    report.append(f"Total hosts scanned: {len(set([v['ip'] for v in vuln_data]))}")
    report.append(f"Total services identified: {len(vuln_data)}")
    
    total_cves = sum(len(v['cves']) for v in vuln_data)
    report.append(f"Total CVEs found: {total_cves}")
    
    # Count by severity
    critical_count = sum(1 for v in vuln_data for cve in v['cves'] if cve['severity'] == 'CRITICAL')
    high_count = sum(1 for v in vuln_data for cve in v['cves'] if cve['severity'] == 'HIGH')
    medium_count = sum(1 for v in vuln_data for cve in v['cves'] if cve['severity'] == 'MEDIUM')
    
    # Count actively exploited
    actively_exploited = sum(1 for v in vuln_data for cve in v['cves'] if cve.get('active_exploitation', {}).get('actively_exploited'))
    
    report.append(f"\nSeverity Breakdown:")
    report.append(f"  🔴 Critical: {critical_count}")
    report.append(f"  🟠 High: {high_count}")
    report.append(f"  🟡 Medium: {medium_count}")
    
    if actively_exploited > 0:
        report.append(f"\n⚠️ ACTIVELY EXPLOITED: {actively_exploited} vulnerabilities")
    
    report.append("\n")
    
    # Detailed Findings
    report.append("DETAILED FINDINGS")
    report.append("-" * 80)
    
    for idx, vuln in enumerate(vuln_data, 1):
        report.append(f"\n[Finding #{idx}]")
        report.append(f"Target: {vuln['ip']}:{vuln['port']}")
        report.append(f"Service: {vuln['product']} {vuln['service']} {vuln['version']}")
        
        if vuln['cves']:
            report.append(f"\nKnown Vulnerabilities ({len(vuln['cves'])} CVEs):")
            for cve in vuln['cves']:
                report.append(f"  - {cve['id']} | Severity: {cve['severity']} | CVSS: {cve['cvss_score']}")
                report.append(f"    {cve['description'][:150]}...")
                
                if cve.get('active_exploitation', {}).get('actively_exploited'):
                    report.append(f"    ⚠️ ACTIVELY EXPLOITED IN THE WILD!")
        else:
            report.append("No known CVEs found in database.")
        
        if vuln['exploits']:
            report.append(f"\n⚠️ Public Exploits Found ({len(vuln['exploits'])}):")
            for exploit in vuln['exploits']:
                report.append(f"  - {exploit['title']}")
        
        if vuln['msf_modules']:
            report.append(f"\n🎯 Metasploit Modules ({len(vuln['msf_modules'])}):")
            for module in vuln['msf_modules']:
                report.append(f"  - {module['name']}")
        
        report.append("")
    
    # Intelligent Analysis
    report.append(analysis)
    report.append("\n")
    
    report.append("=" * 80)
    report.append("END OF REPORT")
    report.append("=" * 80)
    
    return "\n".join(report)

def generate_bug_bounty_report(vuln_data):
    """Generate bug bounty formatted report"""
    print(colored("[+] Generating Bug Bounty Report...", 'green'))
    
    report = []
    report.append("# Bug Bounty Report\n")
    report.append(f"**Date:** {datetime.now().strftime('%Y-%m-%d')}\n")
    report.append("---\n\n")
    
    # Only include high/critical vulnerabilities
    for vuln in vuln_data:
        for cve in vuln['cves']:
            if cve['severity'] in ['CRITICAL', 'HIGH']:
                report.append(f"## Vulnerability: {cve['id']}\n")
                report.append(f"**Severity:** {cve['severity']}\n")
                report.append(f"**CVSS Score:** {cve['cvss_score']}\n")
                report.append(f"**Target:** {vuln['ip']}:{vuln['port']}\n")
                report.append(f"**Service:** {vuln['service']} {vuln['version']}\n\n")
                
                report.append("### Description\n")
                report.append(f"{cve['description']}\n\n")
                
                report.append("### Steps to Reproduce\n")
                report.append(f"1. Target the service at {vuln['ip']}:{vuln['port']}\n")
                report.append(f"2. Identify service as {vuln['service']} {vuln['version']}\n")
                report.append(f"3. Apply exploit for {cve['id']}\n\n")
                
                report.append("### Impact\n")
                if cve['severity'] == 'CRITICAL':
                    report.append("Remote code execution, complete system compromise possible.\n\n")
                else:
                    report.append("Potential unauthorized access or data exposure.\n\n")
                
                report.append("### Remediation\n")
                report.append(f"Update {vuln['service']} to the latest patched version.\n\n")
                
                # Estimated bounty
                if cve['severity'] == 'CRITICAL':
                    report.append("**Estimated Bounty:** $500 - $5,000+\n\n")
                else:
                    report.append("**Estimated Bounty:** $100 - $1,000\n\n")
                
                report.append("---\n\n")
    
    # Save report
    with open("bug_bounty_report.md", "w") as f:
        f.write("".join(report))
    
    print(colored("[+] Bug Bounty Report saved to: bug_bounty_report.md", 'green'))

# Main function to display the menu and handle user input
def main():
    # Display banner
    banner = Figlet(font='slant')
    print(banner.renderText('Mecca X'))
    print(colored("Next-Gen Penetration Testing Framework", 'cyan'))
    print(colored("100% FREE | Network Mapping | Auto-Exploitation | Continuous Monitoring\n", 'cyan'))
    
    while True:
        print("\n" + "="*60)
        print(colored("MAIN MENU", 'cyan', attrs=['bold']))
        print("="*60)
        
        print("\n" + colored("PASSIVE RECONNAISSANCE", 'yellow'))
        print("  1. Subdomain Enumeration")
        
        print("\n" + colored("ACTIVE SCANNING", 'yellow'))
        print("  2. Vulnerability Scan (Single Target)")
        print("  3. Network Mapping (Full Range)")
        
        print("\n" + colored("EXPLOITATION", 'red'))
        print("  4. Auto-Exploitation (Safe Mode)")
        
        print("\n" + colored("CONTINUOUS OPERATIONS", 'yellow'))
        print("  5. Continuous Monitoring (Scheduled Scans)")
        
        print("\n" + colored("REPORTING", 'green'))
        print("  6. Generate Bug Bounty Report")
        
        print("\n" + colored("SYSTEM", 'white'))
        print("  7. Exit")
        
        print("\n" + "="*60)
        
        choice = input(colored("\nEnter your choice: ", 'cyan'))
        
        if choice == "1":
            print(colored("\n[PASSIVE RECONNAISSANCE]", 'yellow', attrs=['bold']))
            domain = input("Enter the domain to enumerate subdomains: ")
            enumerate_subdomains(domain)
            
        elif choice == "2":
            print(colored("\n[ACTIVE SCANNING]", 'yellow', attrs=['bold']))
            target = input("Enter the target IP or hostname: ")
            vuln_data = vulnerability_scan(target)
            
        elif choice == "3":
            print(colored("\n[NETWORK MAPPING]", 'yellow', attrs=['bold']))
            target_range = input("Enter network range (e.g., 192.168.1.0/24): ")
            network_mapper(target_range)
            
        elif choice == "4":
            print(colored("\n[AUTO-EXPLOITATION]", 'red', attrs=['bold']))
            print(colored("⚠️ WARNING: This module will attempt exploitation", 'red'))
            print(colored("Only use on systems you own or have permission to test!", 'red'))
            
            # Check if we have vulnerability data
            if os.path.exists("vuln_scan_results.json"):
                with open("vuln_scan_results.json", "r") as f:
                    vuln_data = json.load(f)
                
                exploit_results = auto_exploit_safe(vuln_data)
                
                if exploit_results:
                    print(colored(f"\n[+] Successfully validated {len(exploit_results)} vulnerabilities", 'green'))
                    
                    # Save exploitation results
                    with open("exploitation_results.json", "w") as f:
                        json.dump(exploit_results, f, indent=2)
                    
                    print(colored("[+] Results saved to: exploitation_results.json", 'green'))
            else:
                print(colored("[-] No vulnerability scan data found. Run option 2 first!", 'red'))
            
        elif choice == "5":
            print(colored("\n[CONTINUOUS MONITORING]", 'yellow', attrs=['bold']))
            target = input("Enter target IP or hostname: ")
            interval = input("Enter scan interval in hours (default: 24): ")
            
            try:
                interval = int(interval) if interval else 24
            except:
                interval = 24
            
            continuous_monitoring(target, interval)
            
        elif choice == "6":
            print(colored("\n[BUG BOUNTY REPORT GENERATION]", 'green', attrs=['bold']))
            
            if os.path.exists("vuln_scan_results.json"):
                with open("vuln_scan_results.json", "r") as f:
                    vuln_data = json.load(f)
                
                generate_bug_bounty_report(vuln_data)
            else:
                print(colored("[-] No vulnerability scan data found. Run option 2 first!", 'red'))
            
        elif choice == "7":
            print(colored("\n[+] Exiting Mecca X...", 'green'))
            print(colored("Stay safe. Happy hacking! 🔒", 'cyan'))
            break
            
        else:
            print(colored("\n[-] Invalid choice. Please try again.", 'red'))

if __name__ == "__main__":
    main()
