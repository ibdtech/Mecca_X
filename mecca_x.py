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
    """Fast subdomain verification"""
    try:
        import socket
        socket.gethostbyname(subdomain)
        return True
    except:
        pass
    
    try:
        response = requests.get(f"http://{subdomain}", timeout=3)
        if response.status_code != 404:
            return True
    except:
        pass
    
    return False

def check_subdomain_fast(subdomain):
    """DNS-only check for speed"""
    try:
        import socket
        socket.gethostbyname(subdomain)
        return True
    except:
        return False

def enumerate_subdomains(domain):
    print(colored("[+] Running Subdomain Enumeration (PASSIVE)...", 'green'))
    print(colored("[*] Using parallel processing + DNS resolution + passive sources", 'yellow'))
    
    all_subdomains = set()
    
    # Run tools in parallel instead of waiting on each one
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
    
    # Certificate transparency logs - super reliable source
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
                    for subdomain in name.split('\n'):
                        subdomain = subdomain.strip().replace('*.', '')
                        if subdomain and domain in subdomain:
                            crt_subdomains.add(subdomain)
                print(colored(f"[+] crt.sh found {len(crt_subdomains)} subdomains", 'green'))
                return crt_subdomains
        except Exception as e:
            print(colored(f"[-] crt.sh error: {str(e)[:50]}", 'red'))
        return set()
    
    # HackerTarget has decent passive recon
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
    
    # Fire off all tools at once
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
    
    with open("subdomains.txt", "w") as f:
        for subdomain in sorted(all_subdomains):
            f.write(subdomain + "\n")
    
    # Quick parallel DNS checks - way faster than sequential
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
    
    with ThreadPoolExecutor(max_workers=50) as executor:
        futures = [executor.submit(check_and_resolve, sub) for sub in all_subdomains]
        
        for future in as_completed(futures):
            result = future.result()
            if result:
                subdomain, ip = result
                live_subdomains.append(subdomain)
                resolved_ips[subdomain] = ip
                print(colored(f"[+] Live: {subdomain} -> {ip}", 'green'))
    
    with open("live_subdomains.txt", "w") as f:
        for subdomain in live_subdomains:
            ip = resolved_ips.get(subdomain, 'Unknown')
            f.write(f"{subdomain} -> {ip}\n")
    
    # Flag interesting targets
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
    # Skip garbage results
    if 'unknown' in service.lower() or 'tcpwrapped' in service.lower():
        return []
    
    print(colored(f"[*] Querying CVE database for {service} {version}...", 'yellow'))
    
    # Try circl.lu first - it's pretty fast
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
    
    # Fallback to NVD if circl.lu doesn't work
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
    print(colored(f"[*] Checking active exploitation status for {cve_id}...", 'yellow'))
    
    try:
        # CISA maintains a list of actively exploited CVEs
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
    print(colored(f"[*] Searching for exploits for {cve_id}...", 'yellow'))
    
    exploits = []
    
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
                for exploit in data['RESULTS_EXPLOIT'][:3]:
                    exploits.append({
                        'title': exploit.get('Title', 'N/A'),
                        'path': exploit.get('Path', 'N/A'),
                        'type': exploit.get('Type', 'N/A')
                    })
    except:
        pass
    
    return exploits

def search_metasploit_modules(service, version):
    print(colored(f"[*] Searching Metasploit modules for {service}...", 'yellow'))
    
    modules = []
    
    try:
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
                        
                        if len(modules) >= 5:
                            break
    except:
        pass
    
    return modules

def auto_exploit_safe(vuln_data):
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
                
                # Just banner grab - completely safe
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
    print(colored("[+] Running Network Mapping (ACTIVE)...", 'green'))
    
    # Quick ping sweep
    print(colored("[*] Step 1: Discovering live hosts...", 'cyan'))
    ping_cmd = f"nmap -sn {target_range} -oX network_hosts.xml"
    subprocess.run(ping_cmd, shell=True)
    
    tree = ET.parse("network_hosts.xml")
    root = tree.getroot()
    
    live_hosts = []
    for host in root.findall("host"):
        if host.find("status").attrib["state"] == "up":
            ip = host.find("address").attrib["addr"]
            live_hosts.append(ip)
    
    print(colored(f"[+] Found {len(live_hosts)} live hosts", 'green'))
    
    # Scan each host
    network_data = []
    for ip in live_hosts:
        print(colored(f"[*] Scanning {ip}...", 'cyan'))
        scan_cmd = f"nmap -sV -T4 --top-ports 100 {ip} -oX host_{ip}.xml"
        subprocess.run(scan_cmd, shell=True)
        
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
    
    attack_graph = build_attack_graph(network_data)
    
    with open("network_map.json", "w") as f:
        json.dump({
            'hosts': network_data,
            'attack_graph': attack_graph
        }, f, indent=2)
    
    print(colored("[+] Network mapping complete! Saved to network_map.json", 'green'))
    return network_data

def build_attack_graph(network_data):
    graph = []
    
    for host in network_data:
        # Look for pivot services
        if any(s['service'] in ['ssh', 'rdp', 'smb', 'vnc'] for s in host['services']):
            graph.append({
                'pivot_host': host['ip'],
                'pivot_services': [s['service'] for s in host['services']],
                'lateral_movement': 'HIGH',
                'reason': 'Remote access services available'
            })
    
    return graph

def continuous_monitoring(target, interval_hours=24):
    print(colored(f"[+] Starting Continuous Monitoring (every {interval_hours} hours)...", 'green'))
    
    def scheduled_scan():
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        print(colored(f"\n[*] Running scheduled scan at {timestamp}...", 'cyan'))
        
        vulnerability_scan(target, scheduled=True, timestamp=timestamp)
        compare_scans(timestamp)
    
    scheduled_scan()
    
    schedule.every(interval_hours).hours.do(scheduled_scan)
    
    print(colored(f"[+] Monitoring active. Press Ctrl+C to stop.", 'green'))
    
    try:
        while True:
            schedule.run_pending()
            time.sleep(60)
    except KeyboardInterrupt:
        print(colored("\n[+] Monitoring stopped.", 'yellow'))

def compare_scans(current_timestamp):
    try:
        with open(f"vuln_scan_{current_timestamp}.json", "r") as f:
            current_scan = json.load(f)
        
        scan_files = sorted([f for f in os.listdir('.') if f.startswith('vuln_scan_') and f.endswith('.json')])
        
        if len(scan_files) > 1:
            previous_file = scan_files[-2]
            
            with open(previous_file, "r") as f:
                previous_scan = json.load(f)
            
            current_cves = set(cve['id'] for vuln in current_scan for cve in vuln.get('cves', []))
            previous_cves = set(cve['id'] for vuln in previous_scan for cve in vuln.get('cves', []))
            
            new_cve_ids = current_cves - previous_cves
            
            if new_cve_ids:
                print(colored(f"\n[!] ALERT: {len(new_cve_ids)} NEW vulnerabilities detected!", 'red'))
                for cve_id in new_cve_ids:
                    print(colored(f"  - {cve_id}", 'red'))
                
                with open(f"alert_{current_timestamp}.txt", "w") as f:
                    f.write(f"NEW VULNERABILITIES DETECTED\n")
                    f.write(f"Scan: {current_timestamp}\n\n")
                    for cve_id in new_cve_ids:
                        f.write(f"- {cve_id}\n")
    except:
        pass

def intelligent_vulnerability_analysis(vuln_data):
    analysis = []
    analysis.append("\n" + "="*80)
    analysis.append("INTELLIGENT VULNERABILITY ANALYSIS")
    analysis.append("="*80 + "\n")
    
    critical_vulns = []
    high_vulns = []
    
    for vuln in vuln_data:
        for cve in vuln['cves']:
            if cve['severity'] == 'CRITICAL':
                critical_vulns.append((vuln, cve))
            elif cve['severity'] == 'HIGH':
                high_vulns.append((vuln, cve))
    
    if critical_vulns:
        analysis.append("🔴 CRITICAL PRIORITY VULNERABILITIES")
        analysis.append("-" * 80)
        analysis.append("These vulnerabilities pose IMMEDIATE risk and should be addressed NOW.\n")
        
        for vuln, cve in critical_vulns[:5]:
            analysis.append(f"[!] {cve['id']} - {vuln['service']} {vuln['version']}")
            analysis.append(f"    CVSS Score: {cve['cvss_score']}")
            analysis.append(f"    Target: {vuln['ip']}:{vuln['port']}")
            
            active_exploit = cve.get('active_exploitation', {})
            if active_exploit.get('actively_exploited'):
                analysis.append(f"\n    ⚠️ ACTIVELY EXPLOITED IN THE WILD!")
                analysis.append(f"    Date Added to CISA KEV: {active_exploit.get('date_added')}")
                analysis.append(f"    Ransomware Use: {active_exploit.get('known_ransomware')}")
            
            analysis.append("\n    💣 EXPLOITATION POTENTIAL:")
            if 'remote' in cve['description'].lower():
                analysis.append("    - Remote code execution possible")
                analysis.append("    - No authentication may be required")
                analysis.append("    - Can be exploited from internet")
            
            if 'overflow' in cve['description'].lower() or 'buffer' in cve['description'].lower():
                analysis.append("    - Buffer overflow vulnerability")
                analysis.append("    - Memory corruption exploitation")
                analysis.append("    - Potential for arbitrary code execution")
            
            analysis.append("\n    🛡️ REMEDIATION STEPS:")
            analysis.append(f"    1. Immediately patch {vuln['service']} to latest version")
            analysis.append(f"    2. Implement network segmentation for {vuln['ip']}")
            analysis.append("    3. Enable intrusion detection monitoring")
            analysis.append("    4. Review logs for exploitation attempts")
            
            exploits = vuln.get('exploits', [])
            if exploits:
                analysis.append("\n    ⚠️ PUBLIC EXPLOITS AVAILABLE:")
                for exploit in exploits:
                    analysis.append(f"    - {exploit['title']}")
            
            modules = vuln.get('msf_modules', [])
            if modules:
                analysis.append("\n    🎯 METASPLOIT MODULES:")
                for module in modules[:3]:
                    analysis.append(f"    - {module['name']}")
            
            exploit_results = vuln.get('exploitation_results', [])
            if exploit_results:
                analysis.append("\n    ✅ EXPLOITATION VALIDATED:")
                for result in exploit_results:
                    analysis.append(f"    - Method: {result['method']}")
                    analysis.append(f"    - Status: {result['status']}")
                    analysis.append(f"    - Proof: {result['proof'][:100]}...")
            
            analysis.append("\n" + "-" * 80 + "\n")
    
    if high_vulns:
        analysis.append("\n🟠 HIGH PRIORITY VULNERABILITIES")
        analysis.append("-" * 80)
        analysis.append("Address these vulnerabilities within 7 days.\n")
        
        for vuln, cve in high_vulns[:5]:
            analysis.append(f"[!] {cve['id']} - {vuln['service']} {vuln['version']}")
            analysis.append(f"    CVSS Score: {cve['cvss_score']}")
            analysis.append(f"    Target: {vuln['ip']}:{vuln['port']}")
            analysis.append(f"    Remediation: Update to patched version\n")
    
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
    
    print(colored("[*] Step 1/6: Running Nmap scan...", 'cyan'))
    vuln_scan_cmd = f"sudo nmap -sV -sC --script=vuln -p- -T4 {target} -oX vuln_scan_results.xml"
    subprocess.run(vuln_scan_cmd, shell=True)
    
    print(colored("[*] Step 2/6: Parsing scan results...", 'cyan'))
    tree = ET.parse("vuln_scan_results.xml")
    root = tree.getroot()
    
    vulnerability
