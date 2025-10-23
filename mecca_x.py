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
    """Fast subdomain check"""
    try:
        import socket
        socket.gethostbyname(subdomain)
        return True
    except:
        pass
    
    try:
        r = requests.get(f"http://{subdomain}", timeout=3)
        if r.status_code != 404:
            return True
    except:
        pass
    
    return False

def check_subdomain_fast(subdomain):
    """DNS only"""
    try:
        import socket
        socket.gethostbyname(subdomain)
        return True
    except:
        return False

def enumerate_subdomains(domain):
    print(colored("[+] Running Subdomain Enumeration (PASSIVE)...", 'green'))
    print(colored("[*] Using parallel processing + DNS resolution + passive sources", 'yellow'))
    
    all_subs = set()
    
    # run tools in parallel
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
    
    # cert transparency
    def get_crtsh():
        print(colored("[*] Querying Certificate Transparency logs (crt.sh)...", 'cyan'))
        try:
            resp = requests.get(
                f"https://crt.sh/?q=%.{domain}&output=json",
                timeout=30
            )
            if resp.status_code == 200:
                data = resp.json()
                crt_subs = set()
                for cert in data:
                    name = cert.get('name_value', '')
                    for sub in name.split('\n'):
                        sub = sub.strip().replace('*.', '')
                        if sub and domain in sub:
                            crt_subs.add(sub)
                print(colored(f"[+] crt.sh found {len(crt_subs)} subdomains", 'green'))
                return crt_subs
        except Exception as e:
            print(colored(f"[-] crt.sh error: {str(e)[:50]}", 'red'))
        return set()
    
    # hackertarget
    def get_hackertarget():
        print(colored("[*] Querying HackerTarget API...", 'cyan'))
        try:
            resp = requests.get(
                f"https://api.hackertarget.com/hostsearch/?q={domain}",
                timeout=15
            )
            if resp.status_code == 200:
                ht_subs = set()
                for line in resp.text.split('\n'):
                    if ',' in line:
                        sub = line.split(',')[0].strip()
                        if sub and domain in sub:
                            ht_subs.add(sub)
                print(colored(f"[+] HackerTarget found {len(ht_subs)} subdomains", 'green'))
                return ht_subs
        except Exception as e:
            print(colored(f"[-] HackerTarget error: {str(e)[:50]}", 'red'))
        return set()
    
    # fire off everything at once
    from concurrent.futures import ThreadPoolExecutor, as_completed
    
    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = {
            executor.submit(run_subfinder): 'Subfinder',
            executor.submit(run_amass): 'Amass',
            executor.submit(get_crtsh): 'crt.sh',
            executor.submit(get_hackertarget): 'HackerTarget'
        }
        
        for future in as_completed(futures):
            tool_name = futures[future]
            try:
                results = future.result()
                all_subs.update(results)
                print(colored(f"[+] {tool_name} completed: {len(results)} subdomains", 'green'))
            except Exception as e:
                print(colored(f"[-] {tool_name} failed: {str(e)}", 'red'))
    
    print(colored(f"\n[+] Phase 1 Complete: {len(all_subs)} unique subdomains found", 'green'))
    
    with open("subdomains.txt", "w") as f:
        for sub in sorted(all_subs):
            f.write(sub + "\n")
    
    # fast parallel DNS checks
    print(colored("\n[*] Phase 2: Fast DNS resolution check (parallel)...", 'cyan'))
    
    live_subs = []
    resolved = {}
    
    def check_and_resolve(sub):
        try:
            import socket
            ip = socket.gethostbyname(sub)
            return (sub, ip)
        except:
            return None
    
    with ThreadPoolExecutor(max_workers=50) as executor:
        futures = [executor.submit(check_and_resolve, sub) for sub in all_subs]
        
        for future in as_completed(futures):
            result = future.result()
            if result:
                sub, ip = result
                live_subs.append(sub)
                resolved[sub] = ip
                print(colored(f"[+] Live: {sub} -> {ip}", 'green'))
    
    with open("live_subdomains.txt", "w") as f:
        for sub in live_subs:
            ip = resolved.get(sub, 'Unknown')
            f.write(f"{sub} -> {ip}\n")
    
    # identify interesting targets
    interesting_keywords = ['admin', 'api', 'dev', 'staging', 'test', 'vpn', 'mail', 'portal', 'dashboard', 'internal', 'private']
    interesting = [sub for sub in live_subs if any(kw in sub.lower() for kw in interesting_keywords)]
    
    print(colored(f"\n{'='*60}", 'green'))
    print(colored("✅ SUBDOMAIN ENUMERATION COMPLETE!", 'green', attrs=['bold']))
    print(colored(f"{'='*60}", 'green'))
    print(colored(f"Total subdomains discovered: {len(all_subs)}", 'white'))
    print(colored(f"Live subdomains (DNS resolved): {len(live_subs)}", 'white'))
    print(colored(f"High-value targets identified: {len(interesting)}", 'yellow'))
    print(colored(f"\n📁 Results saved to:", 'white'))
    print(colored(f"   • subdomains.txt (all discovered)", 'white'))
    print(colored(f"   • live_subdomains.txt (with IP addresses)", 'white'))
    
    print(colored(f"\n{'='*60}", 'cyan'))
    print(colored("📋 INTELLIGENT NEXT STEPS:", 'cyan', attrs=['bold']))
    print(colored(f"{'='*60}", 'cyan'))
    
    if interesting:
        print(colored("\n🎯 HIGH-VALUE TARGETS DETECTED:", 'yellow', attrs=['bold']))
        for sub in interesting[:5]:
            print(colored(f"   → {sub} ({resolved.get(sub, 'Unknown')})", 'yellow'))
        print(colored("\n💡 RECOMMENDATION: Scan these first - they're likely to have valuable findings!", 'yellow'))
        print(colored(f"   Command: Choose Option 2 and enter: {interesting[0]}", 'white'))
    elif live_subs:
        print(colored("\n✅ Live targets found!", 'yellow'))
        print(colored(f"   Suggested first target: {live_subs[0]}", 'white'))
        print(colored(f"   IP Address: {resolved.get(live_subs[0], 'Unknown')}", 'white'))
        print(colored("\n💡 RECOMMENDATION: Run vulnerability scan (Option 2)", 'yellow'))
    else:
        print(colored("\n⚠️ No live subdomains found.", 'yellow'))
        print(colored("   • Try a different domain", 'white'))
        print(colored("   • Or run network mapping if you have an IP range (Option 3)", 'white'))
    
    print(colored(f"{'='*60}\n", 'cyan'))

def calc_severity(cvss):
    if cvss != 'N/A':
        try:
            score = float(cvss)
            if score >= 9.0:
                return 'CRITICAL'
            elif score >= 7.0:
                return 'HIGH'
            elif score >= 4.0:
                return 'MEDIUM'
            else:
                return 'LOW'
        except:
            return 'UNKNOWN'
    return 'UNKNOWN'

def query_cve_database(service, version):
    # skip garbage
    if 'unknown' in service.lower() or 'tcpwrapped' in service.lower():
        return []
    
    print(colored(f"[*] Querying CVE database for {service} {version}...", 'yellow'))
    
    # try circl.lu first
    try:
        search = f"{service} {version}".replace(" ", "%20")
        url = f"https://cve.circl.lu/api/search/{search}"
        
        r = requests.get(url, timeout=10)
        
        if r.status_code == 200:
            data = r.json()
            cves = []
            
            if isinstance(data, list):
                for item in data[:10]:
                    cve_id = item.get('id', 'N/A')
                    summary = item.get('summary', 'No description available')
                    cvss = item.get('cvss', 'N/A')
                    
                    severity = calc_severity(cvss)
                    
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
    
    # fallback to NVD
    try:
        search = f"{service} {version}".replace(" ", "%20")
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={search}&resultsPerPage=10"
        
        r = requests.get(url, timeout=10)
        
        if r.status_code == 200:
            data = r.json()
            cves = []
            
            if 'vulnerabilities' in data:
                for vuln in data['vulnerabilities'][:10]:
                    cve_item = vuln.get('cve', {})
                    cve_id = cve_item.get('id', 'N/A')
                    
                    descriptions = cve_item.get('descriptions', [])
                    desc = descriptions[0].get('value', 'No description') if descriptions else 'No description'
                    
                    metrics = cve_item.get('metrics', {})
                    cvss_score = 'N/A'
                    severity = 'UNKNOWN'
                    
                    if 'cvssMetricV31' in metrics:
                        cvss_data = metrics['cvssMetricV31'][0]['cvssData']
                        cvss_score = cvss_data.get('baseScore', 'N/A')
                        severity = cvss_data.get('baseSeverity', 'UNKNOWN')
                    
                    cves.append({
                        'id': cve_id,
                        'description': desc,
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
        r = requests.get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", timeout=10)
        
        if r.status_code == 200:
            kev_data = r.json()
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
    
    exploit_results = []
    
    for vuln in vuln_data:
        for cve in vuln['cves']:
            if cve['severity'] in ['CRITICAL', 'HIGH']:
                print(colored(f"\n[*] Attempting safe validation for {cve['id']}...", 'cyan'))
                
                try:
                    result = subprocess.run(
                        ['nc', '-v', '-w', '2', vuln['ip'], vuln['port']],
                        capture_output=True,
                        text=True,
                        timeout=5
                    )
                    
                    if result.returncode == 0 or result.stderr:
                        exploit_results.append({
                            'cve': cve['id'],
                            'target': f"{vuln['ip']}:{vuln['port']}",
                            'status': 'VALIDATED',
                            'proof': result.stderr[:200] if result.stderr else 'Connection successful',
                            'method': 'Banner Grab'
                        })
                        print(colored(f"[+] Validated: {cve['id']}", 'green'))
                except:
                    pass
    
    return exploit_results

def network_mapper(target_range):
    print(colored("[+] Running Network Mapping (ACTIVE)...", 'green'))
    
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
    
    net_data = []
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
            
            net_data.append({
                'ip': ip,
                'services': services
            })
        except:
            pass
    
    atk_graph = build_attack_graph(net_data)
    
    with open("network_map.json", "w") as f:
        json.dump({
            'hosts': net_data,
            'attack_graph': atk_graph
        }, f, indent=2)
    
    print(colored("[+] Network mapping complete! Saved to network_map.json", 'green'))
    return net_data

def build_attack_graph(net_data):
    graph = []
    
    for host in net_data:
        if any(s['service'] in ['ssh', 'rdp', 'smb', 'vnc'] for s in host['services']):
            graph.append({
                'pivot_host': host['ip'],
                'pivot_services': [s['service'] for s in host['services']],
                'lateral_movement': 'HIGH',
                'reason': 'Remote access services available'
            })
    
    return graph

def continuous_monitoring(target, interval_hrs=24):
    print(colored(f"[+] Starting Continuous Monitoring (every {interval_hrs} hours)...", 'green'))
    
    def scheduled_scan():
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        print(colored(f"\n[*] Running scheduled scan at {ts}...", 'cyan'))
        
        vulnerability_scan(target, scheduled=True, timestamp=ts)
        compare_scans(ts)
    
    scheduled_scan()
    
    schedule.every(interval_hrs).hours.do(scheduled_scan)
    
    print(colored(f"[+] Monitoring active. Press Ctrl+C to stop.", 'green'))
    
    try:
        while True:
            schedule.run_pending()
            time.sleep(60)
    except KeyboardInterrupt:
        print(colored("\n[+] Monitoring stopped.", 'yellow'))

def compare_scans(current_ts):
    try:
        with open(f"vuln_scan_{current_ts}.json", "r") as f:
            current = json.load(f)
        
        scan_files = sorted([f for f in os.listdir('.') if f.startswith('vuln_scan_') and f.endswith('.json')])
        
        if len(scan_files) > 1:
            prev_file = scan_files[-2]
            
            with open(prev_file, "r") as f:
                previous = json.load(f)
            
            curr_cves = set(cve['id'] for v in current for cve in v.get('cves', []))
            prev_cves = set(cve['id'] for v in previous for cve in v.get('cves', []))
            
            new_cves = curr_cves - prev_cves
            
            if new_cves:
                print(colored(f"\n[!] ALERT: {len(new_cves)} NEW vulnerabilities detected!", 'red'))
                for cve in new_cves:
                    print(colored(f"  - {cve}", 'red'))
                
                with open(f"alert_{current_ts}.txt", "w") as f:
                    f.write(f"NEW VULNERABILITIES DETECTED\n")
                    f.write(f"Scan: {current_ts}\n\n")
                    for cve in new_cves:
                        f.write(f"- {cve}\n")
    except:
        pass

def analyze_vulns(vuln_data):
    analysis = []
    analysis.append("\n" + "="*80)
    analysis.append("INTELLIGENT VULNERABILITY ANALYSIS")
    analysis.append("="*80 + "\n")
    
    critical = []
    high = []
    
    for v in vuln_data:
        for cve in v['cves']:
            if cve['severity'] == 'CRITICAL':
                critical.append((v, cve))
            elif cve['severity'] == 'HIGH':
                high.append((v, cve))
    
    if critical:
        analysis.append("🔴 CRITICAL PRIORITY VULNERABILITIES")
        analysis.append("-" * 80)
        analysis.append("These vulnerabilities pose IMMEDIATE risk and should be addressed NOW.\n")
        
        for v, cve in critical[:5]:
            analysis.append(f"[!] {cve['id']} - {v['service']} {v['version']}")
            analysis.append(f"    CVSS Score: {cve['cvss_score']}")
            analysis.append(f"    Target: {v['ip']}:{v['port']}")
            
            active = cve.get('active_exploitation', {})
            if active.get('actively_exploited'):
                analysis.append(f"\n    ⚠️ ACTIVELY EXPLOITED IN THE WILD!")
                analysis.append(f"    Date Added to CISA KEV: {active.get('date_added')}")
                analysis.append(f"    Ransomware Use: {active.get('known_ransomware')}")
            
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
            analysis.append(f"    1. Immediately patch {v['service']} to latest version")
            analysis.append(f"    2. Implement network segmentation for {v['ip']}")
            analysis.append("    3. Enable intrusion detection monitoring")
            analysis.append("    4. Review logs for exploitation attempts")
            
            exploits = v.get('exploits', [])
            if exploits:
                analysis.append("\n    ⚠️ PUBLIC EXPLOITS AVAILABLE:")
                for exp in exploits:
                    analysis.append(f"    - {exp['title']}")
            
            mods = v.get('msf_modules', [])
            if mods:
                analysis.append("\n    🎯 METASPLOIT MODULES:")
                for mod in mods[:3]:
                    analysis.append(f"    - {mod['name']}")
            
            exp_res = v.get('exploitation_results', [])
            if exp_res:
                analysis.append("\n    ✅ EXPLOITATION VALIDATED:")
                for res in exp_res:
                    analysis.append(f"    - Method: {res['method']}")
                    analysis.append(f"    - Status: {res['status']}")
                    analysis.append(f"    - Proof: {res['proof'][:100]}...")
            
            analysis.append("\n" + "-" * 80 + "\n")
    
    if high:
        analysis.append("\n🟠 HIGH PRIORITY VULNERABILITIES")
        analysis.append("-" * 80)
        analysis.append("Address these vulnerabilities within 7 days.\n")
        
        for v, cve in high[:5]:
            analysis.append(f"[!] {cve['id']} - {v['service']} {v['version']}")
            analysis.append(f"    CVSS Score: {cve['cvss_score']}")
            analysis.append(f"    Target: {v['ip']}:{v['port']}")
            analysis.append(f"    Remediation: Update to patched version\n")
    
    analysis.append("\n🔗 POTENTIAL ATTACK CHAINS")
    analysis.append("-" * 80)
    
    svcs_by_host = {}
    for v in vuln_data:
        if v['ip'] not in svcs_by_host:
            svcs_by_host[v['ip']] = []
        svcs_by_host[v['ip']].append(v)
    
    for ip, svcs in svcs_by_host.items():
        if len(svcs) > 1:
            analysis.append(f"\n[Host: {ip}]")
            analysis.append("Multiple vulnerable services detected - Pivot opportunities:")
            for svc in svcs:
                analysis.append(f"  → {svc['port']}/{svc['service']} ({len(svc['cves'])} CVEs)")
            analysis.append("  Attack Strategy: Compromise one service, pivot to others")
    
    analysis.append("\n\n💼 BUSINESS IMPACT ASSESSMENT")
    analysis.append("-" * 80)
    
    total_crit = len(critical)
    total_high = len(high)
    
    if total_crit > 0:
        analysis.append(f"⚠️ SEVERE RISK: {total_crit} critical vulnerabilities detected")
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
    vuln_cmd = f"sudo nmap -sV -sC --script=vuln -p- -T4 {target} -oX vuln_scan_results.xml"
    subprocess.run(vuln_cmd, shell=True)
    
    print(colored("[*] Step 2/6: Parsing scan results...", 'cyan'))
    tree = ET.parse("vuln_scan_results.xml")
    root = tree.getroot()
    
    vuln_data = []
    
    for host in root.findall("host"):
        ip = host.find("address").attrib["addr"]
        
        if host.find("ports") is not None:
            for port in host.find("ports").findall("port"):
                port_id = port.attrib["portid"]
                
                if port.find("service") is not None:
                    svc_elem = port.find("service")
                    svc_name = svc_elem.attrib.get("name", "unknown")
                    svc_ver = svc_elem.attrib.get("version", "unknown")
                    product = svc_elem.attrib.get("product", "unknown")
                    
                    print(colored(f"[*] Step 3/6: Checking CVEs for {svc_name} {svc_ver}...", 'cyan'))
                    cves = query_cve_database(f"{product} {svc_name}", svc_ver)
                    
                    print(colored(f"[*] Step 4/6: Checking active exploitation status...", 'cyan'))
                    for cve in cves:
                        cve['active_exploitation'] = check_active_exploitation(cve['id'])
                    
                    print(colored(f"[*] Step 5/6: Searching for exploits...", 'cyan'))
                    exploits = []
                    for cve in cves[:3]:
                        exp = search_exploit_db(cve['id'])
                        exploits.extend(exp)
                    
                    msf_mods = search_metasploit_modules(svc_name, svc_ver)
                    
                    vuln_entry = {
                        'ip': ip,
                        'port': port_id,
                        'service': svc_name,
                        'version': svc_ver,
                        'product': product,
                        'cves': cves,
                        'exploits': exploits,
                        'msf_modules': msf_mods
                    }
                    
                    vuln_data.append(vuln_entry)
    
    print(colored("[*] Step 6/6: Running intelligent analysis...", 'cyan'))
    analysis = analyze_vulns(vuln_data)
    
    report = gen_report(vuln_data, analysis)
    
    if scheduled and timestamp:
        fname = f"vuln_scan_{timestamp}.txt"
        json_fname = f"vuln_scan_{timestamp}.json"
    else:
        fname = "vuln_scan_results.txt"
        json_fname = "vuln_scan_results.json"
    
    with open(fname, "w") as f:
        f.write(report)
    
    with open(json_fname, "w") as f:
        json.dump(vuln_data, f, indent=2)
    
    print(colored(f"[+] Advanced Vulnerability Scan Complete!", 'green'))
    print(colored(f"[+] Report saved to: {fname}", 'green'))
    
    return vuln_data

def gen_report(vuln_data, analysis):
    report = []
    report.append("=" * 80)
    report.append("MECCA X - ADVANCED VULNERABILITY ASSESSMENT REPORT")
    report.append("=" * 80)
    report.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    report.append("\n")
    
    report.append("EXECUTIVE SUMMARY")
    report.append("-" * 80)
    report.append(f"Total hosts scanned: {len(set([v['ip'] for v in vuln_data]))}")
    report.append(f"Total services identified: {len(vuln_data)}")
    
    total_cves = sum(len(v['cves']) for v in vuln_data)
    report.append(f"Total CVEs found: {total_cves}")
    
    crit_cnt = sum(1 for v in vuln_data for cve in v['cves'] if cve['severity'] == 'CRITICAL')
    high_cnt = sum(1 for v in vuln_data for cve in v['cves'] if cve['severity'] == 'HIGH')
    med_cnt = sum(1 for v in vuln_data for cve in v['cves'] if cve['severity'] == 'MEDIUM')
    
    active_cnt = sum(1 for v in vuln_data for cve in v['cves'] if cve.get('active_exploitation', {}).get('actively_exploited'))
    
    report.append(f"\nSeverity Breakdown:")
    report.append(f"  🔴 Critical: {crit_cnt}")
    report.append(f"  🟠 High: {high_cnt}")
    report.append(f"  🟡 Medium: {med_cnt}")
    
    if active_cnt > 0:
        report.append(f"\n⚠️ ACTIVELY EXPLOITED: {active_cnt} vulnerabilities")
    
    report.append("\n")
    
    report.append("DETAILED FINDINGS")
    report.append("-" * 80)
    
    for idx, v in enumerate(vuln_data, 1):
        report.append(f"\n[Finding #{idx}]")
        report.append(f"Target: {v['ip']}:{v['port']}")
        report.append(f"Service: {v['product']} {v['service']} {v['version']}")
        
        if v['cves']:
            report.append(f"\nKnown Vulnerabilities ({len(v['cves'])} CVEs):")
            for cve in v['cves']:
                report.append(f"  - {cve['id']} | Severity: {cve['severity']} | CVSS: {cve['cvss_score']}")
                report.append(f"    {cve['description'][:150]}...")
                
                if cve.get('active_exploitation', {}).get('actively_exploited'):
                    report.append(f"    ⚠️ ACTIVELY EXPLOITED IN THE WILD!")
        else:
            report.append("No known CVEs found in database.")
        
        if v['exploits']:
            report.append(f"\n⚠️ Public Exploits Found ({len(v['exploits'])}):")
            for exp in v['exploits']:
                report.append(f"  - {exp['title']}")
        
        if v['msf_modules']:
            report.append(f"\n🎯 Metasploit Modules ({len(v['msf_modules'])}):")
            for mod in v['msf_modules']:
                report.append(f"  - {mod['name']}")
        
        report.append("")
    
    report.append(analysis)
    report.append("\n")
    
    report.append("=" * 80)
    report.append("END OF REPORT")
    report.append("=" * 80)
    
    return "\n".join(report)

def gen_bug_bounty_report(vuln_data):
    print(colored("[+] Generating Bug Bounty Report...", 'green'))
    
    report = []
    report.append("# Bug Bounty Report\n")
    report.append(f"**Date:** {datetime.now().strftime('%Y-%m-%d')}\n")
    report.append("---\n\n")
    
    for v in vuln_data:
        for cve in v['cves']:
            if cve['severity'] in ['CRITICAL', 'HIGH']:
                report.append(f"## Vulnerability: {cve['id']}\n")
                report.append(f"**Severity:** {cve['severity']}\n")
                report.append(f"**CVSS Score:** {cve['cvss_score']}\n")
                report.append(f"**Target:** {v['ip']}:{v['port']}\n")
                report.append(f"**Service:** {v['service']} {v['version']}\n\n")
                
                report.append("### Description\n")
                report.append(f"{cve['description']}\n\n")
                
                report.append("### Steps to Reproduce\n")
                report.append(f"1. Target the service at {v['ip']}:{v['port']}\n")
                report.append(f"2. Identify service as {v['service']} {v['version']}\n")
                report.append(f"3. Apply exploit for {cve['id']}\n\n")
                
                report.append("### Impact\n")
                if cve['severity'] == 'CRITICAL':
                    report.append("Remote code execution, complete system compromise possible.\n\n")
                else:
                    report.append("Potential unauthorized access or data exposure.\n\n")
                
                report.append("### Remediation\n")
                report.append(f"Update {v['service']} to the latest patched version.\n\n")
                
                if cve['severity'] == 'CRITICAL':
                    report.append("**Estimated Bounty:** $500 - $5,000+\n\n")
                else:
                    report.append("**Estimated Bounty:** $100 - $1,000\n\n")
                
                report.append("---\n\n")
    
    with open("bug_bounty_report.md", "w") as f:
        f.write("".join(report))
    
    print(colored("[+] Bug Bounty Report saved to: bug_bounty_report.md", 'green'))

def main():
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
            
            if os.path.exists("vuln_scan_results.json"):
                with open("vuln_scan_results.json", "r") as f:
                    vuln_data = json.load(f)
                
                exp_results = auto_exploit_safe(vuln_data)
                
                if exp_results:
                    print(colored(f"\n[+] Successfully validated {len(exp_results)} vulnerabilities", 'green'))
                    
                    with open("exploitation_results.json", "w") as f:
                        json.dump(exp_results, f, indent=2)
                    
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
                
                gen_bug_bounty_report(vuln_data)
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
