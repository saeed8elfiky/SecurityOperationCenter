import re
import argparse
import os
import json
import html
import csv
import urllib.request
import urllib.error
import urllib.parse
from datetime import datetime
from collections import defaultdict
from urllib.parse import unquote

# Enable ANSI colors for Windows cmd/powershell
if os.name == 'nt':
    os.system('color')

# ANSI Color Codes
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    ORANGE = '\033[38;5;208m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    RESET = '\033[0m'

PATTERNS = {
    "SQL Injection": re.compile(r"(%27)|(\')|(--)|(%23)|(#)|(UNION.*SELECT)|(OR.*1=1)", re.IGNORECASE),
    "Cross-Site Scripting (XSS)": re.compile(r"(%3C)|(<)\s*(script|iframe|img|svg|body|onload|onerror)", re.IGNORECASE),
    "Path Traversal (LFI)": re.compile(r"(\.\./)|(\.\.%2f)|(%2e%2e%2f)|(%2e%2e/)|(/etc/passwd|/etc/shadow|win\.ini|boot\.ini)", re.IGNORECASE),
    "Sensitive Files Exposure": re.compile(r"(\.env|wp-config\.php|\.git/config|id_rsa)", re.IGNORECASE),
    "Malicious User-Agent (Scanners)": re.compile(r"(nikto|nmap|sqlmap|dirbuster|zmcat|masscan|gobuster|ffuf|fuzz faster u fool|wfuzz|feroxbuster|nuclei|wpscan|burpsuite|acunetix|netsparker|zmap|httpx)", re.IGNORECASE),
    "Log4j (JNDI Injection)": re.compile(r"(\$\{jndi:(ldap|rmi|dns|nis|http|corba|iiop):.*?\})", re.IGNORECASE),
    "Shellshock (CVE-2014-6271)": re.compile(r"(\(\)\s*\{\s*:\s*;\s*\}\s*;)", re.IGNORECASE),
    "Server-Side Request Forgery (SSRF)": re.compile(r"((?:\?|&)url=(?:http|https|ftp|file|dict|gopher|ldap)://)", re.IGNORECASE),
    "Command Injection": re.compile(r"(;|\|\||&&)\s*(cat|ls|id|whoami|wget|curl|nc\s+-e|bash\s+-i|cmd\.exe|powershell)", re.IGNORECASE)
}

LOGO = r"""
  ____    _    ____   ____    _    _   _ _____ _   _    _    
 / ___|  / \  |  _ \ / ___|  / \  | \ | |_   _| | | |  / \   
| |  _  / _ \ | |_) | |  _  / _ \ |  \| | | | | | | | / _ \  
| |_| |/ ___ \|  _ <| |_| |/ ___ \| |\  | | | | |_| |/ ___ \ 
 \____/_/   \_\_| \_\\____/_/   \_\_| \_| |_|  \___//_/   \_\
      :: Supermassive Web Threat Analysis Engine ::
                 Created by Saeed Elfiky
"""

GEO_CACHE = {}

def get_geo(ip):
    if ip.startswith(('192.168.', '10.', '172.', '127.')) or ip == '::1':
        return "[Local]"
    if ip in GEO_CACHE:
        return GEO_CACHE[ip]
    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,countryCode,city"
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=1.5) as response:
            data = json.loads(response.read().decode())
            if data.get('status') == 'success':
                loc = f"[{data.get('countryCode')}] {data.get('city')}"
                GEO_CACHE[ip] = loc
                return loc
    except Exception:
        pass
    GEO_CACHE[ip] = "[Unknown Location]"
    return "[Unknown Location]"

def parse_log_line(line):
    line = line.strip()
    if line.startswith('{') and line.endswith('}'):
        try:
            data = json.loads(line)
            ip = data.get('ClientHost') or data.get('remote_ip') or data.get('client_ip') or data.get('ip')
            req = data.get('RequestPath') or data.get('request') or f"{data.get('method', 'GET')} {data.get('path', '/')} HTTP/1.1"
            status = str(data.get('DownstreamStatus') or data.get('status') or '200')
            size = str(data.get('length') or data.get('bytes') or '0')
            ua = data.get('request_User-Agent') or data.get('user_agent') or data.get('user-agent') or ''
            time_str = data.get('time') or data.get('@timestamp') or ''
            if ip and req:
                return {'ip': ip, 'time': time_str, 'request': req, 'status': status, 'size': size, 'user_agent': ua}
        except Exception:
            pass

    log_pattern = re.compile(r'(?P<ip>\S+) \S+ \S+ \[(?P<time>.*?)\] "(?P<request>.*?)" (?P<status>\d{3}) (?P<size>\S+)(?: "(?P<referer>.*?)")?(?: "(?P<user_agent>.*?)")?')
    match = log_pattern.match(line)
    if match: return match.groupdict()
    return None

def export_json(report_data, filepath):
    try:
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=4)
        print(f"{Colors.GREEN}[+] JSON report successfully exported to: {filepath}{Colors.RESET}")
    except Exception as e:
        print(f"{Colors.RED}[!] Error exporting JSON: {e}{Colors.RESET}")

def export_md(report_data, filepath):
    md = f"# Gargantua Web Threat Analysis Report\n**Analyzed File:** `{report_data['file_analyzed']}`\n\n"
    
    if report_data["suspicious_events"]:
        md += "## Malicious Events (Signatures)\n| IP | Location | Threat Type | Occurrences |\n|---|---|---|---|\n"
        for ev in report_data["suspicious_events"]:
            md += f"| `{ev['ip']}` | {get_geo(ev['ip'])} | {ev['type']} | {ev['count']} |\n"
            
    if report_data.get("data_exfil_events"):
        md += "\n## Data Exfiltration Anomalies (High Byte Transfer > 20MB)\n| IP | Location | Megabytes | Target Request |\n|---|---|---|---|\n"
        for ev in report_data["data_exfil_events"]:
            md += f"| `{ev['ip']}` | {get_geo(ev['ip'])} | {int(ev['size'])/1000000:.2f} MB | `{ev['request']}` |\n"
            
    if report_data.get("dos_ips"):
        md += "\n## Severe Traffic (Potential DoS)\n| IP | Location | Peak RPM |\n|---|---|---|\n"
        for ip, count in report_data["dos_ips"].items():
            md += f"| `{ip}` | {get_geo(ip)} | {count} |\n"
            
    if report_data.get("high_fuzzing"):
        md += "\n## Precision Directory Fuzzing\n| IP | Location | 40x Errors targeting Hidden Files |\n|---|---|---|\n"
        for ip, count in report_data["high_fuzzing"].items():
            md += f"| `{ip}` | {get_geo(ip)} | {count} |\n"

    if report_data.get("high_lazy_bots"):
        md += "\n## Automated Lazy Bot Tooling\n| IP | Location | Null/Automated User-Agent Requests |\n|---|---|---|\n"
        for ip, count in report_data["high_lazy_bots"].items():
            md += f"| `{ip}` | {get_geo(ip)} | {count} |\n"

    try:
        with open(filepath, 'w', encoding='utf-8') as f: f.write(md)
        print(f"{Colors.GREEN}[+] Markdown report exported to: {filepath}{Colors.RESET}")
    except Exception as e:
        print(f"{Colors.RED}[!] Error exporting Markdown: {e}{Colors.RESET}")

def export_csv(report_data, filepath):
    try:
        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(["Trigger_Type", "Source_IP", "Details", "Count"])
            for ev in report_data.get("suspicious_events", []):
                writer.writerow(["Signature Alert", ev['ip'], ev['type'], ev['count']])
            for ip, count in report_data.get("dos_ips", {}).items():
                writer.writerow(["DoS/Scraping", ip, "Severe Traffic RPM", count])
            for ev in report_data.get("data_exfil_events", []):
                writer.writerow(["Data Exfiltration", ev['ip'], f"Transferred {int(ev['size'])/1000000:.2f} MB", 1])
            for ip, count in report_data.get("high_fuzzing", {}).items():
                writer.writerow(["Directory Fuzzing", ip, "Hidden File Scans", count])
            for ip, count in report_data.get("high_5xx", {}).items():
                writer.writerow(["Server Error Exploit", ip, "50x Error Count", count])
        print(f"{Colors.GREEN}[+] CSV report exported to: {filepath}{Colors.RESET}")
    except Exception as e:
         print(f"{Colors.RED}[!] Error exporting CSV: {e}{Colors.RESET}")

def export_html(report_data, filepath):
    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Web Log Analysis Report</title>
        <style>
            body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #f4f7f6; color: #333; margin: 0; padding: 20px; }}
            h1 {{ text-align: center; color: #d9534f; }}
            .container {{ max-width: 1000px; margin: auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 4px 12px rgba(0,0,0,0.1); }}
            h2 {{ border-bottom: 2px solid #ddd; padding-bottom: 5px; color: #333; margin-top: 30px; }}
            table {{ width: 100%; border-collapse: collapse; margin-top: 15px; font-size: 14px; break-inside: auto; }}
            th, td {{ border: 1px solid #ddd; padding: 12px; text-align: left; }}
            th {{ background-color: #2c3e50; color: white; }}
            .warning {{ background-color: #fdf2f2; }}
            .info {{ background-color: #e2f0d9; padding: 15px; border-radius: 5px; }}
            .code-snippet {{ background: #f8f9fa; border: 1px solid #ccc; padding: 4px; border-radius: 4px; font-family: monospace; word-break: break-all; }}
            .threat-badge {{ background: #d9534f; color: white; padding: 4px 8px; border-radius: 4px; font-weight: bold; font-size: 12px; }}
            .badge-recon {{ background: #f1c40f; color: #333; padding: 4px 8px; border-radius: 4px; font-weight: bold; font-size: 12px; }}
        </style>
        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    </head>
    <body>
        <div class="container">
            <h1>Gargantua: Logs Report</h1>
            <p><strong>Created by:</strong> Saeed Elfiky</p>
            <p><strong>Generated on:</strong> {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
            <p><strong>Analyzed File:</strong> {report_data.get('file_analyzed', 'Unknown')}</p>
    """
    
    # Section 1: Signature Detections
    html_content += "<h2>Suspicious Events (Signatures)</h2>"
    if report_data.get("suspicious_events"):
        html_content += """
        <table>
            <tr><th>Line</th><th>Source IP</th><th>Location</th><th>Threat Type</th><th>Occurrences</th><th>Request Payload Snippet</th></tr>
        """
        for event in report_data["suspicious_events"]:
            safe_payload = html.escape(event['payload'])
            snippet = safe_payload[:100] + '...' if len(safe_payload) > 100 else safe_payload
            loc = get_geo(event['ip'])
            html_content += f"<tr class='warning'><td>{event['first_line']}</td><td><strong>{event['ip']}</strong></td><td>{loc}</td><td><span class='threat-badge'>{event['type']}</span></td><td><strong>{event['count']}</strong></td><td><span class='code-snippet'>{snippet}</span></td></tr>"
        html_content += "</table>"
    else:
        html_content += "<p class='info'>No signature-based web attacks detected in this log.</p>"

    # Dashboard Charts
    html_content += """
        <div class="charts-row" style="display: flex; flex-wrap: wrap; gap: 20px; margin-top: 30px;">
            <div style="flex: 1; min-width: 300px; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 4px 12px rgba(0,0,0,0.1);">
                <h3 style="text-align: center;">Aggregated Threats Distribution</h3>
                <canvas id="threatChart"></canvas>
            </div>
            <div style="flex: 1; min-width: 300px; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 4px 12px rgba(0,0,0,0.1);">
                <h3 style="text-align: center;">Top Traffic APIs (RPM)</h3>
                <canvas id="trafficChart"></canvas>
            </div>
        </div>
    """
        
    if report_data.get("data_exfil_events"):
        html_content += "<h2>Data Exfiltration (Large Byte Transfer)</h2><table><tr><th>IP</th><th>Location</th><th>File Transfer Size</th><th>Request</th></tr>"
        for event in report_data["data_exfil_events"]:
            mb_size = int(event['size']) / 1_000_000
            html_content += f"<tr class='warning'><td><strong>{event['ip']}</strong></td><td>{get_geo(event['ip'])}</td><td>{mb_size:.2f} MB</td><td><span class='code-snippet'>{html.escape(event['request'])}</span></td></tr>"
        html_content += "</table>"

    # Prepare Threat Type Distribution for Chart.js
    threat_counts = defaultdict(int)
    if report_data.get("suspicious_events"):
        for event in report_data["suspicious_events"]:
            threat_counts[event['type']] += event['count']
    threat_labels = list(threat_counts.keys())
    threat_data = list(threat_counts.values())

    # Prepare Top DoS / Scraping IPs for Chart.js
    all_traffic = {}
    if report_data.get("dos_ips"):
        all_traffic.update(report_data["dos_ips"])
    if report_data.get("scraping_ips"):
        all_traffic.update(report_data["scraping_ips"])
    top_traffic = dict(sorted(all_traffic.items(), key=lambda item: item[1], reverse=True)[:10])
    traffic_labels = list(top_traffic.keys())
    traffic_data = list(top_traffic.values())

    html_content += f"""
        </div>
        <script>
            const ctxThreat = document.getElementById('threatChart').getContext('2d');
            new Chart(ctxThreat, {{
                type: 'doughnut',
                data: {{
                    labels: {json.dumps(threat_labels)},
                    datasets: [{{
                        data: {json.dumps(threat_data)},
                        backgroundColor: ['#e74c3c', '#e67e22', '#f1c40f', '#3498db', '#9b59b6', '#34495e', '#1abc9c'],
                        borderWidth: 1
                    }}]
                }},
                options: {{ responsive: true }}
            }});

            const ctxTraffic = document.getElementById('trafficChart').getContext('2d');
            new Chart(ctxTraffic, {{
                type: 'bar',
                data: {{
                    labels: {json.dumps(traffic_labels)},
                    datasets: [{{
                        label: 'Peak Requests / Minute',
                        data: {json.dumps(traffic_data)},
                        backgroundColor: '#c0392b',
                        borderWidth: 1
                    }}]
                }},
                options: {{ responsive: true, scales: {{ y: {{ beginAtZero: true }} }} }}
            }});
        </script>
    </body>
    </html>
    """
    try:
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html_content)
        print(f"{Colors.GREEN}[+] HTML report successfully exported to: {filepath}{Colors.RESET}")
    except Exception as e:
        print(f"{Colors.RED}[!] Error exporting HTML: {e}{Colors.RESET}")


def analyze_logs(file_path, json_export=None, html_export=None, md_export=None, csv_export=None):
    print(f"{Colors.ORANGE}{LOGO}{Colors.RESET}")
    print(f"{Colors.BLUE}[*] Starting Log Analysis on: {Colors.BOLD}{file_path}{Colors.RESET}\n")
    
    suspicious_events_dict = {}
    ip_requests = defaultdict(int)
    ip_failed_codes = defaultdict(int)
    ip_5xx_codes = defaultdict(int)
    ip_sensitive_posts = defaultdict(int)
    ip_suspicious_methods = defaultdict(list)
    ip_time_requests = defaultdict(lambda: defaultdict(int))
    
    lazy_bots = defaultdict(int)
    ip_dir_fuzzing = defaultdict(int)
    data_exfil_events = []
    
    sensitive_endpoints = re.compile(r"(/wp-login\.php|/admin|/cpanel|/login|/administrator|/xmlrpc\.php)", re.IGNORECASE)
    hidden_files_pattern = re.compile(r"/\.(env|git|bak|old|zip|sql|tar|swp)|/\w+\.(bak|old|zip|sql|tar\.gz|swp)$", re.IGNORECASE)
    lazy_bot_pattern = re.compile(r"(python-requests|urllib|curl|wget|java/)", re.IGNORECASE)
    unusual_methods = {"PUT", "DELETE", "TRACE", "OPTIONS", "CONNECT"}
    
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line_no, line in enumerate(f, 1):
                data = parse_log_line(line)
                if not data: continue
                
                request_decoded = unquote(data['request'])
                user_agent = data.get('user_agent') or ''
                ip = data['ip']
                status = data['status']
                
                int_size = 0
                if data['size'] != '-':
                    try: int_size = int(data['size'])
                    except ValueError: pass
                
                # Tuned Data Exfiltration (Ignore Media, Flag Archives / Anomalous Size)
                if status == '200' and int_size > 500_000:
                    if not re.search(r'\.(mp4|mov|avi|webm|mkv|jpg|jpeg|png|gif|webp|svg|css|js|woff|woff2|ttf|eot|ico|iso|dmg|exe|pkg)(\?.*)?$', request_decoded, re.IGNORECASE):
                        if int_size > 5_000_000 or re.search(r'\.(sql|bak|zip|tar|gz|bz2|7z|db|sqlite|dump|csv|log|pcap)(\?.*)?$', request_decoded, re.IGNORECASE):
                            data_exfil_events.append({'ip': ip, 'first_line': line_no, 'size': int_size, 'request': request_decoded})
                    
                # Check for Blind/Lazy Bots
                if lazy_bot_pattern.search(user_agent) or user_agent == '' or user_agent == '-':
                    lazy_bots[ip] += 1
                
                # Check for Precision Fuzzing
                if status.startswith('4') and hidden_files_pattern.search(request_decoded):
                    ip_dir_fuzzing[ip] += 1

                timestamp = data.get('time', '')
                time_parts = timestamp.split(':')
                minute_str = f"{time_parts[0]}:{time_parts[1]}:{time_parts[2]}" if len(time_parts) >= 3 else "unknown"
                
                ip_requests[ip] += 1
                ip_time_requests[ip][minute_str] += 1
                
                if status.startswith('4'): ip_failed_codes[ip] += 1
                elif status.startswith('5'): ip_5xx_codes[ip] += 1
                
                parts = request_decoded.split()
                method = parts[0].upper() if len(parts) >= 1 else "UNKNOWN"
                    
                if method in unusual_methods and method not in ip_suspicious_methods[ip]:
                    ip_suspicious_methods[ip].append(method)
                        
                if method == "POST" and sensitive_endpoints.search(request_decoded):
                    ip_sensitive_posts[ip] += 1
                
                for attack_type, pattern in PATTERNS.items():
                    matched = False
                    payload = ""
                    if attack_type == "Malicious User-Agent (Scanners)":
                        if user_agent and pattern.search(user_agent):
                            matched = True
                            payload = user_agent
                    else:
                        if pattern.search(request_decoded):
                            matched, payload = True, request_decoded
                        elif user_agent and pattern.search(user_agent):
                            matched, payload = True, user_agent

                    if matched:
                        event_key = (ip, attack_type)
                        if event_key not in suspicious_events_dict:
                            suspicious_events_dict[event_key] = {'first_line': line_no, 'count': 1, 'ip': ip, 'type': attack_type, 'payload': payload}
                        else:
                            suspicious_events_dict[event_key]['count'] += 1

    except FileNotFoundError:
        print(f"{Colors.RED}[!] Error: File '{file_path}' not found.{Colors.RESET}")
        return

    suspicious_events = list(suspicious_events_dict.values())
    ip_max_rpm = {ip: max(minutes.values()) if minutes else 0 for ip, minutes in ip_time_requests.items()}

    scraping_ips = {ip: rpm for ip, rpm in ip_max_rpm.items() if 60 <= rpm < 150}
    dos_ips = {ip: rpm for ip, rpm in ip_max_rpm.items() if rpm >= 150}
    
    high_failures = {ip: count for ip, count in ip_failed_codes.items() if count >= 20}
    high_5xx = {ip: count for ip, count in ip_5xx_codes.items() if count >= 5}
    high_sensitive = {ip: count for ip, count in ip_sensitive_posts.items() if count >= 5}
    high_fuzzing = {ip: count for ip, count in ip_dir_fuzzing.items() if count >= 3}
    high_lazy_bots = {ip: count for ip, count in lazy_bots.items() if count >= 10}

    # -------------------
    # CLI REPORT
    # -------------------
    print(f"{Colors.CYAN}{'=' * 70}")
    print(f"                     GARGANTUA LOG ANALYSIS REPORT")
    print(f"                     Created by Saeed Elfiky")
    print(f"{'=' * 70}{Colors.RESET}")
    
    if suspicious_events:
        print(f"\n{Colors.RED}[!] ALERT: Found {len(suspicious_events)} Unique Suspicious Events (Aggregated):{Colors.RESET}")
        for event in suspicious_events[:50]:
            loc = get_geo(event['ip'])
            print(f"  {Colors.YELLOW}Line: {event['first_line']:<4}{Colors.RESET} | {Colors.CYAN}IP: {event['ip']} {loc:<15}{Colors.RESET} | {Colors.RED}Threat: {event['type']}{Colors.RESET} | {Colors.ORANGE}Occurrences: {event['count']}{Colors.RESET}")
            trimmed_payload = (event['payload'][:80] + '...') if len(event['payload']) > 80 else event['payload']
            print(f"  {Colors.BOLD}Payload :{Colors.RESET} {trimmed_payload}")
            print(f"{Colors.CYAN}{'-' * 70}{Colors.RESET}")

    # Data Exfiltration
    print(f"\n{Colors.BLUE}[*] ADVANCED ANALYTICS: DATA EXFILTRATION (Large File DLs > 20MB):{Colors.RESET}")
    if data_exfil_events:
        for ev in data_exfil_events:
            loc = get_geo(ev['ip'])
            mb = int(ev['size']) / 1_000_000
            print(f"  {Colors.RED}[!!!] HIGH TRANSFER: IP {Colors.BOLD}{ev['ip']} {loc}{Colors.RESET}{Colors.RED} transferred {mb:.2f} MB!{Colors.RESET}")
    else:
        print(f"  {Colors.GREEN}[+] No anomalous high-volume data transfers.{Colors.RESET}")

    print(f"\n{Colors.BLUE}[*] ADVANCED ANALYTICS: PRECISION DIRECTORY FUZZING:{Colors.RESET}")
    if high_fuzzing:
        for ip, count in high_fuzzing.items():
            loc = get_geo(ip)
            print(f"  {Colors.YELLOW}[!] FUZZING: IP {Colors.BOLD}{ip} {loc}{Colors.RESET}{Colors.YELLOW} hit {count} hidden/sensitive paths (40x errors).{Colors.RESET}")
    else:
        print(f"  {Colors.GREEN}[+] No targeted directory fuzzing detected.{Colors.RESET}")
        
    print(f"\n{Colors.BLUE}[*] ADVANCED ANALYTICS: AUTOMATED LAZY BOT TOOLING:{Colors.RESET}")
    if high_lazy_bots:
        for ip, count in high_lazy_bots.items():
            loc = get_geo(ip)
            print(f"  {Colors.ORANGE}[!] BOT: IP {Colors.BOLD}{ip} {loc}{Colors.RESET}{Colors.ORANGE} used Null/Automated User-Agents {count} times.{Colors.RESET}")
    else:
         print(f"  {Colors.GREEN}[+] No lazy scripts bypassing heuristics detected.{Colors.RESET}")

    print(f"\n{Colors.BLUE}[*] BEHAVIORAL: DENIAL OF SERVICE (DoS) & SCRAPING (Rate-Based):{Colors.RESET}")
    if dos_ips:
        for ip, rpm in dos_ips.items():
            print(f"  {Colors.RED}[!!!] DoS ALERT: IP Address {Colors.BOLD}{ip}{Colors.RESET}{Colors.RED} hit a severe peak of {rpm} requests/min.{Colors.RESET}")
    if not dos_ips and not scraping_ips:
        print(f"  {Colors.GREEN}[+] Traffic rates are optimal. No Scraping or DoS behavior detected.{Colors.RESET}")

    print(f"\n{Colors.CYAN}{'=' * 70}{Colors.RESET}")

    report_data = {
        "file_analyzed": file_path,
        "suspicious_events": suspicious_events,
        "dos_ips": dos_ips,
        "scraping_ips": scraping_ips,
        "high_failure_ips": high_failures,
        "high_5xx": high_5xx,
        "high_sensitive": high_sensitive,
        "suspicious_methods": ip_suspicious_methods,
        "high_fuzzing": high_fuzzing,
        "data_exfil_events": data_exfil_events,
        "high_lazy_bots": high_lazy_bots
    }

    if json_export: export_json(report_data, json_export)
    if html_export: export_html(report_data, html_export)
    if md_export: export_md(report_data, md_export)
    if csv_export: export_csv(report_data, csv_export)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Gargantua - Supermassive Web Threat Analysis Engine")
    parser.add_argument("-f", "--file", required=True, help="Path to the access.log file to analyze")
    parser.add_argument("-j", "--json", help="Export to JSON (e.g., report.json)")
    parser.add_argument("-H", "--html", help="Export to HTML (e.g., report.html)")
    parser.add_argument("-md", "--markdown", help="Export to Markdown (e.g., report.md)")
    parser.add_argument("-c", "--csv", help="Export to CSV (e.g., report.csv)")
    
    args = parser.parse_args()
    analyze_logs(args.file, json_export=args.json, html_export=args.html, md_export=args.markdown, csv_export=args.csv)
