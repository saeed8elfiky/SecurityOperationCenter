import re
import argparse
import os
import json
import html
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

# Define regular expressions for malicious signatures / patterns
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
    """Fetches geolocation data for a given IP address."""
    if ip.startswith(('192.168.', '10.', '172.', '127.')) or ip == '::1':
        return "[Local IP]"
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
    """Parses a single line of an Apache/Nginx combined log or JSON format."""
    line = line.strip()
    
    # Attempt to parse as JSON (e.g. Cloudflare, Traefik, AWS ALB)
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
                return {
                    'ip': ip, 'time': time_str, 'request': req, 
                    'status': status, 'size': size, 'user_agent': ua
                }
        except Exception:
            pass

    # Standard Apache/Nginx Combined Format
    log_pattern = re.compile(
        r'(?P<ip>\S+) \S+ \S+ \[(?P<time>.*?)\] "(?P<request>.*?)" (?P<status>\d{3}) (?P<size>\S+)(?: "(?P<referer>.*?)")?(?: "(?P<user_agent>.*?)")?'
    )
    match = log_pattern.match(line)
    if match:
        return match.groupdict()
    return None

def export_json(report_data, filepath):
    """Exports the analysis data to a JSON file."""
    try:
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=4)
        print(f"{Colors.GREEN}[+] JSON report successfully exported to: {filepath}{Colors.RESET}")
    except Exception as e:
        print(f"{Colors.RED}[!] Error exporting JSON: {e}{Colors.RESET}")

def export_html(report_data, filepath):
    """Exports the analysis data to a styled HTML dashboard."""
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
            <p><strong>Analyzed File:</strong> {report_data['file_analyzed']}</p>
    """

    # Section 1: Signature Detections
    html_content += "<h2>Suspicious Events (Signatures)</h2>"
    if report_data["suspicious_events"]:
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

    # Section 2: Advanced Behavioral Analytics
    html_content += "<h2>Advanced Behavioral Analytics</h2>"

    if report_data.get("high_5xx"):
        html_content += "<h3>High Internal Server Errors (50x) - Potential App Exploits/Crashes</h3>"
        html_content += "<table><tr><th>Source IP</th><th>Location</th><th>50x Error Count</th></tr>"
        for ip, count in report_data["high_5xx"].items():
            loc = get_geo(ip)
            html_content += f"<tr class='warning'><td><strong>{ip}</strong></td><td>{loc}</td><td>{count}</td></tr>"
        html_content += "</table>"

    if report_data.get("high_sensitive"):
        html_content += "<h3>Targeted Brute-Force Activity</h3>"
        html_content += "<table><tr><th>Source IP</th><th>Location</th><th>POSTs to Sensitive Endpoints</th></tr>"
        for ip, count in report_data["high_sensitive"].items():
            loc = get_geo(ip)
            html_content += f"<tr class='warning'><td><strong>{ip}</strong></td><td>{loc}</td><td>{count}</td></tr>"
        html_content += "</table>"

    if report_data.get("suspicious_methods"):
        html_content += "<h3>Unusual HTTP Methods (Reconnaissance)</h3>"
        html_content += "<table><tr><th>Source IP</th><th>Location</th><th>Methods Used</th></tr>"
        for ip, methods in report_data["suspicious_methods"].items():
            loc = get_geo(ip)
            html_content += f"<tr class='warning'><td><strong>{ip}</strong></td><td>{loc}</td><td><span class='badge-recon'>{', '.join(methods)}</span></td></tr>"
        html_content += "</table>"
        
    if not (report_data.get("high_5xx") or report_data.get("high_sensitive") or report_data.get("suspicious_methods")):
        html_content += "<p class='info'>No advanced anomalies detected.</p>"

    # Section 3: High Traffic / Volume
    html_content += "<h2>Traffic Anomalies (DoS / Scraping)</h2>"
    
    # DoS Attack Level
    if report_data.get("dos_ips"):
        html_content += "<h3>Severe Traffic (Potential DoS Attacks)</h3>"
        html_content += "<table><tr><th>Source IP</th><th>Location</th><th>Peak Requests/Minute</th><th>Status</th></tr>"
        for ip, count in report_data["dos_ips"].items():
            loc = get_geo(ip)
            html_content += f"<tr class='warning'><td><strong>{ip}</strong></td><td>{loc}</td><td>{count}</td><td><span class='threat-badge' style='background-color:#c0392b;'>DoS/DDoS</span></td></tr>"
        html_content += "</table>"
        
    # Scraping Level
    if report_data.get("scraping_ips"):
        html_content += "<h3>High Traffic (Potential Scraping / Bots)</h3>"
        html_content += "<table><tr><th>Source IP</th><th>Location</th><th>Peak Requests/Minute</th><th>Status</th></tr>"
        for ip, count in report_data["scraping_ips"].items():
            loc = get_geo(ip)
            html_content += f"<tr class='warning'><td><strong>{ip}</strong></td><td>{loc}</td><td>{count}</td><td><span class='threat-badge' style='background-color:#e67e22;'>Scraping</span></td></tr>"
        html_content += "</table>"

    if not report_data.get("dos_ips") and not report_data.get("scraping_ips"):
        html_content += "<p class='info'>Request volumes are within normal thresholds (No DoS/Scraping detected).</p>"

    # Section 4: High Failures
    html_content += "<h2>High 40x Error Rates (Potential Directory Scanning / File Discovery)</h2>"
    if report_data["high_failure_ips"]:
        html_content += "<table><tr><th>Source IP</th><th>Location</th><th>Failure Count</th></tr>"
        for ip, count in report_data["high_failure_ips"].items():
            loc = get_geo(ip)
            html_content += f"<tr class='warning'><td><strong>{ip}</strong></td><td>{loc}</td><td>{count}</td></tr>"
        html_content += "</table>"
    else:
        html_content += "<p class='info'>No unusually high authentication or resource failure rates detected.</p>"

    # Section 5: Fake Bots
    if report_data.get("fake_bots"):
        html_content += "<h2>Fake Search Engine Bots (Spoofed User Agents)</h2>"
        html_content += "<table><tr><th>Source IP</th><th>Location</th><th>Spoofed User-Agent</th></tr>"
        for ip, ua in report_data["fake_bots"].items():
            loc = get_geo(ip)
            html_content += f"<tr class='warning'><td><strong>{ip}</strong></td><td>{loc}</td><td><span class='code-snippet'>{html.escape(ua)}</span></td></tr>"
        html_content += "</table>"

    # Prepare Threat Type Distribution for Chart.js
    threat_counts = defaultdict(int)
    if "suspicious_events" in report_data:
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


def analyze_logs(file_path, json_export=None, html_export=None):
    print(f"{Colors.ORANGE}{LOGO}{Colors.RESET}")
    print(f"{Colors.BLUE}[*] Starting Log Analysis on: {Colors.BOLD}{file_path}{Colors.RESET}\n")
    
    suspicious_events_dict = {}
    claimed_bots = {}
    ip_requests = defaultdict(int)
    ip_failed_codes = defaultdict(int)
    ip_5xx_codes = defaultdict(int)
    ip_sensitive_posts = defaultdict(int)
    ip_suspicious_methods = defaultdict(list)
    ip_time_requests = defaultdict(lambda: defaultdict(int)) # Maps IP -> Minute -> Count
    
    sensitive_endpoints = re.compile(r"(/wp-login\.php|/admin|/cpanel|/login|/administrator|/xmlrpc\.php)", re.IGNORECASE)
    unusual_methods = {"PUT", "DELETE", "TRACE", "OPTIONS", "CONNECT"}
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for line_no, line in enumerate(f, 1):
                data = parse_log_line(line)
                if not data:
                    continue
                
                request_decoded = unquote(data['request'])
                user_agent = data.get('user_agent', '')
                ip = data['ip']
                status = data['status']
                timestamp = data.get('time', '')
                
                # Extract minute identifier
                time_parts = timestamp.split(':')
                if len(time_parts) >= 3:
                    minute_str = f"{time_parts[0]}:{time_parts[1]}:{time_parts[2]}"
                else:
                    minute_str = "unknown"
                
                ip_requests[ip] += 1
                ip_time_requests[ip][minute_str] += 1
                
                if status.startswith('4'):
                    ip_failed_codes[ip] += 1
                elif status.startswith('5'):
                    ip_5xx_codes[ip] += 1
                
                # Method parsing for advanced analytics
                method = "UNKNOWN"
                parts = request_decoded.split()
                if len(parts) >= 1:
                    method = parts[0].upper()
                    
                if method in unusual_methods:
                    if method not in ip_suspicious_methods[ip]:
                        ip_suspicious_methods[ip].append(method)
                        
                if method == "POST" and sensitive_endpoints.search(request_decoded):
                    ip_sensitive_posts[ip] += 1
                
                if user_agent and re.search(r'(Googlebot|Bingbot|Baiduspider|YandexBot|Slurp|DuckDuckBot)', user_agent, re.IGNORECASE):
                    claimed_bots[ip] = user_agent
                
                for attack_type, pattern in PATTERNS.items():
                    matched = False
                    payload = ""
                    if attack_type == "Malicious User-Agent (Scanners)":
                        if user_agent and pattern.search(user_agent):
                            matched = True
                            payload = user_agent
                    else:
                        if pattern.search(request_decoded):
                            matched = True
                            payload = request_decoded
                        elif user_agent and pattern.search(user_agent):
                            matched = True
                            payload = user_agent

                    if matched:
                        event_key = (ip, attack_type)
                        if event_key not in suspicious_events_dict:
                            suspicious_events_dict[event_key] = {
                                'first_line': line_no,
                                'count': 1,
                                'ip': ip,
                                'type': attack_type,
                                'payload': payload
                            }
                        else:
                            suspicious_events_dict[event_key]['count'] += 1

    except FileNotFoundError:
        print(f"{Colors.RED}[!] Error: File '{file_path}' not found.{Colors.RESET}")
        return
    except Exception as e:
        print(f"{Colors.RED}[!] Error parsing logs: {e}{Colors.RESET}")
        return

    suspicious_events = list(suspicious_events_dict.values())

    # Rate-based behavioral anomalies (Requests Per Minute)
    ip_max_rpm = {}
    for ip, minutes in ip_time_requests.items():
        ip_max_rpm[ip] = max(minutes.values()) if minutes else 0

    scraping_ips = {ip: rpm for ip, rpm in ip_max_rpm.items() if 60 <= rpm < 150}
    dos_ips = {ip: rpm for ip, rpm in ip_max_rpm.items() if rpm >= 150}
    
    # Analyze Advanced Behaviours
    high_failures = {ip: count for ip, count in ip_failed_codes.items() if count >= 20}
    high_5xx = {ip: count for ip, count in ip_5xx_codes.items() if count >= 5}
    high_sensitive = {ip: count for ip, count in ip_sensitive_posts.items() if count >= 5}

    # Detect Fake Bots
    fake_bots = {}
    suspicious_ips = {evt['ip'] for evt in suspicious_events}
    for ip, ua in claimed_bots.items():
        if ip in dos_ips or ip in scraping_ips or ip in suspicious_ips or ip in high_5xx or ip in high_sensitive:
            fake_bots[ip] = ua

    # -------------------
    # CLI REPORT
    # -------------------
    print(f"{Colors.CYAN}{'=' * 70}")
    print(f"                     GARGANTUA LOG ANALYSIS REPORT")
    print(f"                     Created by Saeed Elfiky")
    print(f"{'=' * 70}{Colors.RESET}")
    
    if suspicious_events:
        print(f"\n{Colors.RED}[!] ALERT: Found {len(suspicious_events)} Unique Suspicious Events (Aggregated):{Colors.RESET}")
        for event in suspicious_events:
            loc = get_geo(event['ip'])
            print(f"  {Colors.YELLOW}Line: {event['first_line']:<4}{Colors.RESET} | {Colors.CYAN}IP: {event['ip']} {loc:<15}{Colors.RESET} | {Colors.RED}Threat: {event['type']}{Colors.RESET} | {Colors.ORANGE}Occurrences: {event['count']}{Colors.RESET}")
            trimmed_payload = (event['payload'][:80] + '...') if len(event['payload']) > 80 else event['payload']
            print(f"  {Colors.BOLD}Payload :{Colors.RESET} {trimmed_payload}")
            print(f"{Colors.CYAN}{'-' * 70}{Colors.RESET}")
    else:
        print(f"\n{Colors.GREEN}[+] No signature-based web attacks detected.{Colors.RESET}")

    # Advanced Analysis Triggers
    print(f"\n{Colors.BLUE}[*] ADVANCED ANALYTICS: INTERNAL SERVER ERRORS (50x) (Potential Exploits):{Colors.RESET}")
    if high_5xx:
        for ip, count in high_5xx.items():
            loc = get_geo(ip)
            print(f"  {Colors.RED}[!!!] CRITICAL: IP Address {Colors.BOLD}{ip} {loc}{Colors.RESET}{Colors.RED} caused {count} internal server errors!{Colors.RESET}")
    else:
        print(f"  {Colors.GREEN}[+] No IPs generating unusual 50x errors.{Colors.RESET}")

    print(f"\n{Colors.BLUE}[*] ADVANCED ANALYTICS: SENSITIVE ENDPOINT BRUTE-FORCING:{Colors.RESET}")
    if high_sensitive:
        for ip, count in high_sensitive.items():
            loc = get_geo(ip)
            print(f"  {Colors.RED}[!!!] ALERT: IP {Colors.BOLD}{ip} {loc}{Colors.RESET}{Colors.RED} made {count} POST requests to sensitive endpoints.{Colors.RESET}")
    else:
        print(f"  {Colors.GREEN}[+] No targeted brute-forcing detected.{Colors.RESET}")

    print(f"\n{Colors.BLUE}[*] ADVANCED ANALYTICS: UNUSUAL HTTP METHODS (Reconnaissance):{Colors.RESET}")
    if ip_suspicious_methods:
        for ip, methods in ip_suspicious_methods.items():
            loc = get_geo(ip)
            print(f"  {Colors.YELLOW}[!] RECON: IP {Colors.BOLD}{ip} {loc}{Colors.RESET}{Colors.YELLOW} used suspicious methods: {', '.join(methods)}.{Colors.RESET}")
    else:
        print(f"  {Colors.GREEN}[+] No unusual HTTP methods generated.{Colors.RESET}")

    print(f"\n{Colors.BLUE}[*] BEHAVIORAL: DENIAL OF SERVICE (DoS) & SCRAPING (Rate-Based):{Colors.RESET}")
    if dos_ips:
        for ip, rpm in dos_ips.items():
            loc = get_geo(ip)
            print(f"  {Colors.RED}[!!!] DoS ALERT: IP Address {Colors.BOLD}{ip} {loc}{Colors.RESET}{Colors.RED} hit a severe peak of {rpm} requests/min.{Colors.RESET}")
    
    if scraping_ips:
        for ip, rpm in scraping_ips.items():
            loc = get_geo(ip)
            print(f"  {Colors.ORANGE}[!] SCRAPING: IP Address {Colors.BOLD}{ip} {loc}{Colors.RESET}{Colors.ORANGE} hit a high volume of {rpm} requests/min.{Colors.RESET}")
    
    if not dos_ips and not scraping_ips:
        print(f"  {Colors.GREEN}[+] Traffic rates are optimal. No Scraping or DoS behavior detected.{Colors.RESET}")

    print(f"\n{Colors.BLUE}[*] BEHAVIORAL: HIGH 40x ERROR RATES (Potential Scanning / Brute Force):{Colors.RESET}")
    if high_failures:
        for ip, count in high_failures.items():
            loc = get_geo(ip)
            print(f"  {Colors.YELLOW}[!] IP Address {Colors.BOLD}{ip} {loc}{Colors.RESET}{Colors.YELLOW} encountered {count} failed requests (40x HTTP Codes).{Colors.RESET}")
    else:
        print(f"  {Colors.GREEN}[+] No IPs with unusually high 40x failure rates.{Colors.RESET}")
    
    if fake_bots:
        print(f"\n{Colors.BLUE}[*] BEHAVIORAL: FAKE SEARCH ENGINE BOTS (Spoofed User-Agents):{Colors.RESET}")
        for ip, ua in fake_bots.items():
            loc = get_geo(ip)
            print(f"  {Colors.RED}[!!!] FAKE BOT: {Colors.BOLD}{ip} {loc}{Colors.RESET}{Colors.RED} claimed to be a Search Engine but committed attacks.{Colors.RESET}")

    print(f"\n{Colors.CYAN}{'=' * 70}{Colors.RESET}")

    # -------------------
    # EXPORTING LOGIC
    # -------------------
    report_data = {
        "file_analyzed": file_path,
        "suspicious_events": suspicious_events,
        "dos_ips": dos_ips,
        "scraping_ips": scraping_ips,
        "high_failure_ips": high_failures,
        "fake_bots": fake_bots,
        "high_5xx": high_5xx,
        "high_sensitive": high_sensitive,
        "suspicious_methods": ip_suspicious_methods
    }

    if json_export:
        export_json(report_data, json_export)
    if html_export:
        export_html(report_data, html_export)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Gargantua - Supermassive Web Threat Analysis Engine")
    parser.add_argument("-f", "--file", required=True, help="Path to the access.log file to analyze")
    parser.add_argument("-j", "--json", help="Path to output the report as a JSON file (e.g., report.json)")
    parser.add_argument("-H", "--html", help="Path to output the report as an HTML dashboard (e.g., report.html)")
    
    args = parser.parse_args()
    analyze_logs(args.file, json_export=args.json, html_export=args.html)
