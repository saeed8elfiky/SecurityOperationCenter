import re
import argparse
import os
import json
from datetime import datetime
from collections import defaultdict
import html
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
    "Path Traversal": re.compile(r"(\.\./)|(\.\.%2f)|(%2e%2e%2f)|(%2e%2e/)", re.IGNORECASE),
    "Malicious User-Agent (Scanners)": re.compile(r"(nikto|nmap|sqlmap|dirbuster|zmcat|masscan)", re.IGNORECASE)
}

LOGO = r"""
 _____ _            _____                              _   
|_   _| |__   ___  |_   _|__  ___ ___  ___ _ __ __ _  ___| |_ 
  | | | '_ \ / _ \   | |/ _ \/ __/ __|/ _ \ '__/ _` |/ __| __|
  | | | | | |  __/   | |  __/\__ \__ \  __/ | | (_| | (__| |_ 
  |_| |_| |_|\___|   |_|\___||___/___/\___|_|  \__,_|\___|\__|
      :: 5-Dimensional Web Threat Analysis Engine ::
                 Created by Saeed Elfiky
"""

def parse_log_line(line):
    """Parses a single line of an Apache/Nginx combined log format."""
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
            table {{ width: 100%; border-collapse: collapse; margin-top: 15px; font-size: 14px; }}
            th, td {{ border: 1px solid #ddd; padding: 12px; text-align: left; }}
            th {{ background-color: #2c3e50; color: white; }}
            .warning {{ background-color: #fdf2f2; }}
            .info {{ background-color: #e2f0d9; padding: 15px; border-radius: 5px; }}
            .code-snippet {{ background: #f8f9fa; border: 1px solid #ccc; padding: 4px; border-radius: 4px; font-family: monospace; word-break: break-all; }}
            .threat-badge {{ background: #d9534f; color: white; padding: 4px 8px; border-radius: 4px; font-weight: bold; font-size: 12px; }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🛡️ The Tesseract: Web Log Dashboard</h1>
            <p><strong>Created by:</strong> Saeed Elfiky</p>
            <p><strong>Generated on:</strong> {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
            <p><strong>Analyzed File:</strong> {report_data['file_analyzed']}</p>
    """

    # Section 1: Signature Detections
    html_content += "<h2>Suspicious Events (Signatures)</h2>"
    if report_data["suspicious_events"]:
        html_content += """
        <table>
            <tr><th>Line</th><th>Source IP</th><th>Threat Type</th><th>Request Payload Snippet</th></tr>
        """
        for event in report_data["suspicious_events"]:
            # Prevent stored XSS by securely escaping malicious log payloads before writing to HTML dashboard
            safe_payload = html.escape(event['payload'])
            snippet = safe_payload[:100] + '...' if len(safe_payload) > 100 else safe_payload
            html_content += f"<tr class='warning'><td>{event['line_no']}</td><td><strong>{event['ip']}</strong></td><td><span class='threat-badge'>{event['type']}</span></td><td><span class='code-snippet'>{snippet}</span></td></tr>"
        html_content += "</table>"
    else:
        html_content += "<p class='info'>No signature-based web attacks detected in this log.</p>"

    # Section 2: High Traffic
    html_content += "<h2>High Traffic IPs (Potential DoS / Scraping)</h2>"
    if report_data["high_traffic_ips"]:
        html_content += "<table><tr><th>Source IP</th><th>Request Count</th></tr>"
        for ip, count in report_data["high_traffic_ips"].items():
            html_content += f"<tr class='warning'><td><strong>{ip}</strong></td><td>{count}</td></tr>"
        html_content += "</table>"
    else:
        html_content += "<p class='info'>Request volume frequency is normal across all IPs.</p>"

    # Section 3: High Failures
    html_content += "<h2>High 40x Error Rates (Potential Brute-Force / Scanning)</h2>"
    if report_data["high_failure_ips"]:
        html_content += "<table><tr><th>Source IP</th><th>Failure Count</th></tr>"
        for ip, count in report_data["high_failure_ips"].items():
            html_content += f"<tr class='warning'><td><strong>{ip}</strong></td><td>{count}</td></tr>"
        html_content += "</table>"
    else:
        html_content += "<p class='info'>No unusually high authentication or access failure rates detected.</p>"

    html_content += """
        </div>
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
    
    suspicious_events = []
    ip_requests = defaultdict(int)
    ip_failed_codes = defaultdict(int)
    
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
                
                ip_requests[ip] += 1
                
                if status in ['401', '403', '404']:
                    ip_failed_codes[ip] += 1
                
                for attack_type, pattern in PATTERNS.items():
                    if attack_type == "Malicious User-Agent (Scanners)":
                        if user_agent and pattern.search(user_agent):
                            suspicious_events.append({
                                'line_no': line_no,
                                'ip': ip,
                                'type': attack_type,
                                'payload': user_agent
                            })
                    else:
                        if pattern.search(request_decoded):
                            suspicious_events.append({
                                'line_no': line_no,
                                'ip': ip,
                                'type': attack_type,
                                'payload': request_decoded
                            })

    except FileNotFoundError:
        print(f"{Colors.RED}[!] Error: File '{file_path}' not found.{Colors.RESET}")
        return
    except Exception as e:
        print(f"{Colors.RED}[!] Error parsing logs: {e}{Colors.RESET}")
        return

    # Filter behavioral anomalies
    high_traffic = {ip: count for ip, count in ip_requests.items() if count >= 15}
    high_failures = {ip: count for ip, count in ip_failed_codes.items() if count >= 5}

    # -------------------
    # CLI REPORT
    # -------------------
    print(f"{Colors.CYAN}{'=' * 70}")
    print(f"                     THE TESSERACT ANALYSIS REPORT")
    print(f"                     Created by Saeed Elfiky")
    print(f"{'=' * 70}{Colors.RESET}")
    
    if suspicious_events:
        print(f"\n{Colors.RED}[!] ALERT: Found {len(suspicious_events)} Suspicious Events based on signatures:{Colors.RESET}")
        for event in suspicious_events:
            print(f"  {Colors.YELLOW}Line {event['line_no']:<4}{Colors.RESET} | {Colors.CYAN}Source IP: {event['ip']:<15}{Colors.RESET} | {Colors.RED}Threat: {event['type']}{Colors.RESET}")
            trimmed_payload = (event['payload'][:80] + '...') if len(event['payload']) > 80 else event['payload']
            print(f"  {Colors.BOLD}Payload :{Colors.RESET} {trimmed_payload}")
            print(f"{Colors.CYAN}{'-' * 70}{Colors.RESET}")
    else:
        print(f"\n{Colors.GREEN}[+] No signature-based web attacks detected.{Colors.RESET}")

    print(f"\n{Colors.BLUE}[*] BEHAVIORAL: HIGH TRAFFIC IPs (Potential DoS / Brute Force):{Colors.RESET}")
    if high_traffic:
        for ip, count in high_traffic.items():
            print(f"  {Colors.YELLOW}[!] IP Address {Colors.BOLD}{ip}{Colors.RESET}{Colors.YELLOW} made an irregular amount of requests ({count}).{Colors.RESET}")
    else:
        print(f"  {Colors.GREEN}[+] Traffic frequency is normal.{Colors.RESET}")

    print(f"\n{Colors.BLUE}[*] BEHAVIORAL: HIGH 40x ERROR RATES (Potential Scanning / Brute Force):{Colors.RESET}")
    if high_failures:
        for ip, count in high_failures.items():
            print(f"  {Colors.YELLOW}[!] IP Address {Colors.BOLD}{ip}{Colors.RESET}{Colors.YELLOW} encountered {count} failed requests (401/403/404 HTTP Codes).{Colors.RESET}")
    else:
        print(f"  {Colors.GREEN}[+] No IPs with unusually high failure rates.{Colors.RESET}")
        
    print(f"\n{Colors.CYAN}{'=' * 70}{Colors.RESET}")

    # -------------------
    # EXPORTING LOGIC
    # -------------------
    report_data = {
        "file_analyzed": file_path,
        "suspicious_events": suspicious_events,
        "high_traffic_ips": high_traffic,
        "high_failure_ips": high_failures
    }

    if json_export:
        export_json(report_data, json_export)
    if html_export:
        export_html(report_data, html_export)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="The Tesseract - Web Threat Analysis Engine")
    parser.add_argument("-f", "--file", required=True, help="Path to the access.log file to analyze")
    parser.add_argument("-j", "--json", help="Path to output the report as a JSON file (e.g., report.json)")
    parser.add_argument("-H", "--html", help="Path to output the report as an HTML dashboard (e.g., report.html)")
    
    args = parser.parse_args()
    analyze_logs(args.file, json_export=args.json, html_export=args.html)
