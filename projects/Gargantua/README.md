#  Gargantua: Supermassive Web Threat Analysis Engine
**Created by Saeed Elfiky**
```text
  ____    _    ____   ____    _    _   _ _____ _   _    _    
 / ___|  / \  |  _ \ / ___|  / \  | \ | |_   _| | | |  / \   
| |  _  / _ \ | |_) | |  _  / _ \ |  \| | | | | | | | / _ \  
| |_| |/ ___ \|  _ <| |_| |/ ___ \| |\  | | | | |_| |/ ___ \ 
 \____/_/   \_\_| \_\\____/_/   \_\_| \_| |_|  \___//_/   \_\
      :: Supermassive Web Threat Analysis Engine ::
```
<p align ="center">
    <img src= "logo1.svg"
</p>

A Python-based cybersecurity tool designed to parse standard web server access logs (like Apache and Nginx). It acts as an active threat-hunting utility by transcending chaotic log data and detecting both **signature-based attacks** (like SQL Injection, XSS, and Path Traversal) and **behavioral anomalies** (like high-volume scraping and brute-force attempts).

---

##  Features

* **Signature Detection:** Uses robust Regex to spot malicious payloads inside requested URLs.
  * SQL Injection (`OR 1=1`, `UNION SELECT`)
  * Cross-Site Scripting / XSS (`<script>`, `onload=`)
  * Path Traversal (`../../etc/passwd`)
* **Scanner Recognition:** Identifies known automated vulnerability scanners via the `User-Agent` HTTP header (e.g., Nikto, Nmap, SQLmap, Masscan).
* **Behavioral Heuristics:**
  * **Brute Force & Credential Stuffing:** Flags IP addresses that trigger an excessive number of `401 Unauthorized` or `403 Forbidden` Server HTTP responses.
  * **Denial of Service (DoS) & Scraping:** Identifies highly irregular volume spikes in traffic frequency originating from a single IP address.
* **Syntax Highlighting:** Highly readable CLI terminal output utilizing native ANSI color codes to quickly distinguish real alerts from benign traffic visually.
* **XSS-Safe HTML Dashboard Export:** The analyzer can dynamically generate and export a styled `report.html` or a structured `report.json` array. Threat payloads are rigorously sanitised with Python's `html.escape()` wrapper before rendering, preventing highly ironic Stored-XSS injection loops within the tool itself.

---

##  Prerequisites

* Python 3.x installed on your operating system.
* No external libraries are required. The script safely relies purely on Python's robust built-in modules (`re`, `argparse`, `os`, `collections`, `urllib`).

---

##  Installation & Usage

1. Open a terminal, command prompt, or PowerShell window.
2. Navigate to the project directory:
   ```bash
   cd Gargantua/
   ```
3. Run the script and pass the path to your target `.log` file as an argument using the `-f` flag. 
   
   **Test run the analyzer using the provided dummy log file:**
   ```bash
   python Gargantua.py -f file.log
   ```

4. **Exporting Custom Reports:**
   You can easily output the threat analysis to an HTML dashboard or a structured JSON file for SIEM ingestion using the `-H` and `-j` flags respectively:
   ```bash
   python Gargantua.py -f dummy_access.log -j report.json -H report.html
   ```

5. **Running against a real server:**
   Simply point the script at an actual live Apache or Nginx access log file on your system.
   
   *(Example for an Apache server installed locally via XAMPP):*
   ```bash
   python Gargantua.py -f "C:\xampp\apache\logs\access.log"
   ```

   *(Example for a Linux Server):*
   ```bash
   python Gargantua.py -f "/var/log/apache2/access.log"
   ```

---

##  Interpreting the Output

The tool smartly uses native terminal color codes to help prioritize critical situations rapidly:
* 🔵 **Blue:** Section headers and baseline report information.
* 🩵 **Cyan:** Malicious Source IP Addresses and UI table dividers.
* 🔴 **Red:** Critical Threat Types (SQLi, XSS, Path Traversal), and system file-reading errors.
* 🟡 **Yellow:** Line numbers and Behavioral Anomalies (like identifying sudden Brute-Force or HTTP request volume anomalies).
* 🟢 **Green:** Safe states (e.g., "No signature-based web attacks detected").

---

##  Extending the Tool
If you wish to scale this project up later, consider adding:
1. **Dynamic Geolocation Data:** Integrate an IP look-up library like `geoip2` to immediately display down to the city/country where the attacks are originating.
2. **Dashboard UI Integration:** Attach an export flag (e.g., `-json`) to print the final analysis array into a JSON file, which could be ingested by a web dashboard or a larger SIEM system.
