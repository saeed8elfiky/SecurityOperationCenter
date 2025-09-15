# Incident Writeup - FormBook

<p align ="center">
      <img src= "/socPhoto/performa_incident/inident_analysis.svg"
      </p>



## 1 - Executive Summary

A user opened a phishing email with an attachment named `Performa Inovice P101092292891 TT slip pdf.rar.zip`, which led to execution of a FormBook information stealer on host **`CHRIS-LYONS-PC`** (IP: **`10.1.1.97`**, MAC: **`00:22:15:d4:9a:e7`**). I extracted the attachment from the email, hashed it , and matched on VirusTotal as a known malicious malware. The behavioral analysis shows that the sample drops executables, spawns `cmd.exe`, gathers credentials from browsers and Outlook, and contacts multiple Command-and-Control (C2) servers. Immediate containment, credential resets, and forensic collection are recommended!

<p align ="center">
      <img src= "/socPhoto/performa_incident/performa_attack_diagram.svg"
      </p>

---

## 2 - Evidence & Actions Performed (investigation steps)

1. **Mail extraction:** Used `ripmime` to extract the email attachment for analysis.
    
    - Example command:  
        `ripmime -i message.eml -d ./attachments/`

<p align ="center">
<img src= "/socPhoto/performa_incident/1_mail_attach.png"
</p>

        
2. **Hashing the attachment:** Created SHA256 to identify the sample.
    
    - Example command:  
        `sha256sum "Performa Inovice P101092292891 TT slip pdf.rar.zip" > attachment.sha256`

<p align ="center">
<img src= "/socPhoto/performa_incident/1_attach_hach.png"
</p>
        
3. **Threat lookup:** Queried VirusTotal with the SHA256 hash and result in: **confirmed malicious / FormBook** (high severity).

<p align ="center">
<img src= "/socPhoto/performa_incident/3_attach_virustotal.png"
</p>

    
4. **Host & network details collected:**
    
      - **Infected host IP:** `10.1.1.97`
  
<p align ="center">
<img src= "/socPhoto/performa_incident/infected_ip.png"
</p>

- **Hostname:** `CHRIS-LYONS-PC`
- **MAC:** `00:22:15:d4:9a:e7`


  <p align ="center">
      <img src= "/socPhoto/performa_incident/infected.png"
      </p>
      
5. **Primary Domain:** `www[.]ellentscm[.]info`:

<p align ="center">
<img src= "/socPhoto/performa_incident/6_primary_c2.png"
</p>
   
---

## 3 - Observed Indicators of Compromise (IOCs)

#### Files / Attachment

- `Performa Inovice P101092292891 TT slip pdf.rar.zip`. The attachment extracted via `ripmime`
    
- Dropped executables: `WinRAR.exe` (PID: 1632), `lsm.exe` (PID: 2088), `Proforma Invoice … .exe` (multiple PIDs)
    

#### Host/network IOCs

- Infected Host IP: `10.1.1.97`
    
- Hostname: `CHRIS-LYONS-PC`
    
- MAC: `00:22:15:d4:9a:e7`
    

#### C2 IP addresses (to block/monitor)

1. `103.224.212.222`

<p align ="center">
<img src= "/socPhoto/performa_incident/103.224.212.222.png"
</p>

2. `198.105.244.228`

<p align ="center">
<img src= "/socPhoto/performa_incident/198.105.244.228.png"
</p>
    
3. `175.103.55.71`
4. `162.213.212.22`
5. `209.15.20.221`
6. `23.43.62.200`
7. `34.233.12.25`
8. `50.63.202.43`
9. `69.164.223.38`
10. `81.169.145.159`
11. `91.216.107.226`
    
All these IPs are C2s and used by attacker to retrives and stole data as we can see the **Massive** content length in the `POST` Request


<p align ="center">
<img src= "/socPhoto/performa_incident/5-c2_datasole.png"
</p>


> **Actionable:** Immediately block these IPs at perimeter firewall / proxy / DNS and add to EDR blocklist.

---

## 4 - Behavioral Activities 

**Malicious**

- Dropped an executable immediately after execution (e.g., `WinRAR.exe` PID 1632).
    
- YARA signature match for **FormBook** observed on `lsm.exe` (PID 2088).
    

**Suspicious**

- The `Proforma Invoice … .exe` application launched itself multiple times (self-execution/auto-relaunch behavior).
    
- Spawned `CMD.EXE` (command interpreter) to run commands, typical post-execution behavior.
    

**Informational / Recon**

- Checked supported languages (evasion by region).
    
- Retrieved system info (computer name).
    
- Created and overwrote executable content on disk.
    
- Manual execution by user (user opened the phishing attachment).
    

---

## 5 - Strings / Data targeted (exfiltration and credential theft)

Sample strings and targets reveal intent to harvest stored credentials and system artifacts:

- Environment & paths: `LOCALAPPDATA`, `USERPROFILE`, `APPDATA`, `TEMP`, `ProgramFiles`, `CommonProgramFiles`, `ALLUSERSPROFILE`
    
- Registry and Outlook paths: `\Run`, `\Policies`, `\Explorer`, `\Registry\User`, `\Registry\Machine`, `Office\15.0\Outlook\Profiles\Outlook\`, `Windows Messaging Subsystem\Profiles\Outlook\`
    
- Browser credential targets & SQL queries: Chrome `Login Data` (`SELECT origin_url, username_value, password_value FROM logins`), Firefox `logins.json` / `signons.sqlite` (`SELECT encryptedUsername, encryptedPassword, formSubmitURL FROM moz_logins`)
    
- Credential labels: `Username:`, `Password:`, `encryptedUsername`, `encryptedPassword`, `formSubmitURL`, `usernameField`
    
- Network / HTTP: `POST`, `HTTP/1.1`, `Content-Length:`, `User-Agent: Mozilla Firefox/4.0`, `Origin: http://`, `Referer:`
    
- Privilege and artifact names: `SeDebugPrivilege`, `SeShutdownPrivilege`, `IconCache`, `ThumbCache`, `Cookies`
    
- File extensions/targets: `.exe`, `.com`, `.scr`, `.pif`, `.cmd`, `.bat`
    

**Observed inference from this :** very large `Content-Length` suggesting **Data exfiltration**, and the URI path **`/ob`** used by the malware to contact C2 (consistent with `www.ellentscm.info/ob/` observed earlier).

---

## 6  - MITRE ATT&CK Mapping


<p align ="center">
<img src= "/socPhoto/performa_incident/Saeed_Ashraf_Elfiky__Performa_Malware.svg"
</p>


- **Initial Access:** T1566: Phishing (malicious attachment)
    
- **Execution:** T1059: Command and Scripting Interpreter (`cmd.exe`)
    
    - Shared Modules / DLL loading / hollowing (sample uses module/hollowing techniques)
        
- **Persistence:** T1547 / Registry Run Keys, Boot or Logon Autostart Execution (Registry modification + startup entries)
    
- **Defense Evasion:** Rootkit / usermode inline hooks; Virtualization / Sandbox evasion; Modify/disable tools (guard pages)
    
- **Credential Access:** T1056: Input Capture / API Hooking (credential API hooking, usermode inline hooks)
    
- **Discovery:** T1010: Application Window Discovery (monitors windows/applications)
    
- **Command & Control:** T1071: Application Layer Protocol (HTTP/POST to `/ob`)
    
- **Exfiltration:** Large `Content-Length` POSTs, likely exfiltration of harvested credentials and files
    

---

## 7 - Impact Assessment

- **High probability** of credential theft (browser-saved logins, Outlook profiles).
    
- Credentials may be reused across internal services, such as **risk of lateral movement**.
    
- Data exfiltration confirmed by large POST payloads; sensitive data may already be exfiltrated.
    
- Presence of rootkit/inline hooks and persistence mechanisms increases remediation complexity.
    
- System likely compromised to high integrity.
    

---

## 8 - Containment & Recovery

**Containment (immediate)**

1. Isolate `10.1.1.97 / CHRIS-LYONS-PC` from network (remove wired and wireless).
    
2. Block the 11 C2 IPs at perimeter firewall, proxy, and on internal IDS/IPS.
    
3. Suspend the affected user account and force immediate password resets (affected and privileged accounts).
    


**Recovery**  
1. Restore user data from backups (scan backups for compromise).  
2. Re-enable and monitor the host after reimaging.  
3. Enforce credential rotation for affected services and implement MFA for all privileged access.

---

## 9 - Detection & Hunting Recommendations

- Add IDS/IPS rules to alert on HTTP POSTs to `/ob` or to C2 IPs.
    
- Create EDR detections for:
    
    - Process creation of `Proforma Invoice … .exe` and `lsm.exe` spawning `cmd.exe`.
        
    - Processes accessing browser login DB files (`Login Data`, `logins.json`, `signons.sqlite`).
        
- Search logs for large outbound HTTP `Content-Length` POSTs and for connections to the listed C2 IPs.
    
- Deploy YARA signatures for FormBook indicators and monitor matches.
    

---

## 10 - Suggested Blocking - Snort-style example

- **Firewall / Proxy:** block outbound TCP on ports 80/443 to the listed C2 IPs.
    
- **Snort**: alert http any any -> any any (msg:"Possible FormBook C2 POST /ob"; content:"/ob/"; http_method; classtype:trojan-activity; sid:1000001; rev:1;)
    

---

## 11 - Recommendations (policy & user)

1. **Mandatory password reset** for affected user and privileged users; enforce MFA.
    
2. **Reimage infected host** and verify through forensic artifacts before returning to production.
    
3. **Block C2 IPs & domains** and add to blacklists.
    
4. **Harden email gateway**: sandbox attachments, strip/extract archives, quarantine suspicious attachments.
    
5. **User awareness campaign**: phishing simulation and training to reduce click rates.
    
6. **Enable EDR & Sysmon** across endpoints for richer telemetry.
    
7. **Perform internal credential hunting**: look for reuse of credentials obtained from the compromised host.
    
---


### **Feel free to contact me on** **[LinkedIn](https://www.linkedin.com/in/saeed-elfiky-61188b24b/)**.
