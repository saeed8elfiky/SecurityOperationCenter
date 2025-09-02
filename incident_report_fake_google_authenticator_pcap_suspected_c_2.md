# Incident Report – Fake “Google Authenticator” (PCAP) / Suspected C2

**Prepared by:** SOC Analyst  
**Environment (per brief):**  
- LAN: `10.1.17.0/24`  
- Domain: `bluemoontuesday[.]com` (AD env name: **BLUEMOONTUESDAY**)  
- AD DC: `WIN-GSHS4OLW48D` @ `10.1.17.12` *(as interpreted from the brief)*  
- File provided: `Google Authenticator.pcap`

---

## 1) Executive Summary
A user reportedly searched for “Google Authenticator” and downloaded a suspicious file. Network captures reveal the infected Windows client established clear‑text HTTP sessions to download files (including a **PowerShell script**), and maintained **TLS sessions over a non‑standard port** to external IPs with **SNI set to an IP address** (not a domain)—all strong indicators of **command‑and‑control (C2)** activity and staged payload retrieval. The activity appears unrelated to any legitimate Google services and involves **typosquatting** on a domain resembling “Google Authenticator”.

Impact risk includes credential theft, host compromise, and potential lateral movement within the BLUEMOONTUESDAY AD environment. Immediate containment is recommended.

---

## 2) Answers to Incident Questions (from PCAP analysis & screenshots provided)
- **Infected Windows client (IP):** `10.1.17.215`
- **Infected Windows client (MAC):** `00:d0:b7:26:4a:74`
- **Host name:** `DESKTOP-L8C5GSJ` *(observed in DNS response)*
- **User account name:** `shutchenson` *(observed in Kerberos AS‑REQ from the client)*
- **Likely fake “Google Authenticator” domain:** `authenticatoor[.]org` *(typosquatting / misspelling)*
- **C2 / malicious infrastructure IPs observed:**
  - **`5.252.153.241`** – clear‑text HTTP **GET /api/file/get-file/**… including **`.ps1`** payload retrieval
  - **`45.125.66.32`** – **TLS over non‑standard port 2917**, sustained encrypted application data, **SNI = IP**
  - **`44.125.66.252`** – noted in observations; verify in original PCAP as likely related infrastructure

Additional external IPs seen in the capture (may include benign/CDN or staging traffic; treat with caution): `23.220.102.9`, `199.232.214.172`, others.

---

## 3) Key Evidence (from the provided screenshots/PCAP snippets)
1. **HTTP file retrieval from `5.252.153.241`**  
   - Example request: `GET /api/file/get-file/264872 HTTP/1.1`  
   - Another: `GET /api/file/get-file/29842.ps1` → **PowerShell script download**  
   - Multiple **404 Not Found** responses across various paths suggest automated probing/rota for staging or versioning endpoints.  
   - **User‑Agent anomaly:** `Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 10.0; ...)` → outdated UA impersonation typical of malware.

2. **TLS over non‑standard port (suspected C2)**  
   - Client `10.1.17.215` ↔ Server **`45.125.66.32:2917`**  
   - Normal TCP handshake then **TLS 1.2** handshake; subsequent payload as **Application Data (encrypted)**.  
   - **SNI = numeric IP** rather than domain → unusual for legitimate services; strong evasion indicator.

3. **Host & user identification**  
   - **DNS** response resolved the client hostname: `DESKTOP-L8C5GSJ`.  
   - **Kerberos** AS‑REQ from `10.1.17.215` contains user principal **`shutchenson`**, confirming the interacting domain user.

4. **Typosquatting domain**  
   - Reported access to `authenticatoor[.]org` (misspelling of “authenticator”) linked to the user’s search; consistent with drive‑by/download lure.

---

## 4) Attack Narrative / Timeline (relative to capture)
> **T+00:00 – T+00:10**  
> Normal background HTTP like `GET /connecttest.txt` to `23.220.102.9` (Windows connectivity checks).  
>
> **T+01:00+**  
> Client `10.1.17.215` initiates **HTTP GET** to `5.252.153.241` for `/api/file/get-file/264872`, followed by repeated requests including a **`.ps1`** file.  
>
> **Subsequent minutes**  
> Client opens **TLS 1.2** sessions to `45.125.66.32:2917` with **SNI=IP** and large volumes of encrypted **Application Data**, consistent with beaconing/C2 tasking and results exfil over web protocols.

*(Exact timestamps/frames can be pinned from the original PCAP if needed.)*

---

## 5) Assessment & Hypotheses
- **Initial Access:** User search for “Google Authenticator” → visit to **typosquatted domain** `authenticatoor[.]org` → download/execution of malicious payload.  
- **Execution:** **PowerShell** script retrieved over HTTP from `5.252.153.241` (e.g., `.../get-file/29842.ps1`).  
- **Command & Control:** **TLS over non‑standard port 2917** to `45.125.66.32` with IP‑based SNI; continuous application data exchange.  
- **Discovery/Lateral Movement Risk:** Presence of **Kerberos** traffic from the host confirms it’s domain‑joined (`BLUEMOONTUESDAY`), increasing risk to AD if credentials were captured or tokens abused.

**Why this looks like C2:**  
- Non‑standard TLS port; SNI=IP; sustained encrypted payloads  
- Clear‑text staged payload retrieval (PowerShell) via **`/api/file/get-file`**  
- Anomalous UA string inconsistent with Win10 modern browsers  
- Multiple probing/404s typical of staged infra / maltooling

---

## 6) MITRE ATT&CK Mapping (likely)
- **T1566 / T1204.001** – User Execution via malicious site (typosquatting lure)  
- **T1189** – Drive‑by Compromise (from browsing to fake site)  
- **T1059.001** – Command Shell: **PowerShell**  
- **T1105 / T1071.001** – Ingress Tool Transfer & C2 over **web protocols (HTTP/TLS)**  
- **T1036** – Masquerading (old/odd User‑Agent)  
- **T1041** – Exfiltration over C2 channel *(potential)*

---

## 7) Indicators of Compromise (IOCs)
**Hosts / IPs**  
- `10.1.17.215` – infected client  
- `5.252.153.241` – malicious file hosting/API  
- `45.125.66.32:2917` – suspected C2 (TLS)  
- `44.125.66.252` – noted as related; **verify in PCAP**  
- Additional external contacts observed: `23.220.102.9`, `199.232.214.172` *(context‑dependent)*

**Domains**  
- `authenticatoor[.]org` – fake “Google Authenticator” page (typosquatting)

**URLs / Paths**  
- `/api/file/get-file/264872`  
- `/api/file/get-file/29842.ps1`  
- `/filestreamingservice/files/<uuid>` *(HEAD/GET attempts, frequent 404s)*

**Ports / Protocols**  
- **HTTP/80** to `5.252.153.241` (clear‑text downloads)  
- **TLS 1.2 over TCP/2917** to `45.125.66.32`

**User‑Agent**  
- `Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 10.0; ...)` *(suspicious)*

---

## 8) Detection & Hunting Notes
**Wireshark filters:**  
- Infected host focus:  
  `ip.addr == 10.1.17.215 && (http || tls || tcp.port == 2917)`  
- Suspicious HTTP paths:  
  `http.request.uri contains "/api/file/get-file"`  
- PowerShell downloads:  
  `http.request.uri contains ".ps1"`  
- Kerberos user extraction:  
  `kerberos.CNameString` and `ip.addr == 10.1.17.215`  
- TLS SNI is an IP:  
  `tls.handshake.extensions_server_name matches "^\d+\.\d+\.\d+\.\d+$"`

**Zeek (Bro) ideas:**  
- Hunt in `http.log` for `uri` containing `/api/file/get-file/` or `.ps1`  
- Flag `ssl.log` where `server_name` is an **IPv4 literal** and `port != 443`

**Suricata/Snort sample rules:**
```snort
alert http any any -> any any (msg:"Suspicious file API get-file"; http.uri; content:"/api/file/get-file/"; nocase; classtype:trojan-activity; sid:100001; rev:1;)
alert http any any -> any any (msg:"PowerShell script download"; http.uri; content:".ps1"; nocase; classtype:trojan-activity; sid:100002; rev:1;)
alert tls any any -> any 2917 (msg:"TLS on non-standard port"; flow:to_server,established; classtype:policy-violation; sid:100003; rev:1;)
```

**Windows Telemetry / EDR hunts:**  
- **Event 4688** or **Sysmon Event ID 1** – suspicious `powershell.exe` (look for `-ExecutionPolicy Bypass`, `-EncodedCommand`, `Invoke-WebRequest`, `iwr`, `DownloadString`).  
- **Sysmon Event ID 3** – network connections from `powershell.exe` to the listed IOCs.  
- **DNS logs** – queries for `authenticatoor[.]org`.  
- **Browser history** (if available) – referrers/ads leading to the typosquat.

---

## 9) Containment, Eradication, Recovery (Immediate Actions)
1. **Isolate** host `10.1.17.215` from the network.  
2. **Block** at egress: `5.252.153.241`, `45.125.66.32:2917`, and **sinkhole** `authenticatoor[.]org`.  
3. **Credential hygiene:** Force password reset for user **`shutchenson`** and review recent Kerberos TGT activity.  
4. **Collect forensics:** Full volatile capture (RAM) + disk triage from `10.1.17.215`.  
5. **EDR sweep** across the subnet for the same indicators (UA string, HTTP paths, connections to the IOCs).  
6. **Remove persistence:** Check Run keys, Scheduled Tasks, Services, WMI subscriptions; block **PowerShell** download‑cradles via GPO/AppLocker/WDAC.  
7. **Patch & harden:** Browser + OS updates; enforce **HTTPS‑only**, DNS filtering, and ad/typosquat protection.

**Recovery & Monitoring:**  
- Reimage if integrity cannot be ensured; rejoin domain.  
- Monitor for repeated TLS on high ports and IP‑literal SNI.  
- Add detections for `/api/file/get-file/` and `.ps1` downloads.

---

## 10) Risk & Impact
- **Data exposure risk:** Credential theft (browser/SSO), potential token abuse.  
- **Operational risk:** Further compromise of BLUEMOONTUESDAY AD if lateral movement occurs.  
- **Reputation/compliance:** Use of malicious infrastructure; logging gaps if HTTP allowed outbound.

---

## 11) Lessons Learned / Preventive Controls
- **Secure web gateway / DNS filtering** for typosquatting domains; enable **Safe Browsing** and ad‑blocking.  
- **Egress controls**: restrict outbound to required destinations/ports; block **unknown high‑ports TLS**.  
- **Script controls**: AppLocker/WDAC to restrict PowerShell; enable **Constrained Language Mode** & PowerShell logging (Module, ScriptBlock).  
- **User awareness**: training on fake download sites; verify publishers, use official stores.  
- **Threat intel**: continuously ingest typosquat feeds; monitor IP‑literal SNI and outdated UA strings.

---

## 12) Appendices
### A) How the artifacts were identified (replicable steps)
- **Client identity:** `ip.addr == 10.1.17.215`; check **DNS** for hostname `DESKTOP-L8C5GSJ`; **Kerberos AS‑REQ** to extract username `shutchenson`.  
- **MAC address:** from Ethernet layer in frames sourced by `10.1.17.215` (e.g., the HTTP GET to `5.252.153.241`).  
- **Malicious HTTP:** filter `http && ip.addr == 10.1.17.215` then inspect URIs `/api/file/get-file/...` and `*.ps1`.  
- **Suspected C2:** filter `tcp.port == 2917 || (tls && ip.addr == 45.125.66.32)`; confirm **TLS 1.2** handshake and **SNI = IP**.  
- **UA anomaly:** view the HTTP request headers for the same frames (old MSIE UA on Win10).

### B) Open Items / Validation
- Confirm `44.125.66.252` from the original PCAP (noted in observations; may be a typo for `45.125.66.252`).  
- Correlate with proxy/firewall logs to see full DNS/URL chain that led to `authenticatoor[.]org`.

---

**Conclusion:** The network capture supports a **malware infection** on host `DESKTOP-L8C5GSJ (10.1.17.215)` tied to a fake “Google Authenticator” download. Activity includes staged payload retrieval over HTTP and ongoing C2 over non‑standard TLS. Immediate isolation and remediation are advised.

