# Incident Report – Fake Google Authenticator


**Prepared by:** `Saeed Ashraf Elfiky`
**Environment (per brief):**  
- LAN: `10.1.17.0/24`  
- Domain: `bluemoontuesday[.]com` (AD env name: **BLUEMOONTUESDAY**)  
- AD DC: `WIN-GSHS4OLW48D` @ `10.1.17.12`  
- File provided: `Google Authenticator.pcap`

---


## 1. Executive Summary

This report documents the findings from the provided PCAP, based on a simulated SOC investigation. The infection appears to have originated when a user searched for and downloaded a fake version of Google Authenticator from a typosquatted domain. Subsequent traffic analysis indicates communication with suspicious external IPs, likely functioning as Command-and-Control (C2) servers.

---

## 2. Infected Host Details

* **IP Address of Infected Client:** `10.1.17.215`
  Evidence: This host generated a high volume of DNS queries and suspicious connections. It communicated frequently with the internal AD domain controller and initiated outbound traffic toward known suspicious domains and IPs. The behavior suggests malware beaconing or automated processes beyond normal user activity.

* **MAC Address of Infected Client:** `00:d0:b7:26:4a:74`
  Evidence: Extracted from Ethernet headers within the PCAP. Consistently mapped to `10.1.17.215`, confirming device identity.

* **Host Name:** `DESKTOP-L8C5GSJ`
  Evidence: Found in DNS response packets mapping IP ↔ hostname. Confirms the infected machine identity.

<p align ="center">
    <img src= "/socPhoto/host_name.png" alt = "access management"
</p>

* **User Account Name:** `shutchenson`
  Evidence: Kerberos authentication requests captured in the traffic show this username initiating authentication with the AD controller. Indicates that the infection was active during the user’s session.

<p align ="center">
    <img src= "/socPhoto/kerberos_username.png" alt = "access management"
</p>

---

## 3. Malicious Domain Identified

* **Fake Google Authenticator Domain:** `authenticatoor[.]org`
  Analysis:

  * The domain name is a clear typosquatting attempt on “google authenticator”.
  * Traffic logs confirm DNS queries and HTTP(S) requests to this domain.
  * The website likely hosted a malicious installer disguised as the real Google Authenticator.
 
<p align ="center">
    <img src= "/socPhoto/domain_name.png" alt = "access management"
</p>

---

## 4. C2 Infrastructure Identified

### Primary C2 IP

* **`5.252.153.241`**

  * Evidence: The infected host issued HTTP `GET` requests to this server, attempting to retrieve suspicious script-like files.
  * Likely purpose: Stage 2 malware or configuration retrieval.
 
<p align ="center">
    <img src= "/socPhoto/httpc2.png" alt = "access management"
</p>

### Additional Suspicious C2 IPs

* **`45.125.66.32`**
* **`45.125.66.252`**

  * Evidence: Large volumes of TLS traffic on unusual ports.
  * The TLS SNI field contained raw IP addresses instead of domains, which is highly suspicious.
  * Heavy encrypted Application Data exchange suggests C2 activity (data exfiltration, beaconing, or remote tasking).
 
<p align ="center">
    <img src= "/socPhoto/45.125.66.32.png" alt = "access management"
</p>

<p align ="center">
    <img src= "/socPhoto/45.125.66.252.png" alt = "access management"
</p>

---

## 5. Indicators of Compromise (IOCs)

* **Internal IOC**

  * Host IP: `10.1.17.215`
  * MAC: `00:d0:b7:26:4a:74`
  * Hostname: `DESKTOP-L8C5GSJ`
  * User: `shutchenson`

* **External IOC**

  * Domain: `authenticatoor[.]org`
  * C2 IPs:

    * `5.252.153.241`
    * `45.125.66.32`
    * `45.125.66.252`

---

## 6. Attack Analysis & MITRE ATT\&CK Mapping

* **Initial Access (T1566.002 / Drive-by Compromise):** User downloaded a fake Google Authenticator app from typosquatted domain.
* **Execution (T1059 / Command & Scripting Interpreter):** Suspicious script downloads from `5.252.153.241`.
* **Persistence (T1547 / Boot or Logon Autostart):** Potential persistence mechanisms expected, though not visible in PCAP.
* **C2 (T1071.001 / Web Protocols & T1573 / Encrypted Channels):** TLS traffic to IP-only SNIs and script retrieval over HTTP.
* **Credential Access (T1558 / Steal or Forge Kerberos Tickets):** Kerberos traffic may have been targeted for lateral movement.

---

## 7. Recommendations

1. **Immediate Containment**

   * Isolate host `10.1.17.215` from the network.
   * Block malicious domains and IPs on firewalls and DNS filters.

2. **Eradication**

   * Run endpoint malware scans.
   * Check startup entries, scheduled tasks, and registry for persistence.
   * Reset credentials for user `shutchenson` and monitor AD for abnormal logins.

3. **Recovery & Hardening**

   * Restore affected systems from clean images if malware confirmed.
   * Patch systems and deploy application allowlisting.
   * Educate users on typosquatting/phishing risks.

---

## 8. Conclusion

The analysis strongly supports that `DESKTOP-L8C5GSJ` (10.1.17.215) is compromised after installing malware from a fake Google Authenticator website. The host communicated with multiple suspected C2 IPs, suggesting ongoing malicious activity. Immediate containment and eradication steps are required.


