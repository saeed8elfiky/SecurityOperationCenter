# Incident Report – Fake Google Authenticator


**Prepared by:** `Saeed Ashraf Elfiky`
**Environment (per brief):**  
- LAN: `10.1.17.0/24`  
- Domain: `bluemoontuesday[.]com` (AD env name: **BLUEMOONTUESDAY**)  
- AD DC: `WIN-GSHS4OLW48D` @ `10.1.17.12`  
- File provided: `Google Authenticator.pcap`

---


## 1. Executive Summary

This report presents what I found as a SOC Analyst investigating and analyzing the traffic. The infection starts when the user searches for and downloads a fake Google Authenticator from a typosquatted domain. From what I saw in the traffic analysis, there is communication occurring with suspicious external IPs, likely

---

## 2. Infected Host Details

* **IP Address of Infected Client:** `10.1.17.215`
	The host with the 10.1.17.215 IP address generates a large number of DNS queries and suspicious connections. It often contacted the Active Directory domain controller and sent traffic to known suspicious domains and IPs. This means malware beaconing or automated processes beyond normal user activity.

* **MAC Address of Infected Client:** `00:d0:b7:26:4a:74`
	It appears in the Ethernet headers. Consistently mapped to `10.1.17.215`, and confirming the device identity.

* **Host Name:** `DESKTOP-L8C5GSJ`
	I found it in the DNS response's packets mapping IP and hostname. That confirms the identity of the infected machine.


<p align ="center">
    <img src= "/socPhoto/host_name.png" alt = "access management"
</p>


* **User Account Name:** `shutchenson`
	I searched for Kerberos authentication requests in the traffic, and it confirms that the username-initiated authentication with the AD controller. This proves the infection was active during the user’s session.


<p align ="center">
    <img src= "/socPhoto/kerberos_username.png" alt = "access management"
</p>


---

## 3. Malicious Domain Identified

**Fake Google Authenticator Domain:** `authenticatoor[.]org`

  Analysis:

  * The domain name is a clear typosquatting attempt on “Google Authenticator”.
  * Traffic logs confirm the DNS queries and HTTP(S) requests to this domain.
  * The website likely hosted a malicious installer disguised as the real Google Authenticator.
 

<p align ="center">
    <img src= "/socPhoto/domain_name.png" alt = "access management"
</p>


---

## 4. C2 Infrastructure Identified

### Primary C2 IP

* **`5.252.153.241`**

The infected host's device had made HTTP `GET` requests to this server, attempting to retrieve suspicious scripts.
 

<p align ="center">
    <img src= "/socPhoto/httpc2.png" alt = "access management"
</p>


### Additional Suspicious C2 IPs

* **`45.125.66.32`**
* **`45.125.66.252`**

	- *A very much of TLS traffic is on unusual ports.
	- The TLS SNI field contained raw IP addresses instead of domains, which is highly suspicious.
	- A large amount of encrypted Application Data exchange suggests C2 activity (data exfiltration, beaconing, or remote tasking).
 

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

