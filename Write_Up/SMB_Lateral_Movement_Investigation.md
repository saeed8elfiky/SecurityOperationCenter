#### Prepared by: Saeed Ashraf Saeed Elfiky 

<p align ="center">
    <img src= "/socPhoto/Saeed_Elfiky__Incident_PsExec.svg"
</p>

#### Environment (per brief):
- LAN: 10.0.0.0/24 
- Protocol in scope: SMB (TCP/445) 
- Tool observed: PsExec (Sysinternals) 
- Key shares accessed: `ADMIN$`, `IPC$ `

### 1) Executive Summary
An alert was triggered by the IDS indicating suspicious lateral movement activity involving PsExec over SMB. A packet capture was reviewed to trace the attacker’s actions, initial point, authentication details, and subsequent network pivoting
### 2) Involved Hosts

**Attacker Host:**    
- IP: 10.0.0.130
	Generated an unusually large amount of SMB traffic compared to other clients.
	
**First Target (SALES-PC):**
- IP: 10.0.0.133
	Does NTLM authentication attempt with the user account `ssales`, and deployment of `PSEXESVC.exe` is confirmed via `ADMIN$` share
	
**Second Target (MARKETING-PC):**
- IP: 10.0.0.131
	Session setup following compromise of SALES-PC, indicating attacker pivot.

### 3) Attack Progression
#### 1. Initial Access Point 
The attacker’s activity originated from 10.0.0.130, which generated an unusually large amount of SMB traffic compared to other hosts. 


<p align ="center">
    <img src= "/socPhoto/first_machine.png"
</p>




#### 2. First Pivot 
The first target machine that responded was `SALES-PC 10.0.0.133`, and was identified in the SMB Session Setup Authentication attempts. also appears that the attacker used the account confirmed `ssales` during the`NTLM` negotiation process. To install `PSEXESVC.exe` on the victim's machine.

<p align ="center">
    <img src= "/socPhoto/10.0.0.133_hostname.png" 
</p>

<p align ="center">
    <img src= "/socPhoto/username.png"
</p>





#### 3. Execution on Target
The attacker deployed `PsExec`, which created the service-compromised host. The installation was carried out using the `ADMIN$` share. The communication between attacker and victim occurred via the `IPC$` share.

<p align ="center">
    <img src= "/socPhoto/service_ex.png"
</p>
<p align ="center">
    <img src= "/socPhoto/admin_dolar_sign.png"
</p>

<p align ="center">
    <img src= "/socPhoto/pc_dollar_sign.png"
</p>





#### 4. Further Lateral Movement
After establishing access on the `SALES-PC`, the attacker pivoted to `10.0.0.131`, identified as `MARKETING-PC` in the session setup exchange.

<p align ="center">
    <img src= "/socPhoto/10.0.0.131_ip.png"
</p>

<p align ="center">
    <img src= "/socPhoto/10.0.0.131_hostname.png"
</p>

### 4) Indicators of Compromise (IOCs)

**Internal IOCs:**

- Attacker Host: 10.0.0.130
- Compromised Targets: 10.0.0.133 (SALES-PC), 10.0.0.131 (MARKETING-PC)
- Executable: `PSEXESVC.exe`    
- Shares used: `ADMIN$`, `IPC$`

### 5) Attack Analysis & MITRE ATT&CK Mapping

- **Initial Access (T1566 - Phishing | T1078 - Valid Accounts):**  Iam not sure because there is no information about how the attacker entered the victim's machine.

- **Execution (T1569.002 – Service Execution):** PsExec created remote service `PSEXESVC.exe`.
    
- **Lateral Movement (T1021.002 – SMB/Windows Admin Shares):** Attacker used ADMIN$ share to deploy malicious service.
    
- **Credential Access (T1078 – Valid Accounts):** Compromise of `ssales` domain account leveraged for lateral movement.
    
- **Persistence (T1543.003 – Windows Service):** PsExec service persistence mechanism possible on compromised hosts.


### 6) Recommendations

**Immediate Containment**

- Isolate affected hosts (**`10.0.0.133, 10.0.0.131`**) from the network.
- **Block** SMB (TCP/445) traffic from `10.0.0.130` at network perimeter.


**Eradication**

- Remove `PSEXESVC.exe` service and review startup entries.
- Reset credentials for account `ssales`. Or even delete it and recreate it 
- Start malware scans on compromised hosts.


**Recovery & Hardening**

- Patch SMB's related vulnerabilities on all hosts.
- Enable SMB signing to mitigate credential relay risks.
- Enforce principle of least privilege for domain accounts.
- Deploy monitoring rules to detect `PsExec` and abnormal SMB activity.
