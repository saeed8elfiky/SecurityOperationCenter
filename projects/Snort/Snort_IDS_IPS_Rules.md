# Snort IDS demo: detecting pings and Nmap scans with custom rules on Ubuntu

<p align ="center">
    <img src= "/projects/Snort_Nmape_IDS_IPS/photo/SNORT.svg"
</p>

### Project Overview

This project shows how to install and configure **Snort**, an open-source Intrusion Detection System (IDS), to detect suspicious network activity such as **ICMP pings** and **Nmap port scans**.

We set up two virtual machines:

- **Machine 1 (Ubuntu)** -> runs Snort in IDS mode, monitoring the network and generating alerts when malicious traffic is detected.
    
- **Machine 2 (Linux)** -> acts as the attacker, using **Nmap** to perform scans against Machine 1.


Custom Snort rules are created to:

- Alert when someone **pings** the protected network (ICMP Echo Request).
    
- Detect **stealthy SYN scans** (`nmap -sS`) by monitoring repeated SYN packets from the same source.


By the end, you’ll see Snort trigger alerts in real time when Machine 2 scans Machine 1, proving the IDS is working correctly.

----

### Machine 1 - Ubuntu

Install **`Snort`**, an open-source Intrusion Detection System (IDS), using the package manager.

```shell
sudo apt install snort
```


* Open the Snort configuration file to edit.  

* `sudo nano /etc/snort/rule/local.rule`

Inside the file, define your **HOME_NET** (the network you want to protect/monitor) (e.g. 192.168.1.0/24) `var HOME_NET 192.168.1.0/24`

First go to 

```shell
sudo nano /etc/snort/rules/local.rules
```

Then Add:

```shell
alert icmp any any -> $HOME_NET (msg: "Someone is pinging on us!"; sid:1000001; rev:1;)
```

#### ***Breakdown***
- `alert`  
    Action: generate an alert (log it) when the rule matches. Other possible actions: `log`, `drop`, `reject`, etc.
    
- `icmp`  
    Protocol: the rule applies to ICMP traffic (IPv4). ICMP has no TCP/UDP ports, so the port fields are filler here.
    
- `any any`  
    Source address and source port. For ICMP the second `any` is a placeholder (ICMP uses types/codes rather than ports). This means _any source IP_.
    
- `->`  
    Direction operator. This matches traffic from source (left) to destination (right). `->` is unidirectional. You could use `<->` for both directions.
    
- `$HOME_NET`  
    Destination network variable. This is defined in your `snort.conf` (for example `var HOME_NET 192.168.1.0/24`). The rule fires when ICMP from anywhere goes **to** your HOME_NET.
    
- `( ... )`  
    Rule options block - a semicolon-separated list of options that describe what to do and metadata.
    
    Inside the block:
    
    - `msg: "Someone is pinging on us!";`  
        Human-readable message that shows in alerts/logs.
        
    - `sid:1000001;`  
        **Signature ID**: a unique numeric identifier for this rule. Local rules typically use SIDs >= 1000000 to avoid colliding with vendor rules. Must be unique.
        
    - `rev:1;`  
        Revision number of the rule — increment when you change the rule.


#### Detect Stealthy Scan SYN

```shell
alert tcp any any -> $HOME_NET any (msg:"APP-Detect: Possible Nmap SYN scan"; flags:S; detection_filter: track by_src, count 15, seconds 60; sid:1000002; rev:1;)

```

- **alert** -> action: raise an alert.
    
- **tcp** -> protocol: TCP.
    
- **any any -> 
	-`$HOME_NET any**` > from any source/port to any host/port in `$HOME_NET`
    
- **msg:"..."** -> text shown in the alert.
    
- **flags:S** -> match TCP packets with SYN flag.
    
- **detection_filter: track by_src, count 15, seconds 60** — trigger if the same source sends ≥15 SYNs within 60 seconds.
    
- **sid:1000002** -> unique rule ID.
    
- **rev:1** -> rule revision number.
    

**In short:** Alerts when a single source sends 15 or more SYN packets within one minute — likely an Nmap SYN scan.

<p align ="center">
    <img src= "/projects/Snort_Nmape_IDS_IPS/photo/syn_rule.png"
</p>

**Test Snort configuration**:

```shell
sudo snort -T -c /etc/snort/rules/local.rules -i enp0s3
```

- `-T` → Test mode (verifies that the configuration is correct, no packets captured).
    
- `-c /etc/snort/rules/local.rules` → Path to config file.
    
- `-i enp0s3` → The network interface Snort will monitor.

**Test Snort configuration**:

```shell
sudo snort -T -c /etc/snort/snort.conf -i enp0s3
```

- `-T` → Test mode (verifies that the configuration is correct, no packets captured).
    
- `-c /etc/snort/snort.conf` → Path to config file.
    
- `-i enp0s3` → The network interface Snort will monitor.

<p align ="center">
    <img src= "/projects/Snort_Nmape_IDS_IPS/photo/conf_check.png"
</p>

**Run Snort in IDS mode**:

```shell
sudo snort -A console -q -u snort -g snort -c /etc/snort/snort.conf -i enp0s3
```

- `-A console` → Send alerts directly to the terminal.
    
- `-q` → Quiet mode (suppress banner + startup info).
    
- `-u snort` → Run as the **snort** user for security.
    
- `-g snort` → Run under the **snort** group.
    
- `-c /etc/snort/snort.conf` → Use custom config file.
    
- `-i enp0s3` → Listen on the specified network interface.

-----

### Machine 2- Linux
```shell
nmap 10.0.2.15
```

Use **Nmap** to scan the target machine (`10.0.2.15`).  
* This simulates an attacker scanning open ports.  
* Snort (running on Machine 1) should detect this scan and generate alerts.

<p align ="center">
    <img src= "/projects/Snort_Nmape_IDS_IPS/photo/syn_attack.png"
</p>

----
### The Result
Snort on **Machine 1** should display alerts in the console when **Machine 2** runs the Nmap scan, confirming that the IDS is working correctly.

<p align ="center">
    <img src= "/projects/Snort_Nmape_IDS_IPS/photo/synscan.png"
</p>


---

### **Feel free to contact me on** **[LinkedIn](https://www.linkedin.com/in/saeed-elfiky-61188b24b/)**.
