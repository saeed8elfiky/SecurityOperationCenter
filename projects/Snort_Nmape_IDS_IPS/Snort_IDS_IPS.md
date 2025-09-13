### Machine 1 - Ubuntu

Install **`Snort`**, an open-source Intrusion Detection System (IDS), using the package manager.

```shell
sudo apt install snort
```


* Open the Snort configuration file to edit.  

* `sudo nano /etc/snort/rule/snort.conf`

Inside the file, define your **HOME_NET** (the network you want to protect/monitor) (e.g. 192.168.1.0/24) `var HOME_NET 192.168.1.0/24`

<p align ="center">
    <img src= "/projects/Snort_Nmape_IDS_IPS/photo/home_net.png"
</p>


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

<p align ="center">
    <img src= "/projects/Snort_Nmape_IDS_IPS/photo/snort_ids.png"
</p>

### Machine 2- Linux
```shell
nmap 10.0.2.15
```

Use **Nmap** to scan the target machine (`10.0.2.15`).  
* This simulates an attacker scanning open ports.  
* Snort (running on Machine 1) should detect this scan and generate alerts.

<p align ="center">
    <img src= "/projects/Snort_Nmape_IDS_IPS/photo/attacker_machine.png"
</p>

----
### The Result
Snort on **Machine 1** should display alerts in the console when **Machine 2** runs the Nmap scan, confirming that the IDS is working correctly.

<p align ="center">
    <img src= "/projects/Snort_Nmape_IDS_IPS/photo/detect_result.png"
</p>

```

### **Feel free to contact me on** **[LinkedIn](https://www.linkedin.com/in/saeed-elfiky-61188b24b/)**.
