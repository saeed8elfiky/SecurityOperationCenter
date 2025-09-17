# ⚡ Elasticsearch, Kibana, Filebeat & Fluent Bit Setup with Custom Regex Parsing

<p align ="center">
    <img src= "/projects/Elasticsearch-SIEM/screenshoot/ELK-fluent-bit.svg"
</p>

## 1) Project Overview

This project provides a step-by-step guide to installing and configuring the ELK stack (Elasticsearch, Kibana, Filebeat) along with Fluent Bit for advanced log collection and parsing. It covers:

- Installing and configuring Elasticsearch & Kibana
- Setting up Filebeat for log forwarding
- Installing Fluent Bit with custom regex-based parsers
- Integrating logs into Elasticsearch and visualizing them in Kibana
- Using regular expressions to extract structured fields (e.g., date, time, IPs, ports, users, and sites) from raw logs

----

## 2) ***Install Elasticsearch***
> **Note:** You have to set Static IP to the **Hosting Machine**

#### Import the Elasticsearch PGP key
```shell
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo gpg --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg
```

#### Install from the APT repository
You may need to install the `apt-transport-https` package on Debian before proceeding

```shell
sudo apt-get install apt-transport-https
```

Save the repository definition to `/etc/apt/sources.list.d/elastic-9.x.list`

```shell
echo "deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] https://artifacts.elastic.co/packages/9.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-9.x.list
```

1. Install the Elasticsearch Debian package:

Elasticsearch is the search and analytics engine that stores logs in an indexed format. It allows fast querying, filtering, and correlation of log data.

```shell
sudo apt-get update && sudo apt-get install elasticsearch
```

2. Install Kibana

Kibana is the web interface for Elasticsearch. It’s used to visualize logs, create dashboards, and run searches.

```shell
sudo apt-get update && sudo apt-get install kibana
```

---
## 3) ***Configure Elasticsearch & Kibana***
First we will configure the ELK 

```shell
sudo nano /etc/elasticsearch/elasticsearch.yml
```
<p align ="center">
    <img src= "/projects/Elasticsearch-SIEM/screenshoot/elk_yml.png" alt = "cloud deployment"
</p>

<p align ="center">
    <img src= "/projects/Elasticsearch-SIEM/screenshoot/elk_yml2.png" alt = "cloud deployment"
</p>

<p align ="center">
    <img src= "/projects/Elasticsearch-SIEM/screenshoot/elk_yml3.png" alt = "cloud deployment"
</p>

Next, start the machine

```shell
sudo systemctl start elasticsearch
```


Next, go to the configuration file of Kibana

```shell
sudo nano /etc/kibana/kibana.yml
```

<p align ="center">
    <img src= "/projects/Elasticsearch-SIEM/screenshoot/kibana_yml.png"
</p>

---
### 4) ***Access the web***
Go to the browser and search for `https://localhost:9200` will ask you for the username and password.
the default username: `elastic` and to get the password:

<p align ="center">
    <img src= "/projects/Elasticsearch-SIEM/screenshoot/acess_web.png"
</p>

  
```shell
cd /usr/shared/elasticsearch/bin
sudo ./elasticsearch-reset-password
```


and it will output the password for you. You should see a JSON response with cluster and version details.

Next search for: `http://localhost:5601`

<p align ="center">
    <img src= "/projects/Elasticsearch-SIEM/screenshoot/kibana_token.png"
</p>

will ask you for The enrollment token 

```shell
cd /usr/shared/elasticsearch/bin
sudo ./elasticsearch-enrollment-token
```

take the token and past it in kibana, after that it will required the verification code, to find it:

<p align ="center">
    <img src= "/projects/Elasticsearch-SIEM/screenshoot/kibana_verification.png"
</p>

```shell
cd /usr/shared/kiban/bin
sudo ./kibana-verification-code
```


---
## 5)***Install & Configure filebeat***

**Filebeat** is a log shipper that collects logs from files and forwards them to Elasticsearch.

First go to the official ELK website, and download the filebeat for debian.

<p align ="center">
    <img src= "/projects/Elasticsearch-SIEM/screenshoot/download_filebeat.png"
</p>

```shell
cd Downloads
sudo apt install ./filebeat-9.1.3-amd64.deb
```


Then navigate to:

```shell
sudo nano /etc/filebeat/filebeat.yml
```

and configure these parameters 

<p align ="center">
    <img src= "/projects/Elasticsearch-SIEM/screenshoot/filebeat_con1.png"
</p>

<p align ="center">
    <img src= "/projects/Elasticsearch-SIEM/screenshoot/filebeat_con2.png"
</p>

```shell
sudo filebeat test config
sudo systemctl start filebeat
```


now if we go to kibana:

`Analytics > Discover`

You will see the logs from your machine:

<p align ="center">
    <img src= "/projects/Elasticsearch-SIEM/screenshoot/kibana_logs_dashbord.png"
</p>
  
---
## 6)***Download Fluent-Bit***

**Fluent-Bit** is a lightweight log processor and forwarder. Unlike Filebeat, it is optimized for speed and parsing flexibility.
We’ll use it to apply custom regex parsers that extract structured fields from raw logs.

First

```shell
curl https://raw.githubusercontent.com/fluent/fluent-bit/master/install.sh | sh
```

Then Install Fluent Bit server GPG key to your keyring to ensure you can get the correct signed packages.

```shell
sudo sh -c 'curl https://packages.fluentbit.io/fluentbit.key | gpg --dearmor > /usr/share/keyrings/fluentbit-keyring.gpg'
```

#### Update your sources lists
On Ubuntu, you need to add the Fluent Bit APT server entry to your sources lists. Ensure codename is set to your specific Ubuntu release name

```shell
codename=$(grep -oP '(?<=VERSION_CODENAME=).*' /etc/os-release 2>/dev/null || lsb_release -cs 2>/dev/null)
```

Then update your source list

```shell
echo "deb [signed-by=/usr/share/keyrings/fluentbit-keyring.gpg] https://packages.fluentbit.io/ubuntu/$codename $codename main" | sudo tee /etc/apt/sources.list.d/fluent-bit.list
```


Use the following apt-get command to install the latest Fluent Bit:

```shell
sudo apt-get install fluent-bit
```

Instruct `systemd` to enable the service:

```shell
sudo systemctl start fluent-bit
```

-----
## 7)***Create Regular Expressions***
First go to [rubular](https://rubular.com) 

<p align ="center">
    <img src= "/projects/Elasticsearch-SIEM/screenshoot/regex.png"
</p>

these our test logs:

```
2006-09-19 03:31:17 DROP TCP 192.168.99.165 239.255.255.250 1900 22   root    headquarters.com

2006-09-19 03:02:17 ACCEPT TCP 192.18.19.65 239.235.255.50 1900 22   user    cairo_1

2006-09-19 03:38:17 REJECT TCP 10.18.29.65 244.235.211.50 1900 22   root    alex_2

```

we will set these expressions:

```
(?<date>\d{4}-\d{2}-\d{2})\s+(?<time>\d{2}:\d{2}:\d{2})\s+(?<action>\S+)\s+(?<Protocol>\w+)\s+(?<SRC_IP>\d{1,3}\.\d{1,3}\.\d{1,3}.\d{1,3})\s+(?<DST_IP>\d{1,3}\.\d{1,3}\.\d{1,3}.\d{1,3})\s+(?<SRC_Port>\d{1,5})\s+(?<DST_Port>\d{1,5})\s+(?<User>\S+)\s+(?<Site>\S+)
```

Explaination:
1. **`(?<date>\d{4}-\d{2}-\d{2})`**
    
    - Named group: `date`
    - Matches a date like `2006-09-19`
    - `\d{4}` → year (4 digits)
    - `-` → dash
    - `\d{2}` → month (2 digits)
    - `-` → dash
    - `\d{2}` → day (2 digits)

2. **`\s+`**
	- One or more spaces (used as separators)


3. **`(?<time>\d{2}:\d{2}:\d{2})`**

	- Named group: `time`
	- Matches time like `03:32:17`
	- `\d{2}` → hours (2 digits)
	- `:` → colon
	- `\d{2}` → minutes
	- `:` → colon
	- `\d{2}` → seconds

4. **`(?<action>\S+)`**

    - Named group: `action`        
    - `\S+` → one or more **non-space characters**
    - Example: `DROP`, `ALLOW`

5. **`(?<Protocol>\w+)`**
    
    - Named group: `Protocol`
    - `\w+` → one or more word characters (letters, digits, underscore)
    - Example: `TCP`, `UDP`, `HTTP`

6. **`(?<SRC_IP>\d{1,3}\.\d{1,3}\.\d{1,3}.\d{1,3})`**
    
    - Named group: `SRC_IP`
    - Matches IPv4 address (source IP)
    - `\d{1,3}` → 1 to 3 digits
    - `\.` → literal dot
    - Repeated 4 times
	* Example: `192.168.99.165`

7. **`(?<DST_IP>\d{1,3}\.\d{1,3}\.\d{1,3}.\d{1,3})`**
    
    - Named group: `DST_IP`        
    - Matches destination IP (same pattern as above)
    - Example: `239.255.255.250`

8. **`(?<SRC_Port>\d{1,5})`**
    
    - Named group: `SRC_Port`
    - Matches port number (1–5 digits)
    - Example: `1900`

9. **`(?<DST_Port>\d{1,5})`**
    
    - Named group: `DST_Port`
    - Matches destination port (same as above)
    - Example: `22`

10. **`(?<User>\S+)`**
    
    - Named group: `User`        
    - Matches username (no spaces)
    - Example: `root`

11. **`(?<Site>\S+)`**
    
    - Named group: `Site`        
    - Matches site/location/department (no spaces)
    - Example: `headquarters`

---
## 8)**Create Test logs & Parsers file 

```shell
sudo nano /var/log/saeed.log
```

**and then put our Test logs into it**

Next, Create **Parser** file

```shell
sudo nano /etc/fluent-bit/saeed_parser.cof
```

Ensure these lines are in

```shell
[PARSER]
    Name        test_parser
    Format      regex
    Regex       ^(?<timestamp>\w{3}\s+\d+\s\d+:\d+:\d+)\s(?<host>\S+)\ssshd\[(?<pid>\d+)\]:\s(?<message>.*)$

```

----
## 9) **Configure Fluent-Bit**
First :

```shell
sudo nano /etc/fluent-bit/fluent-bit.conf
```

Then ensure to add these lines:

```
[SERVICE]
    Flush        1
    Daemon       Off
    Log_Level    info
    parsers_file saeed_paresr.conf

[INPUT]
    Name   tail
    Path   /var/log/saeed.log
    Parser test_parser
    Tag    test-logs

[OUTPUT]
    Name  es
    Match *
    Host  <elastic_ip>
    Port  9200
    HTTP_User elastic
    http_passwd <elastic_passwod>
    tls on
    tls.verify off
    Trace_Output on
    Index test-logs
    Suppress_Type_Name No

```


---
## 10) ***Start Fluent-Bit***
```shell
cd /opt/fluent-bit/bin
./fluent-bit -c /etc/fluent-bit/fluent-bit.conf
```

Then go to your browser and open `http:<elastic_ip>:5601`

Menu > Stacks Management > Index Management

<p align ="center">
    <img src= "/projects/Elasticsearch-SIEM/screenshoot/final_kibana_logs_dashbord.png"
</p>

---
### **Feel free to contact me on** **[LinkedIn](https://www.linkedin.com/in/saeed-elfiky-61188b24b/)**.
