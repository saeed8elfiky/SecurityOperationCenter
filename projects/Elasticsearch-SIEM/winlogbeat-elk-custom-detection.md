# ELK SIEM with Winlogbeat: Custom Detection for Windows Threats
### **1) Project Overview: Winlogbeat + ELK**
This project shows how to integrate **Winlogbeat** with the **ELK stack** to collect and analyze Windows Event Logs in **Kibana**.

- **Winlogbeat Setup**: Install as a Windows service, configure `winlogbeat.yml` to collect Application, System, and Security logs, then connect securely to Elasticsearch.

- **Detection Rules**: Create custom queries in Kibana SIEM to detect suspicious activity (e.g., `whoami.exe`, `net.exe` with privilege escalation commands).

- **Testing**: Run test commands like `whoami` and verify that alerts are triggered in Kibana.
---
### **2 ) Install & Configure Winlogbeat**
Download from the official [Elastic](https://www.elastic.co/downloads/beats/winlogbeat) and Extract WinlogBeat in `C:\Program Files\`

**Open `Power Shell` as an *Administrator***

```powershell
cd 'C:\Program Files\Winlogbeat'
.\install-service-winlogbeat.ps1
```

Open `winlogbeat.yml` with any editor (*Notpad++ recommended*)

>**Note:** Delete `Microsoft-Windows-Sysmon/Operational` line

Ensure each line here is configured in the `.yml`

```yml
winlogbeat.event_logs:
  - name: Application
    ignore_older: 72h

  - name: System

  - name: Security


  - name: Microsoft-Windows-Sysmon/Operational
    event_id: 1, 12, 13, 14

  - name: Windows PowerShell
    
setup.kibana:

  host: "<elastick_url>:5601"
  username: "elastic"
  password: "password"

output.elasticsearch:
  hosts: ["<elastick_url>:9200"]
  protocol: "https"
  username: "elastic"
  password: "password"
  pipeline: "winlogbeat-%{[agent.version]}-routing"
  ssl.verification_mode: none
```

and right click on `winlogbeat.yml` > Properties > security > user > edit > users > allow all

Then go to `secpol.msc` and then Go to 
- **Advanced Aduit Policy Configuration** > **System Audit Policies** > **Object Access** > `Audit Other Object Access Events` "Success & Failure" 
- `Audit Process Creation` "Success"

Then go to `gpedit.msc` and then 
- **Computer Configuration** > **Administrator Templates** > **Windows Components** > **Windows Powershell** > `Turn on Module Logging` Put `*` in module names
- ``Turn on Powershell Script Block Logging`


<p align ="center">
    <img src= "/projects/Elasticsearch-SIEM/screenshoot/allow_all"
</p>

```powershell
.\winlogbeat.exe test config -c .\winlogbeat.yml -e
.\winlogbeat.exe setup -e
Start-Service winlogbeat
```



**Go to Kibana** > Left menu > Discover > Data view: `winlogbeat`
You should see the windows logs there:

<p align ="center">
    <img src= "/projects/Elasticsearch-SIEM/screenshoot/winlogs.png"
</p>

---
### **3) Create Rule**
Now we will create custom Rule to detect the suspicious activity, such as `whoami.exe`, `net.exe`
First go  to **Left Menu** > **Rule** > **Detection rule (SIEM)**

<p align ="center">
    <img src= "/projects/Elasticsearch-SIEM/screenshoot/create_rule.png"
</p>
.

**Then, Create  new rule**
1. Definition
	- **Rule Type:** `Custom Query`
	- **Data View:** `winlogbeat-*`
	- **Custom Query:

```KQL
	(
  process.name : "whoami.exe"
)
OR
(
  process.name : "net.exe" AND (
    process.command_line : "*net user*" OR
    process.command_line : "*net localgroup*" OR
    process.command_line : "*net group*" OR
    process.command_line : "* /add*" OR
    process.command_line : "* /delete*"
  )
)
```

2. About
	* Name: `whoami & net discovery/escalation attempts`
	* Description:  `Detect: whoami & net discovery/escalation attempts`
	* Severity: `High`
	* Risk score: `75`

3. Schedule
	* Runs every: `5 min`

Click **Save**

<p align ="center">
    <img src= "/projects/Elasticsearch-SIEM/screenshoot/rule.png"
</p>

---
### **4) Testing**
Open `CMD`

```cmd
whoami
```

And check the alerts: You should see the alert holding the rule name
>**Note:** If the alert is not exist, just refresh the page

<p align ="center">
    <img src= "/projects/Elasticsearch-SIEM/screenshoot/alert.png"
</p>

---
### **For more Details**
**Feel free to contact me on [LinkedIn](https://www.linkedin.com/in/saeed-elfiky-61188b24b/)**.
