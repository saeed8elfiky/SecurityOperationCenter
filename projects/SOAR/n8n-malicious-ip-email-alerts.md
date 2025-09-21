# **Automated Detection & Notification of Malicious IP using n8n**

## Report Information

- **Prepared by:** Saeed Ashraf Saeed Elfiky

- **Data:** 21-09-2025

- **Category:** SOC Engineering

---

## Project Overview

The goal of this project is to automate the process of identifying devices and users that communicate with a known malicious IP address and to notify affected users via email. This reduces response time and ensures quick awareness and remediation.



<p align ="center">
    <img src= "/projects/SOAR/screenshots/workflow.png"
</p>


---

## Tools & Technologies

- **n8n** (workflow automation platform)

- **Logs API** (data source for communication records)

- **IF Node** (filter malicious IP traffic)

- **Set & Unique Nodes** (extract relevant information and avoid duplicates)

- **Email/Gmail Node (or SMTP)** (notify impacted users)

---

## Workflow Summary

- **Data Collection**: Use the **HTTP Request Node** to fetch logs from the Logs API.



<p align ="center">
    <img src= "/projects/SOAR/screenshots/logs.png"
</p>



- **Data Preparation**: Apply **Split Out Items** to process each log entry individually.



<p align ="center">
    <img src= "/projects/SOAR/screenshots/split2.png"
</p>


- **Filtering**: Use the **IF Node** to check whether the source or destination IP equals the malicious IP (`192.168.1.100`).



<p align ="center">
    <img src= "/projects/SOAR/screenshots/if2.png"
</p>



- **Data Extraction**: Apply the **Set Node** to extract important fields (hostname, user, Source IP).



<p align ="center">
    <img src= "/projects/SOAR/screenshots/get_info.png"
</p>


- **Notification**: Send alert emails via **Gmail/SMTP Node** to inform users about the malicious communication.



<p align ="center">
    <img src= "/projects/SOAR/screenshots/sendmail.png"
</p>


### Testing



<p align ="center">
    <img src= "/projects/SOAR/screenshots/mailrecieved.png"
</p>


---

### Expected Outcomes

- Faster incident response by automatically detecting malicious IP communications.

- Improved user awareness with direct email alerts.

- Reduced workload on SOC analysts through automation.

----
### **Feel free to contact me on** **[LinkedIn](https://www.linkedin.com/in/saeed-elfiky-61188b24b/)**.


