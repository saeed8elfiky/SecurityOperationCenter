# **Automated Detection & Notification of Malicious IP using n8n**

## Report Information

- **Prepared by:** Saeed Ashraf Saeed Elfiky

- **Data:** 21-09-2025

- **Category:** SOC Engineering

---

## Project Overview

The goal of this project is to automate the process of identifying devices and users that communicate with a known malicious IP address and to notify affected users via email. This reduces response time and ensures quick awareness and remediation.



![workflow.png](D:\Courses\We%20Innovate\SOC_Engineering_week\soar.100_task\workflow.png)



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



![logs.png](D:\Courses\We%20Innovate\SOC_Engineering_week\soar.100_task\logs.png)



- **Data Preparation**: Apply **Split Out Items** to process each log entry individually.



![split.png](D:\Courses\We%20Innovate\SOC_Engineering_week\soar.100_task\split.png)



- **Filtering**: Use the **IF Node** to check whether the source or destination IP equals the malicious IP (`192.168.1.100`).



![if.png](D:\Courses\We%20Innovate\SOC_Engineering_week\soar.100_task\if.png)



- **Data Extraction**: Apply the **Set Node** to extract important fields (hostname, user, Source IP).



![get_info.png](D:\Courses\We%20Innovate\SOC_Engineering_week\soar.100_task\get_info.png)



- **Notification**: Send alert emails via **Gmail/SMTP Node** to inform users about the malicious communication.



![sendmail.png](D:\Courses\We%20Innovate\SOC_Engineering_week\soar.100_task\sendmail.png)



### Testing



![mailrecieved.png](D:\Courses\We%20Innovate\SOC_Engineering_week\soar.100_task\mailrecieved.png)



---

### Expected Outcomes

- Faster incident response by automatically detecting malicious IP communications.

- Improved user awareness with direct email alerts.

- Reduced workload on SOC analysts through automation.


