# Elasticsearch-API-Workflow-with-n8n-and-VirusTotal

<p align ="center">
    <img src= "/projects/SOAR/screenshots/n8n-elk.svg"
</p>

 
## Project Overview
This project demonstrates how to create and use an Elasticsearch API key for secure access to indices, integrate it with n8n for workflow automation, and extend the workflow by connecting to the VirusTotal API for IP reputation checks.

The setup includes:

- Generating and using an Elasticsearch API key with curl
- Installing and deploying Docker & n8n
- Building an n8n workflow to query Elasticsearch indices
- Using Split Out and IF nodes for log filtering and conditions
- Integrating the VirusTotal API to scan suspicious IP addresses

This project provides a hands-on guide for automating threat intelligence workflows by combining log analysis from Elasticsearch with external reputation checks using VirusTotal.

### Prerequisites
- Ubuntu 20.04 / 22.04 (tested environment)
- Elasticsearch instance running (remote or local)
- Docker & Docker Compose installed
- n8n (latest Docker image)
- VirusTotal API key (free or premium account)

----

## ***Create API for Elasticsearch***
First, generate an API key that allows secure access to **Elasticsearch indices**.

Replace: `<username>` with your elastic username, `<password>` with your Elastic password and `<elastic_ip>` with the ip of the elastic machine

```shell
curl -u <elastic_username>:<your_password> -X POST "https://<elastic_ip>:9200/_security/api_key" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "my-api-key",
    "role_descriptors": {}
  }' \
  -k
```

**Next** 

<p align ="center">
    <img src= "/projects/SOAR/screenshots/elk_api_off.png"
</p>

From the elastic website:

Replace `<api>` with the **Encoded API**

```shell
curl -X GET "https://192.168.1.40:9200/_cat/indices?v=true" \
  -H "Authorization: ApiKey <api>" \
  -k
```

---
## ***Install Docker & n8n***
We will deploy n8n, an automation and workflow orchestration tool, using Docker

```shell
sudo apt update && sudo apt upgrade -y
sudo apt install ca-certificates curl gnupg lsb-release -y

sudo mkdir -p /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg

echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
  $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

sudo apt install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin -y

```

**Deploy n8n:**

```shell
docker volume create n8n_data
docker run -it --rm --name n8n -p 5678:5678 -v n8n_data:/home/node/.n8n docker.n8n.io/n8nio/n8n
```

----
## ***Create the workflow***
Access the n8n editor at `http://localhost:5678`
	
#### 1) Create Credential
Name: Elasticsearch account
- Username: `<elastic_username>`
- password: `<decoded API>`
- Base URL: `<elastic_url>`
- `ignore SSL `

<p align ="center">
    <img src= "/projects/SOAR/screenshots/create_credintials.png"
</p>

#### 2) Create workflow

<p align ="center">
    <img src= "/projects/SOAR/screenshots/create_workflow.png"
</p>


- deploy `HTTP Request`
	- configure the autorization process
	- Methode: `GET`
	- URL: `<elastic_url>/<index_name>/_search`
	- Authentication: `Predefined Credential Type`
	- Credential Type: `Elasticsearch API`
	- Elasticsearch API: `Elasticsearch account` >

Click `Execute`, now you should see the logs coming from your index:

<p align ="center">
<img src= "/projects/SOAR/screenshots/get_index.png"
</p>

#### 3) Deploy Split Out
We use `Split Out` to separate logs into individual items for easier processing

<p align ="center">
    <img src= "/projects/SOAR/screenshots/dia.png"
</p>
	
- In fields to Split Out: `<drag and drop the id of the begaining of log>`
- Include: `No Other Fields` 

<p align ="center">
    <img src= "/projects/SOAR/screenshots/split.png"
</p>

#### 4) IF
This step defines conditions to filter logs (e.g., by IP address)

<p align ="center">
    <img src= "/projects/SOAR/screenshots/dia.png"
</p>
	
<p align ="center">
    <img src= "/projects/SOAR/screenshots/if.png"
</p>

- Condition: `Drag and drop the value you want to specify`
- specify which condition state you want to use as a reference, in my case I will use `Is equal to` 
- I will make the reference value specific a **IP Address** 

<p align ="center">
    <img src= "/projects/SOAR/screenshots/dia.png"
</p>

>**Note:** `limit` is used to limit the amount of action per cycle




## ***VirusTotal API***
#### 1) Create Account on VirusTotal
Go to [VirusTotal](https://www.virustotal.com/gui/join-us) and create account and get your own API 

<p align ="center">
    <img src= "/projects/SOAR/screenshots/virustotal_acc_api.png"
</p>

#### 2) VirusTotal

<p align ="center">
    <img src= "/projects/SOAR/screenshots/virustotal_acc.png"
</p>
	
**Create Credential** and choose **VirusTotal account**
- API Token: `<virustotal_api>`

In the right menu search for `VirusTotal HTTP Request`, Then connect the `true` output of `IF` to it.

<p align ="center">
    <img src= "/projects/SOAR/screenshots/dia.png"
</p>

<p align ="center">
    <img src= "/projects/SOAR/screenshots/vt_conf.png"
</p>

- Credential for VirusTotal: `VirusTotal account`
- URL: it will set the url for you and put `/ip_addresses/<the id of the IP u want to scan>`

**Click Execute, it will display the VirusTotal scan's result**

<p align ="center">
    <img src= "/projects/SOAR/screenshots/final_w.png"
</p>

---

### **Feel free to contact me on** **[LinkedIn](https://www.linkedin.com/in/saeed-elfiky-61188b24b/)**.
