# Elasticsearch-API-Workflow-with-n8n-and-VirusTotal


## Project Overview
This project demonstrates how to create and use an Elasticsearch API key for secure access to indices, integrate it with n8n for workflow automation, and extend the workflow by connecting to the VirusTotal API for IP reputation checks.

The setup includes:

- Generating and using an Elasticsearch API key with curl
- Installing and deploying Docker & n8n
- Building an n8n workflow to query Elasticsearch indices
- Using Split Out and IF nodes for log filtering and conditions
- Integrating the VirusTotal API to scan suspicious IP addresses

This project provides a hands-on guide for automating threat intelligence workflows by combining log analysis from Elasticsearch with external reputation checks using VirusTotal.

----

## ***Create API for Elasticsearch***
First write these commands to create the **Elasticsearch API** 

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

From the elastic website use this command to 

Replace `<api>` with the **Encoded API**

```shell
curl -X GET "https://192.168.1.40:9200/_cat/indices?v=true" \
  -H "Authorization: ApiKey <api>" \
  -k
```

---
## ***Install Docker & n8n***
We should install docker first, so we can use to download n8n

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


#### 2) Create workflow
- deploy `HTTP Request`
	- configure the autorization process
	- Methode: `GET`
	- URL: `<elastic_url>/<index_name>/_search`
	- Authentication: `Predefined Credential Type`
	- Credential Type: `Elasticsearch API`
	- Elasticsearch API: `Elasticsearch account` >
Click `Execute`, now you should see the logs coming from your index:



#### 3) Deploy Split Out
We use `Split out` to separate each log from the other

- In fields to Split Out: `<drag and drop the id of the begaining of log>`
- Include: `No Other Fields` 



#### 4) IF
We use **`IF`** to specify which case we should do action about

- Condition: `Drag and drop the value you want to specify`
- specify which condition state you want to use as a reference, in my case I will use `Is equal to` 
- I will make the reference value specific **IP Address** 

>**Note:** `limit` is used to limit the amount of action per execution




## ***VirusTotal API***
#### 1) Create Account on VirusTotal
Go to [VirusTotal](https://www.virustotal.com/gui/join-us) and create account and get your own API 



#### 2) VirusTotal
**Create Credential** and choose **VirusTotal account**
- API Token: `<virustotal_api>`

In the right menu search for `VirusTotal HTTP Request`, Then connect the `true` output of `IF` to it.

- Credential for VirusTotal: `VirusTotal account`
- URL: it will set the url for you and put `/ip_addresses/<the id of the IP u want to scan>`

**Click Execute, it will display the VirusTotal scan's result **
