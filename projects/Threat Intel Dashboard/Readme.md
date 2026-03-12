# Threat Intel Dashboard CLI

A lightweight, noise-reduced Threat Intelligence dashboard for IPs and Domains, built with Bash.  
This tool allows security analysts and enthusiasts to quickly check the reputation and high-risk reports of any IP or domain across multiple threat intelligence sources.

## Features

- Query **VirusTotal** for malicious/suspicious classifications and vendor-specific results.  
- Query **AbuseIPDB** for high-confidence abuse reports.  
- Noise-reduced output: shows only high-risk detections and relevant descriptions.  
- Color-coded CLI dashboard for quick risk assessment.  
- Displays **Clean / Safe** status for benign IPs/domains.  
- Easily extensible to add more Threat Intelligence sources (OTX, Shodan, GreyNoise).

## Requirements

- Bash  
- `curl`  
- `jq`  
- API Keys for VirusTotal and AbuseIPDB

## Usage

```bash
chmod +x cti_dashboard.sh
./cti_dashboard.sh
