# Alerting with ElastAlert2

### Step 1: Install Dependencies

First, install the core package and the specific versions of dependencies required for compatibility.

```bash
git clone https://github.com/jertel/elastalert2.git
pip install "setuptools>=11.3"
python setup.py install
```

### Step 2: Initialize Workspace

Prepare the configuration files and create a dedicated folder for your alerting rules.

```bash
# Move to the example directory to copy the template
cd example/
cp config.yaml.example config.yaml
cd ..

# Create a folder to store all your alert rules
mkdir rules
```

### Step 3: Configure Global Settings

Edit the main configuration file to establish a secure connection to your Elasticsearch server.

```bash
nano config.yaml
```

Paste the following configuration:

```bash
# --- Connection Settings ---
use_ssl: True
verify_certs: False  # Set to False for self-signed certificates
ssl_show_warn: False
es_host: 192.168.1.50
es_port: 9200

# --- Authentication ---
es_username: "elastic"
es_password: "your_password"

# --- General Settings ---
rules_folder: rules
run_every:
  minutes: 1
writeback_index: elastalert_status
buffer_time:
  minutes: 15
```

### Step 4: Create the Disk Usage Rule

Define the logic for the alert, the threshold (10%), and the email format.

```bash
nano rules/disk_usage_alert.yaml
```

Paste the following rule:

```bash
# Required fields according to documentation
name: "High Disk Usage Alert"
type: "any"
index: "metrics-*"

# Time settings (unit: X format)
run_every:
  minutes: 1
buffer_time:
  minutes: 60

# Filter DSL - Alert if disk usage is greater than 10% (0.1)
filter:
- range:
    system.filesystem.used.pct:
      gt: 0.90

# --- Alert Customization ---

# 1. Subject line for your inbox
alert_subject: "CRITICAL: High Disk Usage on {0}"
alert_subject_args:
  - agent.name

# 2. Custom body text
alert_text_type: alert_text_only
alert_text: |
  Disk Space Alert!
  -----------------------------------
  Hostname: {0}
  Mount Point: {1}
  Usage Percentage: {2}
  Time of Event: {3}
  -----------------------------------
  Action Required: Please clear some space on the server.

# 3. Mapping variables {0}, {1}, {2}, {3} to data fields
alert_text_args:
  - agent.name
  - system.filesystem.mount_point
  - system.filesystem.used.pct
  - "@timestamp"

# --- Alerter Configuration ---

# Alert type
alert:
  - "email"

# Recipient email (where you receive the alert)
email:
  - "user@gmail.com"

# Sender email (must match the user in smtp_auth.yaml)
from_addr: "user-two@gmail.com"

# Server Settings
smtp_host: "smtp.gmail.com"
smtp_port: 587
smtp_starttls: true
smtp_ssl: false

# Authentication file path
smtp_auth_file: "/home/$USER/elastalert2/smtp_auth.yaml"

# Realert: Send only one email per hour for the same issue
realert:
  minutes: 60
```

### Step 4.5: Create SMTP Authentication File

This file stores the credentials for your sender email (`youemail@gmail.com`). For Gmail, you **must** use an **App Password** (16 characters), not your regular login password.

```bash
# Create the file in your main directory
nano /home/$USER/elastalert2/smtp_auth.yaml
```

```bash
# Gmail Credentials
user: "youremail@gmail.com"

# Replace with your 16-character Google App Password
# Example: "abcd efgh ijkl mnop"
password: "your_google_app_password"
```

### Step 5: Initialize Metadata Index

Before running for the first time, create the internal index that ElastAlert 2 uses to track alert history.

```bash
python3 -m elastalert.create_index --config config.yaml
```

### Step 6: Launch ElastAlert 2

Run the application in verbose mode to monitor the logs and ensure alerts are firing correctly.

```bash
python3 -m elastalert.elastalert --config config.yaml --verbose
```

### Step 7: Create a Systemd Service (Autostart & Background)

This step ensures ElastAlert 2 runs as a persistent service in the background.

### 1. Create the Service File

Open a new service configuration file using `sudo`:

```bash
sudo nano /etc/systemd/system/elastalert.service
```

### 2. Paste the Service Configuration

Copy and paste the following block (adjust the paths if your username is different from `saeed`):

```bash
[Unit]
Description=ElastAlert 2 Service
After=network.target elasticsearch.service

[Service]
Type=simple
# Path to your virtual environment python and elastalert module
User=saeed
WorkingDirectory=/home/saeed/elastalert2
ExecStart=/home/saeed/elastalert2/pytools/bin/python3 -m elastalert.elastalert --config /home/saeed/elastalert2/config.yaml --verbose
StandardOutput=append:/home/saeed/elastalert2/elastalert.log
StandardError=append:/home/saeed/elastalert2/elastalert.log
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

**Note:** Make sure the `ExecStart` path points exactly to the `python3` inside your **pytools** folder. You can find the exact path by typing `which python` while your environment is active.

### 3. Enable and Start the Service

Now, tell Debian to recognize the new service and start it:

```bash
# Reload the systemd manager to see the new file
sudo systemctl daemon-reload

# Enable the service to start on every boot
sudo systemctl enable elastalert.service

# Start the service now
sudo systemctl start elastalert.service
```

## Step 8: Optional - Sending Alerts to Discord (Webhooks)

Using Discord is often faster and more reliable than Email. It provides instant mobile notifications and doesn't require SMTP authentication.

### 1. Create a Discord Webhook

1. Open your Discord Server.
2. Go to **Server Settings** > **Integrations** > **Webhooks**.
3. Click **New Webhook**, name it "ElastAlert", and select your desired channel.
4. Click **Copy Webhook URL**.

### 2. Update the Rule File

Modify your `rules/disk_usage_alert.yaml` to include the Discord settings. You can use **both** Email and Discord at the same time if you wish.

```bash
nano rules/disk_usage_alert.yaml
```

Paste/Update this section:

```bash
# --- Alerter Configuration ---

# You can list both 'email' and 'discord' here
alert:
  - "discord"
  - "email"

# Discord Webhook URL (Paste your copied link here)
discord_webhook_url: "https://discord.com/api/webhooks/YOUR_ID/YOUR_TOKEN"

# Enhanced Discord Text Format (Supports Markdown)
alert_text_type: alert_text_only
alert_text: |
  **:warning: DISK USAGE CRITICAL :warning:**
  -----------------------------------
  **Hostname:** {0}
  **Mount Point:** {1}
  **Usage:** {2}
  **Time:** {3}
  -----------------------------------
  *Action Required: Please check the server immediately.*

alert_text_args:
  - agent.name
  - system.filesystem.mount_point
  - system.filesystem.used.pct
  - "@timestamp"
```

### 3. Restart the Service

Whenever you change a rule file, you must restart the service to apply the changes:

```bash
sudo systemctl restart elastalert.service
```
