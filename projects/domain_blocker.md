# 🔒 Domain Blocker Script (Bash + iptables)

This Bash script does the following:
1. Takes a **domain name** as input.
2. Uses `dig` to resolve the domain into its **IP addresses**.
3. Blocks both **incoming (INPUT)** and **outgoing (OUTPUT)** traffic to these IPs using `iptables`.
4. Logs the domain and its resolved IP addresses into a text file (`test44.txt`).

---

## Script

```bash
#!/bin/bash

# Prompt the user
echo "Enter Domain"
read DOMAIN 

# Resolve domain to IP addresses
IP_ADDRESSES=$(dig +short $DOMAIN)

# Loop through each IP and block traffic
for IP in $IP_ADDRESSES; do
    sudo iptables -A OUTPUT -d $IP -j DROP
    sudo iptables -A INPUT -s $IP -j DROP
    echo "Blocked IP: $IP"
done

# Save the results into a file
FILE=test44.txt 
touch $FILE
echo "$DOMAIN" >> $FILE
echo "$IP_ADDRESSES" >> $FILE
```
### **Feel free to contact me on** **[LinkedIn](https://www.linkedin.com/in/saeed-elfiky-61188b24b/)**.
