# ⚡ Interactive IPTables Rule Adder (Bash + iptables)

This Bash script allows users to **interactively add firewall rules** using `iptables`.  
It guides the user step by step to define:
1. The **source IP address and subnet**.  
2. The **destination port**.  
3. The **action** to apply (ACCEPT, DROP, or REJECT).  
4. Users can add multiple rules in a single run.  
5. At the end, the script **lists all active iptables rules** for review.  

---

## Script

```bash
#!/bin/bash

# Print header
echo "====IP Table Rules===="

# Infinite loop to allow multiple rule additions
while true; do

    # Ask for IP and subnet
    read -p "Enter the IP Address and the subnet (e.g. 192.168.1.2/24): " address

    # Ask for destination port
    read -p "Enter the destination port: " port

    # Ask for action
    read -p "Enter the action (ACCEPT, DROP, REJECT): " action

    # Add the iptables rule
    sudo iptables -A INPUT -s "$address" -p tcp --dport "$port" -j "$action"

    # Confirm to user
    echo "Rule has been added IP= $address, Port= $port , Action= $action"

    # Ask if user wants to continue
    read -p "Do u want to add another rule? [y/n]: " yn
    case $yn in
        [Yy]) continue;;
        [Nn]) break;;
        *) echo "Please choose y/n";;
    esac
done

# Show final iptables rules
sudo iptables -L -v -n
```

### **Feel free to contact me on** **[LinkedIn](https://www.linkedin.com/in/saeed-elfiky-61188b24b/)**.
