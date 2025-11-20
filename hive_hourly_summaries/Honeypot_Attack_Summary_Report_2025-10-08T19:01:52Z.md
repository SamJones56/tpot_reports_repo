Honeypot Attack Summary Report
Report generated on 2025-10-08T19:01:27Z for the period covering the last 6 minutes.
Files used to generate this report:
- agg_log_20251008T182001Z.json
- agg_log_20251008T184001Z.json
- agg_log_20251008T190002Z.json

Executive Summary
This report summarizes 17,969 malicious events recorded across the honeypot network. The majority of attacks targeted the Cowrie honeypot, indicating a high volume of SSH brute-force attempts. A significant portion of the activity originated from a small number of IP addresses, with 165.232.105.167 and 178.128.41.154 being the most persistent attackers. The most common attack vectors involved targeting services like SSH (port 22) and Windows SMB (port 445). Several CVEs were detected, including attempts to exploit vulnerabilities in Microsoft Exchange and Apache Struts. Attackers were observed attempting to download and execute malicious scripts, as well as attempting to manipulate SSH authorized_keys to maintain persistence.

Detailed Analysis:

Attacks by Honeypot:
- Cowrie: 10227
- Honeytrap: 2894
- Suricata: 1516
- Ciscoasa: 1571
- Dionaea: 1204
- ConPot: 98
- Adbhoney: 84
- Sentrypeer: 103
- Mailoney: 94
- Tanner: 50
- Miniprint: 48
- Honeyaml: 16
- H0neytr4p: 23
- ElasticPot: 11
- Heralding: 11
- Redishoneypot: 12
- Dicompot: 6
- Wordpot: 1

Top Attacking IPs:
- 165.232.105.167: 1500
- 178.128.41.154: 1494
- 196.251.88.103: 996
- 103.75.54.141: 739
- 182.176.149.227: 402
- 27.79.0.60: 363
- 209.38.90.29: 263
- 103.250.10.128: 242
- 171.244.141.177: 317
- 103.217.145.154: 233
- 94.228.113.178: 253
- 52.224.109.126: 184
- 103.189.235.134: 238
- 139.59.24.22: 224
- 180.76.119.46: 115
- 167.71.221.242: 293
- 180.76.96.235: 110
- 58.69.56.44: 109
- 90.169.216.25: 109
- 187.45.100.0: 183
- 51.79.165.204: 92

Top Targeted Ports/Protocols:
- 22: 1618
- 445: 1144
- 5903: 208
- TCP/5900: 164
- 1024: 117
- 8333: 146
- 5060: 103
- 25: 95
- 80: 56
- 23: 28
- 9100: 48
- 5555: 20
- 1025: 89
- 443: 9
- 4433: 23
- 8291: 10

Most Common CVEs:
- CVE-2021-3449
- CVE-2019-11500
- CVE-2023-26801
- CVE-2018-11776
- CVE-2002-0013
- CVE-2002-0012
- CVE-2005-4050
- CVE-1999-0517
- CVE-2020-2551
- CVE-1999-0183

Commands Attempted by Attackers:
- cd ~; chattr -ia .ssh; lockr -ia .ssh
- lockr -ia .ssh
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."
- uname -a
- cat /proc/cpuinfo | grep name | wc -l
- Enter new UNIX password: 
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
- ls -lh $(which ls)
- which ls
- crontab -l
- w
- uname -m
- top
- whoami
- lscpu | grep Model
- df -h | head -n 2 | awk 'FNR == 2 {print $2;}'

Signatures Triggered:
- ET DROP Dshield Block Listed Source group 1
- ET SCAN NMAP -sS window 1024
- ET SCAN Potential SSH Scan
- ET SCAN MS Terminal Server Traffic on Non-standard Port
- ET INFO Reserved Internal IP Traffic
- ET INFO Proxy CONNECT Request
- ET HUNTING RDP Authentication Bypass Attempt
- ET DROP Spamhaus DROP Listed Traffic Inbound group 28
- ET CINS Active Threat Intelligence Poor Reputation IP group 41
- ET CINS Active Threat Intelligence Poor Reputation IP group 45
- ET DROP Spamhaus DROP Listed Traffic Inbound group 41
- ET CINS Active Threat Intelligence Poor Reputation IP group 48
- ET CINS Active Threat Intelligence Poor Reputation IP group 42
- ET CINS Active Threat Intelligence Poor Reputation IP group 43
- ET CINS Active Threat Intelligence Poor Reputation IP group 46

Users / Login Attempts:
- 345gs5662d34/345gs5662d34
- vpn/123
- unknown/4444444
- RPM/RPM
- devuser/devuser123
- myuser/Password@123
- root/qazwsx12
- kale/123
- root/7
- support/888
- root/root8
- ubnt/ubnt77
- Unknown/555555555
- centos/centos123456789
- guest/guest9
- ubnt/ubnt999
- github/github123321
- support/22222

Files Uploaded/Downloaded:
- wget.sh;
- w.sh;
- c.sh;

HTTP User-Agents:
- No HTTP User-Agents were recorded in this period.

SSH Clients and Servers:
- No specific SSH clients or servers were identified in this period.

Top Attacker AS Organizations:
- No attacker AS organizations were recorded in this period.

Key Observations and Anomalies
- The command `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."` was frequently observed. This indicates a common tactic to gain persistent access to compromised systems by adding the attacker's public key to the `authorized_keys` file.
- The high number of scans for port 445 suggests widespread attempts to exploit SMB vulnerabilities, possibly related to variants of ransomware or worms.
- A notable amount of activity was seen from IPs 165.232.105.167 and 178.128.41.154, which were responsible for a large percentage of the total attacks. These IPs should be monitored closely.
- The variety of CVEs being tested against the honeypots shows that attackers are using a broad range of exploits to find vulnerable systems.
- The presence of commands like `wget` and `curl` to download shell scripts (`w.sh`, `c.sh`, `wget.sh`) indicates attempts to install malware or other backdoors on the system.
- There were 246 dropped connections in total.
