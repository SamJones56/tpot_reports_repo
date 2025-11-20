Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-15T20:01:28Z
**Timeframe:** 2025-10-15T19:20:01Z to 2025-10-15T20:00:01Z
**Log Files:**
- agg_log_20251015T192001Z.json
- agg_log_20251015T194001Z.json
- agg_log_20251015T200001Z.json

### Executive Summary
This report summarizes 17,105 events collected from the honeypot network over a 40-minute period. The majority of attacks were captured by the Cowrie, Honeytrap, and Sentrypeer honeypots. A significant volume of activity originated from IP address 206.191.154.180. The most frequently targeted port was 5060 (SIP), followed by port 22 (SSH). Attackers were observed attempting to exploit older vulnerabilities, including CVE-2002-0013 and CVE-2002-0012, and used a variety of common and default credentials in brute-force attempts. A notable command pattern involved attempts to modify the `.ssh/authorized_keys` file to gain persistent access.

### Detailed Analysis

**Attacks by Honeypot**
- Cowrie: 6196
- Honeytrap: 3848
- Sentrypeer: 3585
- Ciscoasa: 1660
- Suricata: 1390
- Dionaea: 134
- Miniprint: 62
- Redishoneypot: 53
- Tanner: 56
- ConPot: 42
- Mailoney: 37
- Honeyaml: 20
- H0neytr4p: 10
- Dicompot: 6
- Adbhoney: 3
- Ipphoney: 1
- ElasticPot: 2

**Top Attacking IPs**
- 206.191.154.180: 1363
- 185.243.5.121: 1205
- 196.251.88.103: 951
- 47.116.214.122: 863
- 23.94.26.58: 861
- 172.86.95.98: 496
- 172.86.95.115: 471
- 14.29.238.151: 365
- 162.240.109.28: 317
- 62.141.43.183: 322

**Top Targeted Ports/Protocols**
- 5060: 3585
- 22: 906
- 5903: 229
- 23: 94
- 8333: 96
- 5901: 113
- 445: 53
- UDP/5060: 94
- 80: 65
- TCP/22: 46

**Most Common CVEs**
- CVE-2002-0013 CVE-2002-0012: 12
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 6
- CVE-2019-11500 CVE-2019-11500: 3
- CVE-2006-2369: 1
- CVE-2002-1149: 1

**Commands Attempted by Attackers**
- cd ~; chattr -ia .ssh; lockr -ia .ssh: 26
- lockr -ia .ssh: 26
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ...": 26
- cat /proc/cpuinfo | grep name | wc -l: 26
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}': 26
- whoami: 26
- uname -a: 26
- crontab -l: 26
- rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; ...: 9
- uname -s -v -n -r -m: 5

**Signatures Triggered**
- ET DROP Dshield Block Listed Source group 1: 350
- 2402000: 350
- ET SCAN NMAP -sS window 1024: 174
- 2009582: 174
- ET INFO Reserved Internal IP Traffic: 58
- 2002752: 58
- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication: 49
- 2024766: 49
- ET SCAN Potential SSH Scan: 41
- 2001219: 41

**Users / Login Attempts**
- 345gs5662d34/345gs5662d34: 26
- root/Qaz123qaz: 12
- root/123@@@: 11
- root/3245gs5662d34: 11
- config/22222: 6
- debian/debian222: 6
- support/password321: 8
- root/1234567: 4
- support/111111: 10

**Files Uploaded/Downloaded**
- 11: 7
- fonts.gstatic.com: 7
- css?family=Libre+Franklin...: 7
- ie8.css?ver=1.0: 7
- html5.js?ver=3.7.3: 7
- arm.urbotnetisass;: 1
- mipsel.urbotnetisass: 1
- x86_32.urbotnetisass: 1

**HTTP User-Agents**
- No user agents recorded in this period.

**SSH Clients**
- No SSH clients recorded in this period.

**SSH Servers**
- No SSH servers recorded in this period.

**Top Attacker AS Organizations**
- No AS organizations recorded in this period.

### Key Observations and Anomalies
- **SSH Persistence:** A recurring tactic observed across multiple attack attempts involved a series of commands designed to establish SSH persistence. The sequence `cd ~; chattr -ia .ssh; lockr -ia .ssh` followed by adding a new SSH key to `authorized_keys` indicates a clear and automated attempt to maintain access after a successful breach.
- **SIP Scanning:** The high number of events on port 5060 suggests widespread, automated scanning for vulnerabilities in VoIP (Voice over IP) systems. This remains a consistent and high-volume threat vector.
- **Malware Downloads:** The `Dionaea` honeypot captured attempts to download several variants of the "urbotnetisass" malware, targeting different architectures (ARM, x86, MIPS). This indicates attackers are attempting to compromise IoT or embedded devices.
- **Outdated CVEs:** The focus on CVEs from the early 2000s (e.g., CVE-2002-0012) suggests that attackers are still finding success with legacy vulnerabilities, likely targeting unpatched or abandoned systems.