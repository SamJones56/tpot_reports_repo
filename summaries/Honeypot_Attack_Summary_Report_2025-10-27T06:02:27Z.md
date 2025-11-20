Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-27T06:01:41Z
**Timeframe:** 2025-10-27T05:20:01Z to 2025-10-27T06:00:01Z
**Log Files:**
- agg_log_20251027T052001Z.json
- agg_log_20251027T054001Z.json
- agg_log_20251027T060001Z.json

### Executive Summary
This report summarizes 21,704 events collected from multiple honeypots over the last hour. The majority of attacks targeted the Sentrypeer honeypot, indicating significant scanning activity related to VoIP services. A single IP address, `2.57.121.61`, was responsible for a large volume of these scans. A notable number of SSH-based attacks were also observed, with attackers attempting to gain access using common credentials and execute post-exploitation commands, including modifying SSH authorized keys and system reconnaissance. Several vulnerabilities were targeted, with `CVE-2005-4050` being the most frequent.

### Detailed Analysis

**Attacks by Honeypot:**
- Sentrypeer: 9716
- Cowrie: 3225
- Suricata: 3188
- Honeytrap: 2839
- Ciscoasa: 1632
- Dionaea: 711
- Tanner: 98
- Adbhoney: 79
- Mailoney: 75
- H0neytr4p: 46
- ConPot: 32
- Redishoneypot: 18
- Honeyaml: 19
- Miniprint: 16
- ElasticPot: 5
- Ipphoney: 5

**Top Attacking IPs:**
- 2.57.121.61: 7090
- 198.23.190.58: 1952
- 144.172.108.231: 1000
- 160.22.87.9: 873
- 1.10.130.237: 429
- 134.122.60.171: 558
- 77.90.185.47: 334
- 79.106.102.70: 287
- 185.243.5.158: 309
- 103.174.114.143: 292
- 103.45.234.227: 202
- 45.119.81.249: 197
- 201.81.240.66: 187
- 107.170.36.5: 216
- 69.63.77.146: 197
- 88.210.63.16: 145

**Top Targeted Ports/Protocols:**
- 5060: 9716
- TCP/445: 878
- 445: 683
- UDP/5060: 654
- 22: 489
- TCP/80: 83
- TCP/22: 73
- 80: 96
- 25: 75
- 5903: 110
- 5901: 103
- 20201: 102

**Most Common CVEs:**
- CVE-2005-4050: 652
- CVE-2002-0013 CVE-2002-0012: 5
- CVE-2024-4577 CVE-2002-0953: 2
- CVE-2024-4577 CVE-2024-4577: 2
- CVE-2021-41773 CVE-2021-41773 CVE-2021-41773 CVE-2021-41773: 1
- CVE-2021-42013 CVE-2021-42013: 1

**Commands Attempted by Attackers:**
- `cd ~; chattr -ia .ssh; lockr -ia .ssh`: 15
- `lockr -ia .ssh`: 15
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."`: 15
- `cat /proc/cpuinfo | grep name | wc -l`: 13
- `cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'`: 13
- `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`: 13
- `ls -lh $(which ls)`: 13
- `which ls`: 13
- `crontab -l`: 13
- `w`: 13
- `uname -m`: 13
- `whoami`: 13
- `lscpu | grep Model`: 13
- `df -h | head -n 2 | awk 'FNR == 2 {print $2;}'`: 13
- `uname -a`: 12
- `top`: 12
- `uname`: 12
- `cd /data/local/tmp/; busybox wget ...`: 6
- `Enter new UNIX password: `: 6

**Signatures Triggered:**
- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication: 874
- 2024766: 874
- ET VOIP MultiTech SIP UDP Overflow: 652
- 2003237: 652
- ET DROP Dshield Block Listed Source group 1: 390
- 2402000: 390
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 297
- 2023753: 297
- ET SCAN NMAP -sS window 1024: 157
- 2009582: 157
- ET HUNTING RDP Authentication Bypass Attempt: 107
- 2034857: 107
- ET INFO Reserved Internal IP Traffic: 51
- 2002752: 51
- ET INFO curl User-Agent Outbound: 23
- 2013028: 23
- ET HUNTING curl User-Agent to Dotted Quad: 23
- 2034567: 23

**Users / Login Attempts (username/password):**
- 345gs5662d34/345gs5662d34: 15
- root/3245gs5662d34: 7
- root/Igpwwpn2014: 4
- root/IgS123!!: 4
- root/IhtT4204: 4
- root/ik87Tgfr!QW: 4
- deploy/111111: 4
- root/ihN42oz1: 4
- wordpress/wordpress: 3
- root/02041992Ionela%^&: 3
- ubuntu/tizi@123: 3
- miroslav/miroslav: 3
- root/Ikatel: 3

**Files Uploaded/Downloaded:**
- sh: 98
- wget.sh;: 32
- w.sh;: 8
- c.sh;: 8
- arm.urbotnetisass: 2
- arm5.urbotnetisass: 2
- arm6.urbotnetisass: 2
- arm7.urbotnetisass: 2
- x86_32.urbotnetisass: 2
- mips.urbotnetisass: 2
- mipsel.urbotnetisass: 2

**HTTP User-Agents:**
- *No user agents recorded in this timeframe.*

**SSH Clients:**
- *No client versions recorded in this timeframe.*

**SSH Servers:**
- *No server versions recorded in this timeframe.*

**Top Attacker AS Organizations:**
- *No AS organizations recorded in this timeframe.*

### Key Observations and Anomalies
- The overwhelming volume of traffic from `2.57.121.61` targeting port 5060 (SIP) suggests a large-scale, automated scanning operation, likely searching for vulnerable VoIP systems.
- Attackers on the Cowrie (SSH) honeypot consistently attempt to modify the `.ssh/authorized_keys` file. This is a common technique to establish persistent backdoor access. The repeated use of the same SSH key indicates a coordinated campaign.
- The execution of `wget` and `curl` to download and execute shell scripts (`w.sh`, `c.sh`, `wget.sh`) and binaries (`*.urbotnetisass`) from attacker-controlled servers (`213.209.143.62`, `94.154.35.154`, `202.55.132.254`) points to attempts to deploy malware or enroll the device in a botnet.
- The Suricata honeypot triggered numerous alerts for the DoublePulsar backdoor, which is associated with the EternalBlue exploit. This indicates that systems are still being scanned for this critical vulnerability.