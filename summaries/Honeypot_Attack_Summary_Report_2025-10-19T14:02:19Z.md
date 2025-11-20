Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-19T14:01:26Z
**Timeframe:** 2025-10-19T13:20:01Z to 2025-10-19T14:00:01Z
**Log Files:**
*   agg_log_20251019T132001Z.json
*   agg_log_20251019T134001Z.json
*   agg_log_20251019T140001Z.json

### Executive Summary

This report summarizes 26,405 events collected from the honeypot network. The majority of attacks were captured by the Cowrie honeypot, with significant activity also observed on Dionaea and Honeytrap. The most prominent attack vector remains SSH, with a high volume of brute-force attempts. A notable concentration of attacks originated from the IP address 77.232.146.41. The most frequently observed CVE is CVE-2005-4050, related to SIP protocol vulnerabilities.

### Detailed Analysis

**Attacks by Honeypot:**
*   Cowrie: 12,224
*   Honeytrap: 4,026
*   Dionaea: 3,172
*   Suricata: 3,058
*   Sentrypeer: 2,681
*   Ciscoasa: 852
*   Redishoneypot: 120
*   Tanner: 108
*   H0neytr4p: 56
*   Mailoney: 26
*   Miniprint: 18
*   ConPot: 16
*   Dicompot: 15
*   Adbhoney: 15
*   Honeyaml: 12
*   ElasticPot: 4
*   Heralding: 2

**Top Attacking IPs:**
*   77.232.146.41: 3,103
*   194.50.16.73: 2,037
*   137.184.179.27: 1,244
*   51.89.1.88: 1,258
*   72.146.232.13: 1,206
*   198.23.190.58: 1,197
*   23.94.26.58: 1,179
*   198.12.68.114: 848
*   188.166.103.215: 758
*   45.128.199.34: 503
*   178.128.254.166: 480
*   81.192.46.36: 417
*   185.243.5.103: 410
*   196.251.72.53: 339
*   123.20.40.90: 302
*   193.32.162.157: 242
*   116.110.146.224: 175
*   171.231.185.185: 155
*   103.148.195.173: 124
*   4.213.138.243: 119

**Top Targeted Ports/Protocols:**
*   445: 3,112
*   5060: 2,681
*   22: 2,591
*   UDP/5060: 1,386
*   5903: 224
*   8333: 159
*   TCP/22: 143
*   6379: 120
*   5901: 113
*   80: 112
*   5909: 49
*   5908: 48
*   5907: 48
*   TCP/445: 27
*   5905: 74
*   5904: 75
*   3306: 21
*   22999: 19
*   25: 14
*   TCP/443: 13

**Most Common CVEs:**
*   CVE-2005-4050: 1,382
*   CVE-2019-11500: 5
*   CVE-2021-3449: 4
*   CVE-2002-0013, CVE-2002-0012: 2
*   CVE-2006-3602, CVE-2006-4458, CVE-2006-4542: 1
*   CVE-2002-0013, CVE-2002-0012, CVE-1999-0517: 1

**Commands Attempted by Attackers:**
*   `cd ~; chattr -ia .ssh; lockr -ia .ssh`: 24
*   `lockr -ia .ssh`: 24
*   `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..." >> .ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~`: 23
*   `cat /proc/cpuinfo | grep name | wc -l`: 23
*   `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`: 23
*   `ls -lh $(which ls)`: 23
*   `which ls`: 23
*   `crontab -l`: 23
*   `w`: 23
*   `uname -m`: 23
*   `cat /proc/cpuinfo | grep model | grep name | wc -l`: 23
*   `top`: 23
*   `uname`: 23
*   `uname -a`: 23
*   `whoami`: 23
*   `lscpu | grep Model`: 23
*   `df -h | head -n 2 | awk 'FNR == 2 {print $2;}'`: 23
*   `Enter new UNIX password: `: 21
*   `Enter new UNIX password:`: 21

**Signatures Triggered:**
*   ET VOIP MultiTech SIP UDP Overflow (2003237): 1,382
*   ET DROP Dshield Block Listed Source group 1 (2402000): 503
*   ET SCAN MS Terminal Server Traffic on Non-standard Port (2023753): 220
*   ET SCAN NMAP -sS window 1024 (2009582): 160
*   ET SCAN Potential SSH Scan (2001219): 133
*   ET HUNTING RDP Authentication Bypass Attempt (2034857): 85
*   ET INFO Reserved Internal IP Traffic (2002752): 56
*   ET INFO CURL User Agent (2002824): 33
*   ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication (2024766): 25
*   ET SCAN Suspicious inbound to PostgreSQL port 5432 (2010939): 23

**Users / Login Attempts:**
*   345gs5662d34/345gs5662d34: 21
*   user01/Password01: 12
*   deploy/123123: 9
*   blank/333333: 7
*   debian/debian2000: 7
*   config/p@ssword: 6
*   default/default333: 6
*   nobody/nobody2017: 6
*   admin/admin2023: 6
*   guest/00: 6
*   root/621248: 4
*   blank/blank222: 4
*   unknown/9999999: 4
*   root/63su03ta03no: 4
*   postgres/postgres123: 4
*   root/654789QqWw654789QqWw: 4
*   ubnt/qwerty12345: 4
*   root/65ab49cd13ef: 4
*   nobody/123654: 4
*   root/65corvair!: 4
*   blank/ubuntu: 4

**Files Uploaded/Downloaded:**
*   wget.sh;
*   w.sh;
*   c.sh;
*   rondo.naz.sh|sh&...

**HTTP User-Agents:**
*   *No user agents recorded in this timeframe.*

**SSH Clients and Servers:**
*   *No specific SSH client or server versions recorded in this timeframe.*

**Top Attacker AS Organizations:**
*   *No AS organization data recorded in this timeframe.*

### Key Observations and Anomalies

*   **High Volume of SIP Attacks:** The high number of events related to CVE-2005-4050 and the "ET VOIP MultiTech SIP UDP Overflow" signature indicates a targeted campaign against VoIP systems.
*   **Repetitive SSH Commands:** The commands executed by attackers are consistent and focus on reconnaissance and establishing persistence by adding SSH keys to `authorized_keys`.
*   **Malware Download Attempts:** The presence of `wget` and `curl` commands, along with filenames like `w.sh`, `c.sh`, and `wget.sh`, suggests attempts to download and execute malicious scripts.
*   **DoublePulsar Detection:** The "DoublePulsar Backdoor" signature suggests that some attackers are attempting to exploit systems using tools associated with the Equation Group.
