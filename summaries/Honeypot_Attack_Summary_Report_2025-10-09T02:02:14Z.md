Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-09T02:01:28Z
**Timeframe:** 2025-10-09T01:20:01Z to 2025-10-09T02:00:01Z
**Files Used:**
- agg_log_20251009T012001Z.json
- agg_log_20251009T014001Z.json
- agg_log_20251009T020001Z.json

### Executive Summary
This report summarizes 28,091 events collected from the honeypot network over the last hour. The majority of attacks were captured by the Cowrie honeypot. The most targeted service was SMB on port 445. A significant amount of activity originated from IP address 188.246.224.87. Attackers attempted to exploit several vulnerabilities, with CVE-2021-44228 (Log4j) being the most prominent. A number of shell commands were executed, indicating attempts to establish persistence and gather system information.

### Detailed Analysis

**Attacks by Honeypot:**
*   **Cowrie:** 10,531
*   **Suricata:** 5,592
*   **Dionaea:** 5,426
*   **Honeytrap:** 3,944
*   **Ciscoasa:** 1,446
*   **Mailoney:** 887
*   **Sentrypeer:** 100
*   **Tanner:** 27
*   **Honeyaml:** 23
*   **ElasticPot:** 20
*   **Adbhoney:** 20
*   **H0neytr4p:** 15
*   **ConPot:** 13
*   **Heralding:** 34
*   **Redishoneypot:** 6
*   **Dicompot:** 4
*   **Medpot:** 3

**Top Attacking IPs:**
*   188.246.224.87: 3,289
*   182.10.130.80: 3,146
*   161.35.161.124: 1,163
*   139.59.176.42: 1,133
*   20.2.136.52: 1,043
*   36.81.153.14: 1,040
*   47.86.36.165: 840
*   176.65.141.117: 820
*   94.187.170.251: 783
*   36.68.34.158: 677

**Top Targeted Ports/Protocols:**
*   445: 4,742
*   22: 1,712
*   TCP/445: 1,616
*   25: 888
*   1026: 195
*   TCP/21: 186
*   5903: 184
*   8333: 147
*   TCP/22: 114
*   5060: 100

**Most Common CVEs:**
*   CVE-2021-44228
*   CVE-2019-11500
*   CVE-2016-20016
*   CVE-2005-4050
*   CVE-2002-0013
*   CVE-2002-0012
*   CVE-1999-0517

**Commands Attempted by Attackers:**
*   `cd ~; chattr -ia .ssh; lockr -ia .ssh`
*   `lockr -ia .ssh`
*   `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."`
*   `Enter new UNIX password:`
*   `cat /proc/cpuinfo | grep name | wc -l`
*   `cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'`
*   `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`
*   `ls -lh $(which ls)`
*   `which ls`
*   `crontab -l`
*   `w`
*   `uname -m`
*   `uname -a`
*   `whoami`

**Signatures Triggered:**
*   ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication: 1,614
*   ET SCAN MS Terminal Server Traffic on Non-standard Port: 1,612
*   ET HUNTING RDP Authentication Bypass Attempt: 778
*   ET DROP Dshield Block Listed Source group 1: 346
*   ET SCAN NMAP -sS window 1024: 145
*   ET SCAN Potential SSH Scan: 104
*   ET FTP FTP PWD command attempt without login: 93
*   ET FTP FTP CWD command attempt without login: 93

**Users / Login Attempts:**
*   345gs5662d34/345gs5662d34: 35
*   userbot/3245gs5662d34: 8
*   support/qaz123wsx: 6
*   root/D13HH[: 6
*   ubnt/ubnt6: 6
*   user/123: 4
*   root/911911: 4
*   admin/admin12345: 4
*   root/Aa123456: 4
*   git/git123: 4
*   minecraft/minecraft!: 4
*   support/5555555: 4
*   uucp/uucp: 4

**Files Uploaded/Downloaded:**
*   wget.sh;
*   w.sh;
*   c.sh;
*   11
*   fonts.gstatic.com
*   css?family=Libre+Franklin%3A300%2C300i%2C400%2C400i%2C600%2C600i%2C800%2C800i&amp;subset=latin%2Clatin-ext
*   ie8.css?ver=1.0
*   html5.js?ver=3.7.3

**HTTP User-Agents:**
*   *No data in logs*

**SSH Clients and Servers:**
*   *No data in logs*

**Top Attacker AS Organizations:**
*   *No data in logs*

### Key Observations and Anomalies
- The high number of events targeting port 445, combined with the "DoublePulsar Backdoor" signature, suggests widespread, automated attempts to exploit the EternalBlue vulnerability.
- The variety of commands executed through the Cowrie honeypot indicates that attackers are attempting to profile the system, likely to determine if it is a valuable target for further exploitation or for use in a botnet.
- The attempted downloads of `.sh` files are indicative of attempts to install malware or other malicious tools on the compromised system.
- The presence of login attempts with credentials like "minecraft/minecraft!" and "erpnext/erpnext!@#" suggests that attackers are targeting specific applications in addition to common default credentials.
