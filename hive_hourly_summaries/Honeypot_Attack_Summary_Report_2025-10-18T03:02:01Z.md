Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-18T03:01:19Z
**Timeframe:** This report summarizes data from the last hour, generated from three 2-minute log snippets.

**Files Used:**
- `agg_log_20251018T022001Z.json`
- `agg_log_20251018T024001Z.json`
- `agg_log_20251018T030001Z.json`

### Executive Summary

This report outlines the malicious activities captured by our honeypot network over the last hour. A total of 14,473 attacks were recorded across various honeypots. The `Cowrie` honeypot registered the highest number of interactions, indicating a strong focus on SSH-based attacks. The most prominent attack vector was the exploitation of SMB services, with TCP port 445 being the most targeted. A significant number of attacks originated from the IP address `58.56.127.170`. Attackers were observed attempting to download and execute malicious scripts, manipulate SSH authorized keys, and perform system reconnaissance. The "DoublePulsar Backdoor" signature was the most frequently triggered, suggesting attempts to exploit known vulnerabilities.

### Detailed Analysis

**Attacks by Honeypot:**
- **Cowrie:** 6256
- **Suricata:** 3006
- **Honeytrap:** 2427
- **Ciscoasa:** 1407
- **Dionaea:** 875
- **Sentrypeer:** 250
- **Mailoney:** 85
- **Tanner:** 87
- **H0neytr4p:** 37
- **ConPot:** 14
- **Adbhoney:** 13
- **Honeyaml:** 11
- **Redishoneypot:** 3
- **ElasticPot:** 1
- **Ipphoney:** 1

**Top Attacking IPs:**
- **58.56.127.170:** 1717
- **72.146.232.13:** 903
- **186.10.24.214:** 791
- **157.92.145.135:** 692
- **116.110.16.226:** 435
- **116.110.16.222:** 408
- **79.116.89.197:** 347
- **124.70.223.123:** 330
- **66.181.171.136:** 382
- **194.226.49.149:** 362
- **193.32.162.157:** 263
- **107.170.36.5:** 245
- **103.144.28.85:** 173
- **103.23.135.183:** 174
- **103.134.154.55:** 223

**Top Targeted Ports/Protocols:**
- **TCP/445:** 1821
- **445:** 855
- **22:** 1175
- **5060:** 250
- **5903:** 225
- **8333:** 126
- **80:** 93
- **5901:** 112
- **25:** 86
- **TCP/80:** 68
- **TCP/22:** 57
- **5905:** 75
- **5904:** 74
- **5907:** 50
- **5909:** 50
- **5908:** 48
- **9000:** 38
- **UDP/161:** 14
- **443:** 33

**Most Common CVEs:**
- `CVE-2002-0013 CVE-2002-0012`: 9
- `CVE-2002-0013 CVE-2002-0012 CVE-1999-0517`: 6
- `CVE-2024-1709 CVE-2024-1709`: 6
- `CVE-2021-3449 CVE-2021-3449`: 3
- `CVE-2019-11500 CVE-2019-11500`: 2
- `CVE-2019-12263 CVE-2019-12261 CVE-2019-12260 CVE-2019-12255`: 2
- `CVE-2024-3721 CVE-2024-3721`: 1
- `CVE-2021-35394 CVE-2021-35394`: 1
- `CVE-2016-20016 CVE-2016-20016`: 1

**Commands Attempted by Attackers:**
- `cd ~; chattr -ia .ssh; lockr -ia .ssh`: 17
- `lockr -ia .ssh`: 17
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."`: 17
- `cat /proc/cpuinfo | grep name | wc -l`: 17
- `Enter new UNIX password:`: 16
- `cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'`: 17
- `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`: 17
- `ls -lh $(which ls)`: 17
- `which ls`: 17
- `crontab -l`: 17
- `w`: 17
- `uname -m`: 17
- `cat /proc/cpuinfo | grep model | grep name | wc -l`: 17
- `top`: 17
- `uname`: 17
- `uname -a`: 18
- `whoami`: 17
- `lscpu | grep Model`: 17
- `df -h | head -n 2 | awk 'FNR == 2 {print $2;}'`: 17

**Signatures Triggered:**
- `ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication`: 1814
- `ET DROP Dshield Block Listed Source group 1`: 320
- `ET SCAN NMAP -sS window 1024`: 126
- `ET SCAN Potential SSH Scan`: 43
- `ET INFO CURL User Agent`: 37
- `ET SCAN MS Terminal Server Traffic on Non-standard Port`: 43
- `ET INFO Reserved Internal IP Traffic`: 47
- `ET WEB_SERVER Possible HTTP 404 XSS Attempt (Local Source)`: 36
- `ET CINS Active Threat Intelligence Poor Reputation IP group 47`: 19
- `ET CINS Active Threat Intelligence Poor Reputation IP group 44`: 8
- `ET CINS Active Threat Intelligence Poor Reputation IP group 50`: 7
- `ET CINS Active Threat Intelligence Poor Reputation IP group 49`: 12
- `ET SCAN Laravel Debug Mode Information Disclosure Probe Inbound`: 11

**Users / Login Attempts:**
- `345gs5662d34/345gs5662d34`: 17
- `debian/debian2016`: 4
- `guest/guest2008`: 4
- `operator/operator2018`: 4
- `nobody/0000000`: 4
- `support/88888`: 4
- `root/1qaz2wsx`: 4
- `blank/1q2w3e`: 4
- `blank/alpine`: 4
- `root/1Q2W3E4R5TY`: 3
- `nagios/nagios123`: 3
- `root/1qaw3ed`: 3
- `root/P@ssword`: 3
- `root/Pa$$w0rd`: 3
- `ubnt/ubnt2004`: 3
- `plex/plex`: 3
- `root/1`: 3
- `root/qwerty123`: 3
- `root/!Q2w3e4r`: 3
- `ubuntu/ubuntu`: 3
- `elastic/elastic`: 3

**Files Uploaded/Downloaded:**
- `fonts.gstatic.com`: 35
- `css?family=Libre+Franklin...`: 35
- `ie8.css?ver=1.0`: 35
- `html5.js?ver=3.7.3`: 35
- `arm.urbotnetisass`: 1
- `arm5.urbotnetisass`: 1
- `arm6.urbotnetisass`: 1
- `arm7.urbotnetisass`: 1
- `x86_32.urbotnetisass`: 1
- `mips.urbotnetisass`: 1
- `mipsel.urbotnetisass`: 1
- `ohshit.sh;`: 4
- `wget.sh;`: 4
- `w.sh;`: 1
- `c.sh;`: 1

**HTTP User-Agents:**
- *None Recorded*

**SSH Clients and Servers:**
- *None Recorded*

**Top Attacker AS Organizations:**
- *None Recorded*

### Key Observations and Anomalies

- **Automated Script Execution:** Attackers were frequently observed attempting to download and execute shell scripts (e.g., `w.sh`, `c.sh`, `wget.sh`, `ohshit.sh`) using `wget` and `curl`. This is indicative of automated attempts to install malware or backdoors.
- **SSH Key Manipulation:** A recurring command sequence involved removing the `.ssh` directory and replacing it with a new `authorized_keys` file containing a hardcoded public key. This is a common technique for attackers to maintain persistent access to a compromised machine.
- **Malware Delivery:** The downloading of files with names like `*.urbotnetisass` suggests attempts to install specific malware, likely targeting various architectures (ARM, x86, MIPS).
- **Reconnaissance:** A large number of commands were focused on system reconnaissance, such as checking CPU information (`/proc/cpuinfo`), memory usage (`free -m`), disk space (`df -h`), and running processes (`top`). This is typical behavior for attackers trying to understand the environment they have landed in.

The observed activities point to a high volume of automated attacks targeting common vulnerabilities and weak credentials. The focus on SSH and SMB protocols, combined with the specific malware and command patterns, suggests widespread, opportunistic campaigns.