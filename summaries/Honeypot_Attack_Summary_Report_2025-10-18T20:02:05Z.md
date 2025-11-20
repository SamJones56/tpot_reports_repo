Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-18T20:01:27Z
**Timeframe:** 2025-10-18T19:20:01Z to 2025-10-18T20:00:01Z
**Files Used:**
*   agg_log_20251018T192001Z.json
*   agg_log_20251018T194001Z.json
*   agg_log_20251018T200001Z.json

**Executive Summary**

This report summarizes honeypot activity over a period of approximately 40 minutes, analyzing data from three separate log files. A total of 11,726 attacks were recorded, with a significant focus on the Cowrie and Heralding honeypots. Attackers primarily targeted SSH (port 22) and VNC (port 5900) services. The most prominent attack vector involved attempts to install SSH keys for unauthorized access. Two CVEs, CVE-2024-3721 and CVE-2022-27255, were observed in the attack patterns.

**Detailed Analysis**

***Attacks by Honeypot***

*   Cowrie: 5314
*   Heralding: 1995
*   Suricata: 1576
*   Honeytrap: 1367
*   Ciscoasa: 1172
*   Sentrypeer: 184
*   Dionaea: 46
*   ConPot: 22
*   H0neytr4p: 12
*   Tanner: 12
*   Mailoney: 10
*   Ipphoney: 7
*   Adbhoney: 3
*   Redishoneypot: 3
*   ssh-rsa: 2
*   Honeyaml: 1

***Top Attacking IPs***

*   196.251.69.191
*   196.251.69.192
*   10.17.0.5
*   159.75.149.54
*   194.50.16.73
*   176.9.111.156
*   72.146.232.13
*   152.32.203.205
*   159.253.36.117
*   31.193.137.183

***Top Targeted Ports/Protocols***

*   vnc/5900
*   22
*   5060
*   8333
*   5904
*   5905
*   TCP/22
*   8088
*   5901
*   5903

***Most Common CVEs***

*   CVE-2024-3721
*   CVE-2022-27255

***Commands Attempted by Attackers***

*   `cd ~; chattr -ia .ssh; lockr -ia .ssh`
*   `lockr -ia .ssh`
*   `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAA... mdrfckr">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~`
*   `cat /proc/cpuinfo | grep name | wc -l`
*   `cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'`
*   `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`
*   `ls -lh $(which ls)`
*   `which ls`
*   `crontab -l`
*   `w`

***Signatures Triggered***

*   ET INFO VNC Authentication Failure
*   2002920
*   ET DROP Dshield Block Listed Source group 1
*   2402000
*   ET SCAN NMAP -sS window 1024
*   2009582
*   ET SCAN Potential SSH Scan
*   2001219
*   ET INFO Reserved Internal IP Traffic
*   2002752

***Users / Login Attempts***

*   345gs5662d34/345gs5662d34
*   root/3301176
*   root/Fz123456
*   ivan/ivan123
*   centos/default
*   dados/123
*   admin/9999999
*   centos/159753
*   test/test2010
*   root/Zc123456

***Files Uploaded/Downloaded***

*   wget.sh;
*   w.sh;
*   c.sh;

***HTTP User-Agents***

*   No user agents were recorded in this period.

***SSH Clients***

*   No SSH clients were recorded in this period.

***SSH Servers***

*   No SSH servers were recorded in this period.

***Top Attacker AS Organizations***

*   No attacker AS organizations were recorded in this period.

**Key Observations and Anomalies**

*   A high volume of attacks originated from the `196.251.69.0/24` subnet, specifically targeting VNC services.
*   The overwhelming majority of commands are reconnaissance and attempts to install a malicious SSH key, indicating a coordinated campaign.
*   The presence of CVE-2022-27255, a Realtek eCos RSDK/MSDK vulnerability, suggests that attackers are targeting IoT devices.
*   The lack of HTTP user agents, SSH clients/servers, and AS organization data might indicate that the attacks are coming from compromised devices or that the honeypots did not capture this information.