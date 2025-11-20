Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-24T01:01:25Z
**Timeframe:** 2025-10-24T00:20:01Z to 2025-10-24T01:00:01Z
**Log Files:** agg_log_20251024T002001Z.json, agg_log_20251024T004001Z.json, agg_log_20251024T010001Z.json

**Executive Summary**

This report summarizes 12,438 attacks recorded by T-Pot honeypots over a 40-minute period. The primary attack vectors were SMB (445/TCP) and SIP (5060/UDP). The most active honeypots were Dionaea, Cowrie, and Ciscoasa. A significant portion of the attacks originated from IP addresses 45.171.150.123 and 114.35.170.253.

**Detailed Analysis**

***Attacks by Honeypot***

*   Dionaea: 4,187
*   Cowrie: 2,156
*   Ciscoasa: 1,858
*   Honeytrap: 1,532
*   Sentrypeer: 1,377
*   Suricata: 1,146
*   Tanner: 114
*   Mailoney: 31
*   H0neytr4p: 23
*   ElasticPot: 4
*   Honeyaml: 4
*   ConPot: 3
*   Heralding: 3

***Top Attacking IPs***

*   45.171.150.123
*   114.35.170.253
*   216.9.225.39
*   80.94.95.238
*   185.242.226.74
*   5.78.83.32
*   103.67.78.102
*   41.204.63.118
*   103.118.114.22
*   107.170.36.5

***Top Targeted Ports/Protocols***

*   445
*   5060
*   22
*   TCP/1080
*   8333
*   80
*   5905
*   5904
*   5901
*   5902

***Most Common CVEs***

*   CVE-2002-0013
*   CVE-2002-0012
*   CVE-1999-0517
*   CVE-2002-1149

***Commands Attempted by Attackers***

*   cd ~; chattr -ia .ssh; lockr -ia .ssh
*   lockr -ia .ssh
*   cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ...">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~
*   cat /proc/cpuinfo | grep name | wc -l
*   echo "root:ZoSSsgWRp34S"|chpasswd|bash
*   rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts.deny; pkill -9 sleep;
*   free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
*   uname -a
*   whoami
*   system
*   shell

***Signatures Triggered***

*   ET SCAN MS Terminal Server Traffic on Non-standard Port
*   ET DROP Dshield Block Listed Source group 1
*   ET SCAN NMAP -sS window 1024
*   GPL INFO SOCKS Proxy attempt
*   ET INFO Reserved Internal IP Traffic
*   ET WEB_SERVER WEB-PHP phpinfo access
*   ET SCAN Unusually Fast 404 Error Messages (Page Not Found), Possible Web Application Scan/Directory Guessing Attack
*   ET DROP Spamhaus DROP Listed Traffic Inbound group 14

***Users / Login Attempts***

*   root/vps1234
*   umer/umer
*   root/d1
*   seshu/seshu
*   fiscal/fiscal
*   345gs5662d34/345gs5662d34
*   root/aa12345678!
*   root/Titwoac99
*   sysuser/sysuser
*   aac/aac

***Files Uploaded/Downloaded***

*   None observed in the provided logs.

***HTTP User-Agents***

*   None observed in the provided logs.

***SSH Clients and Servers***

*   None observed in the provided logs.

***Top Attacker AS Organizations***

*   None observed in the provided logs.

**Key Observations and Anomalies**

*   The high number of attacks on port 445 (SMB) suggests widespread scanning for vulnerabilities like EternalBlue.
*   The significant activity on port 5060 indicates a focus on exploiting VoIP systems.
*   The commands executed by attackers are consistent with attempts to establish persistent access and gather system information.
*   The presence of commands to modify SSH authorized_keys files highlights the risk of attackers gaining persistent, passwordless access to compromised systems.
*   The variety of usernames and passwords attempted in brute-force attacks underscores the importance of strong, unique credentials for all services.
