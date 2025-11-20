Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-25T08:01:35Z
**Timeframe:** 2025-10-25T07:20:01Z to 2025-10-25T08:00:01Z
**Files Used:**
- agg_log_20251025T072001Z.json
- agg_log_20251025T074001Z.json
- agg_log_20251025T080001Z.json

**Executive Summary**

This report summarizes 21,070 attacks recorded by honeypots over a 40-minute period. The most active honeypot was Cowrie, with 6,042 events. A significant portion of the attacks targeted SMB (port 445) and SSH (port 22). The top attacking IP address was 203.210.157.144, responsible for 2,336 attacks. Several CVEs were exploited, with CVE-2021-44228 (Log4Shell) being the most frequent. Attackers attempted various commands, including reconnaissance and attempts to install malware.

**Detailed Analysis**

***Attacks by Honeypot***

*   Cowrie: 6,042
*   Suricata: 4,957
*   Honeytrap: 4,083
*   Dionaea: 3,726
*   Ciscoasa: 1,756
*   Sentrypeer: 204
*   Mailoney: 160
*   ConPot: 39
*   Adbhoney: 30
*   Tanner: 24
*   H0neytr4p: 16
*   Redishoneypot: 9
*   Honeyaml: 8
*   Dicompot: 7
*   ElasticPot: 6
*   Heralding: 3

***Top Attacking IPs***

*   203.210.157.144: 2,336
*   156.198.249.65: 1,648
*   80.94.95.238: 1,384
*   143.198.201.181: 1,252
*   114.47.12.143: 1,018
*   165.227.174.138: 696
*   46.32.178.190: 655
*   188.166.24.228: 530
*   119.159.254.226: 399
*   104.28.237.51: 375

***Top Targeted Ports/Protocols***

*   445: 3,471
*   TCP/445: 2,341
*   22: 1,031
*   5060: 204
*   3306: 203
*   25: 160
*   5903: 129
*   8333: 119
*   5901: 112
*   TCP/22: 80

***Most Common CVEs***

*   CVE-2021-44228: 5
*   CVE-2002-0013 CVE-2002-0012: 4
*   CVE-2022-27255: 3
*   CVE-2005-4050: 2
*   CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 1
*   CVE-2021-35394: 1
*   CVE-2019-11500: 1
*   CVE-2006-2369: 1

***Commands Attempted by Attackers***

*   `cd ~; chattr -ia .ssh; lockr -ia .ssh`
*   `lockr -ia .ssh`
*   `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..." >> .ssh/authorized_keys`
*   `cat /proc/cpuinfo | grep name | wc -l`
*   `uname -a`
*   `whoami`
*   `./N0OLATZD`
*   `scp -t /tmp/N0OLATZD`
*   `rm -rf /data/local/tmp; mkdir -p /data/local/tmp; ...`

***Signatures Triggered***

*   ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication: 2,334
*   ET SCAN MS Terminal Server Traffic on Non-standard Port: 930
*   ET DROP Dshield Block Listed Source group 1: 507
*   ET SCAN NMAP -sS window 1024: 182
*   ET HUNTING RDP Authentication Bypass Attempt: 138
*   ET INFO Reserved Internal IP Traffic: 58
*   ET SCAN Suspicious inbound to Oracle SQL port 1521: 15
*   GPL INFO SOCKS Proxy attempt: 15
*   ET SCAN Suspicious inbound to PostgreSQL port 5432: 15
*   ET COMPROMISED Known Compromised or Hostile Host Traffic group 10: 27

***Users / Login Attempts***

*   345gs5662d34/345gs5662d34: 14
*   root/elx015: 4
*   pi/raspberry: 4
*   root/emazhul1: 4
*   root/EMGAdmin: 4
*   root/Emily: 4
*   root/elzorromuerdemordiendo: 3
*   admin/18041982: 3
*   admin/1804: 3
*   admin/180180: 3

***Files Uploaded/Downloaded***

*   wget.sh;: 8
*   w.sh;: 2
*   c.sh;: 2
*   loader.sh|sh;#: 1
*   perl|perl: 1

***HTTP User-Agents***

*   None observed.

***SSH Clients***

*   None observed.

***SSH Servers***

*   None observed.

***Top Attacker AS Organizations***

*   None observed.

**Key Observations and Anomalies**

*   A high volume of attacks targeting SMB (port 445) suggests widespread scanning for vulnerabilities like EternalBlue. The high number of DoublePulsar backdoor signatures supports this.
*   The commands attempted by attackers indicate a focus on compromising SSH servers and adding their own authorized keys for persistent access.
*   The variety of CVEs exploited, including older ones, highlights that attackers are still finding unpatched systems.
*   The presence of commands related to downloading and executing shell scripts indicates attempts to install malware or establish a botnet presence.
*   No HTTP user-agents, SSH clients, servers, or AS organizations were recorded in this period, which may be an anomaly or a limitation of the current honeypot configuration.
