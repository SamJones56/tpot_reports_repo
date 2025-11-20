Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-07T23:01:44Z
**Timeframe of Analysis:** 2025-10-07T22:20:01Z to 2025-10-07T23:00:01Z
**Files Used for Report Generation:**
- `agg_log_20251007T222001Z.json`
- `agg_log_20251007T224001Z.json`
- `agg_log_20251007T230001Z.json`

**Executive Summary**

This report summarizes 15,743 attacks recorded by honeypots over a period of approximately 40 minutes. The majority of attacks were captured by the Cowrie honeypot. The most targeted service was SSH on port 22, followed by SMTP on port 25. A significant number of attacks originated from the IP address 86.54.42.238. Attackers attempted a variety of commands, primarily focused on reconnaissance and establishing persistent access. Several CVEs were targeted, with CVE-2002-0013 and CVE-2002-0012 being the most frequent.

**Detailed Analysis**

*   **Attacks by Honeypot:**
    *   Cowrie: 6,379
    *   Honeytrap: 2,856
    *   Mailoney: 1,788
    *   Suricata: 1,787
    *   Ciscoasa: 1,634
    *   Sentrypeer: 582
    *   Tanner: 490
    *   Dionaea: 65
    *   Redishoneypot: 53
    *   ConPot: 36
    *   H0neytr4p: 23
    *   Adbhoney: 22
    *   Honeyaml: 13
    *   ElasticPot: 9
    *   Ipphoney: 3
    *   Dicompot: 3

*   **Top Attacking IPs:**
    *   86.54.42.238
    *   45.207.223.64
    *   185.255.126.223
    *   116.193.191.159
    *   160.22.123.78
    *   103.2.225.33
    *   94.232.170.210
    *   94.72.115.49
    *   186.4.131.49
    *   34.57.181.41
    *   74.225.11.113
    *   165.232.46.14
    *   115.190.109.103
    *   81.192.46.45
    *   103.25.47.94
    *   103.28.57.98
    *   124.156.238.210
    *   41.223.30.169
    *   78.109.200.147
    *   43.153.68.18

*   **Top Targeted Ports/Protocols:**
    *   25
    *   22
    *   5060
    *   80
    *   TCP/80
    *   8333
    *   5903
    *   6379
    *   1025
    *   3388
    *   8888
    *   5907
    *   5908
    *   5909
    *   23
    *   1234
    *   TCP/3388

*   **Most Common CVEs:**
    *   CVE-2002-0013
    *   CVE-2002-0012
    *   CVE-1999-0517
    *   CVE-2019-11500
    *   CVE-2021-3449
    *   CVE-2005-4050
    *   CVE-2006-2369

*   **Commands Attempted by Attackers:**
    *   `cd ~; chattr -ia .ssh; lockr -ia .ssh`
    *   `lockr -ia .ssh`
    *   `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ...">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~`
    *   `cat /proc/cpuinfo | grep name | wc -l`
    *   `Enter new UNIX password:`
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

*   **Signatures Triggered:**
    *   ET INFO Login Credentials Possibly Passed in POST Data
    *   ET DROP Dshield Block Listed Source group 1
    *   ET SCAN NMAP -sS window 1024
    *   ET SCAN MS Terminal Server Traffic on Non-standard Port
    *   ET INFO Reserved Internal IP Traffic
    *   ET CINS Active Threat Intelligence Poor Reputation IP group 44
    *   ET CINS Active Threat Intelligence Poor Reputation IP group 45
    *   ET CINS Active Threat Intelligence Poor Reputation IP group 48
    *   ET ATTACK_RESPONSE Possible MS CMD Shell opened on local system
    *   ET CINS Active Threat Intelligence Poor Reputation IP group 49

*   **Users / Login Attempts:**
    *   345gs5662d34/345gs5662d34
    *   sysadmin/sysadmin@1
    *   config/config9
    *   guest/guest77
    *   operator/operator33
    *   deploy/deploydeploy
    *   root/1qaz2wsx
    *   support/1961
    *   default/123qwe
    *   admin/admin1234
    *   debian/12345
    *   root/computer
    *   teamspeak/teamspeak@123
    *   odoo/123odoo
    *   operator/654321
    *   pivpn/pivpn!

*   **Files Uploaded/Downloaded:**
    *   ?utm_source=bitnami&amp;utm_medium=virtualmachine&amp;utm_campaign=Virtual%2BMachine
    *   xhtml1-transitional.dtd
    *   xhtml
    *   fbml
    *   tomcat?utm_source=bitnami&amp;utm_medium=virtualmachine&amp;utm_campaign=Virtual%2BMachine
    *   community.bitnami.com?utm_source=bitnami&amp;utm_medium=virtualmachine&amp;utm_campaign=Virtual%2BMachine
    *   wget.sh;
    *   w.sh;
    *   c.sh;
    *   Mozi.a+varcron

*   **HTTP User-Agents:**
    *   No HTTP User-Agents were recorded in the logs.

*   **SSH Clients:**
    *   No specific SSH clients were recorded in the logs.

*   **SSH Servers:**
    *   No specific SSH servers were recorded in the logs.

*   **Top Attacker AS Organizations:**
    *   No attacker AS organizations were recorded in the logs.

**Key Observations and Anomalies**

*   The high number of attacks from a single IP (86.54.42.238) suggests a targeted or persistent attacker.
*   The commands attempted indicate a focus on establishing a foothold on the compromised system, likely for use in a botnet. The repeated attempts to modify SSH authorized_keys files are a strong indicator of this.
*   The presence of Mozi botnet-related file downloads confirms the botnet hypothesis.
*   The targeting of older CVEs alongside newer ones suggests that attackers are using a broad set of exploits to maximize their chances of success against a wide range of systems.
*   The lack of diverse HTTP User-Agents, SSH clients, or server information might indicate that the attacks are highly automated and originate from a limited set of tools.
