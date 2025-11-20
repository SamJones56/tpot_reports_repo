Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-28T05:01:41Z
**Timeframe:** 2025-10-28T04:20:02Z to 2025-10-28T05:00:01Z
**Files Used:**
- agg_log_20251028T042002Z.json
- agg_log_20251028T044001Z.json
- agg_log_20251028T050001Z.json

**Executive Summary**

This report summarizes honeypot activity over a period of approximately 40 minutes, based on data from three log files. A total of 19,996 events were recorded. The most active honeypots were Cowrie, Suricata, and Honeytrap. The majority of attacks originated from a diverse set of IP addresses, with significant activity from IPs located in China and the United States. The most targeted ports were TCP/445 and 5060, commonly associated with SMB and SIP services respectively. Several CVEs were detected, with a focus on older vulnerabilities. Attackers attempted a variety of commands, primarily focused on reconnaissance and establishing persistent access.

**Detailed Analysis**

***Attacks by Honeypot***

- Cowrie: 5779
- Suricata: 4946
- Honeytrap: 3298
- Sentrypeer: 2052
- Ciscoasa: 2043
- Dionaea: 1586
- Mailoney: 116
- Adbhoney: 78
- H0neytr4p: 29
- Tanner: 22
- Miniprint: 13
- ConPot: 11
- Honeyaml: 10
- Redishoneypot: 6
- ElasticPot: 6
- Ipphoney: 1

***Top Attacking IPs***

- 58.64.14.146: 1461
- 36.75.157.153: 1444
- 85.116.125.143: 1026
- 144.172.108.231: 1125
- 36.65.103.166: 404
- 185.243.5.121: 508
- 205.185.125.150: 327
- 51.158.146.158: 268
- 202.125.94.71: 266
- 185.225.22.80: 198
- 81.192.46.49: 193
- 103.139.193.223: 189
- 14.225.3.79: 292
- 194.107.115.2: 258
- 8.243.50.114: 253
- 163.172.99.31: 327
- 88.210.63.16: 228
- 103.161.207.2: 189
- 167.250.224.25: 96
- 77.83.207.203: 95

***Top Targeted Ports/Protocols***

- TCP/445: 2898
- 5060: 2052
- 445: 1526
- 22: 660
- 1110: 273
- 5901: 230
- 8333: 123
- UDP/5060: 145
- 5903: 131
- 25: 116
- TCP/22: 96
- 23: 87
- 5902: 41
- 1167: 117
- 2095: 39
- TCP/1110: 17
- 9100: 13
- TCP/80: 12
- TCP/46654: 12
- TCP/2087: 9

***Most Common CVEs***

- CVE-2002-0013 CVE-2002-0012
- CVE-2005-4050
- CVE-2019-11500 CVE-2019-11500
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517
- CVE-2021-3449 CVE-2021-3449
- CVE-2021-35394 CVE-2021-35394
- CVE-2006-2369

***Commands Attempted by Attackers***

- cd ~; chattr -ia .ssh; lockr -ia .ssh
- lockr -ia .ssh
- cd ~ && rm -rf .ssh && mkdir .ssh && echo ...
- cat /proc/cpuinfo | grep name | wc -l
- Enter new UNIX password:
- Enter new UNIX password:
- cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
- ls -lh $(which ls)
- which ls
- crontab -l
- w
- uname -m
- cat /proc/cpuinfo | grep model | grep name | wc -l
- top
- uname
- uname -a
- whoami
- lscpu | grep Model
- df -h | head -n 2 | awk 'FNR == 2 {print $2;}'

***Signatures Triggered***

- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication
- 2024766
- ET DROP Dshield Block Listed Source group 1
- 2402000
- ET SCAN MS Terminal Server Traffic on Non-standard Port
- 2023753
- ET SCAN NMAP -sS window 1024
- 2009582
- ET HUNTING RDP Authentication Bypass Attempt
- 2034857
- ET INFO Reserved Internal IP Traffic
- 2002752
- ET CINS Active Threat Intelligence Poor Reputation IP group 44
- 2403343
- ET CINS Active Threat Intelligence Poor Reputation IP group 47
- 2403346
- ET Cins Active Threat Intelligence Poor Reputation IP group 45
- 2403344
- ET CINS Active Threat Intelligence Poor Reputation IP group 48
- 2403347

***Users / Login Attempts***

- 345gs5662d34/345gs5662d34
- sa/!@#123qwe
- root/K1ngst0N
- root/K3yb0
- root/k4mbing88
- root/k4mbingit4m
- root/K4rlb0hm
- api/123123
- gameserver/password123
- manish/123
- indra/P@ssw0rd
- user/www.pkidc.cn
- user/www.21cn.com
- user/wwQxam1z9VQ1ch7
- user/wuyanxin
- padmin/P@ssw0rd
- padmin/3245gs5662d34
- jira/Password123
- traefik/traefik123!
- nemati/nemati

***Files Uploaded/Downloaded***

- wget.sh;
- arm.uhavenobotsxd;
- arm.uhavenobotsxd
- arm5.uhavenobotsxd;
- arm5.uhavenobotsxd
- arm6.uhavenobotsxd;
- arm6.uhavenobotsxd
- arm7.uhavenobotsxd;
- arm7.uhavenobotsxd
- x86_32.uhavenobotsxd;
- x86_32.uhavenobotsxd
- mips.uhavenobotsxd;
- mips.uhavenobotsxd
- mipsel.uhavenobotsxd;
- mipsel.uhavenobotsxd
- w.sh;
- c.sh;
- loader.sh|sh;#

***HTTP User-Agents***

- No HTTP User-Agents were logged in this timeframe.

***SSH Clients and Servers***

- No SSH clients or servers were logged in this timeframe.

***Top Attacker AS Organizations***

- No attacker AS organizations were logged in this timeframe.

**Key Observations and Anomalies**

- A high number of events were recorded in a short timeframe, indicating a high level of automated scanning and exploitation attempts.
- The most common commands are related to establishing a foothold on the system, such as modifying SSH authorized_keys and gathering system information.
- The presence of commands related to downloading and executing scripts (e.g., wget.sh, w.sh, c.sh) suggests that attackers are attempting to deploy malware on compromised systems.
- The triggered signatures indicate a mix of scanning activity, exploitation attempts (DoublePulsar), and connections from known malicious IPs.
- A significant number of login attempts with weak or default credentials were observed.
- The lack of HTTP User-Agents, SSH clients/servers, and AS organization data might indicate that the attacks are primarily focused on lower-level protocols or that the honeypots did not capture this information.
