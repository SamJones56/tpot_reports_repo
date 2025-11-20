Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-07T17:01:33Z
**Timeframe:** 2025-10-07T16:20:01Z to 2025-10-07T17:00:01Z
**Files Used:** `agg_log_20251007T162001Z.json`, `agg_log_20251007T164001Z.json`, `agg_log_20251007T170001Z.json`

**Executive Summary:**
This report summarizes 11,229 attacks recorded by the honeypot network. The majority of attacks were SSH brute-force attempts, with a significant number of scans and other automated attacks. The most active attacker IP was 209.38.88.14. The most targeted port was 22 (SSH). Several CVEs were exploited, with CVE-2021-44228 (Log4j) being the most common.

**Detailed Analysis:**

**Attacks by Honeypot:**
*   Cowrie: 6558
*   Honeytrap: 1988
*   Suricata: 1414
*   Sentrypeer: 621
*   Mailoney: 455
*   Redishoneypot: 52
*   Adbhoney: 27
*   Tanner: 31
*   Dionaea: 19
*   H0neytr4p: 24
*   ConPot: 16
*   Ipphoney: 4
*   ElasticPot: 3
*   Dicompot: 5
*   Miniprint: 9
*   Heralding: 3

**Top Attacking IPs:**
*   209.38.88.14: 1383
*   50.6.225.98: 1246
*   4.144.169.44: 693
*   185.255.126.223: 568
*   45.140.17.52: 418
*   86.54.42.238: 395
*   83.235.16.111: 333
*   103.119.92.117: 281
*   64.225.55.168: 258
*   201.186.40.250: 194
*   194.107.115.11: 219
*   103.148.195.173: 179
*   106.58.220.179: 199
*   186.103.169.12: 199
*   190.129.114.222: 159
*   124.221.16.51: 129
*   212.57.118.142: 105
*   68.183.207.213: 94
*   107.170.36.5: 97
*   35.244.25.124: 70

**Top Targeted Ports/Protocols:**
*   22: 1094
*   5060: 621
*   25: 455
*   8333: 184
*   TCP/22: 91
*   5903: 95
*   4433: 48
*   6379: 43
*   5909: 49
*   5908: 48
*   5907: 48
*   TCP/1433: 22
*   23: 35
*   80: 28
*   TCP/80: 18
*   9001: 24
*   TCP/5432: 16
*   9093: 57
*   9500: 18
*   8728: 12

**Most Common CVEs:**
*   CVE-2021-44228 CVE-2021-44228
*   CVE-2021-3449 CVE-2021-3449
*   CVE-2002-0013 CVE-2002-0012
*   CVE-2019-11500 CVE-2019-11500
*   CVE-2005-4050
*   CVE-2002-0013 CVE-2002-0012 CVE-1999-0517

**Commands Attempted by Attackers:**
*   cd ~; chattr -ia .ssh; lockr -ia .ssh
*   lockr -ia .ssh
*   cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~
*   cat /proc/cpuinfo | grep name | wc -l
*   Enter new UNIX password: 
*   Enter new UNIX password:
*   cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
*   free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
*   ls -lh $(which ls)
*   which ls
*   crontab -l
*   w
*   uname -m
*   cat /proc/cpuinfo | grep model | grep name | wc -l
*   top
*   uname
*   uname -a
*   whoami
*   lscpu | grep Model
*   df -h | head -n 2 | awk 'FNR == 2 {print $2;}'

**Signatures Triggered:**
*   ET SCAN MS Terminal Server Traffic on Non-standard Port
*   2023753
*   ET DROP Dshield Block Listed Source group 1
*   2402000
*   ET SCAN NMAP -sS window 1024
*   2009582
*   ET SCAN Potential SSH Scan
*   2001219
*   ET INFO Reserved Internal IP Traffic
*   2002752
*   ET CINS Active Threat Intelligence Poor Reputation IP group 68
*   2403367
*   ET DROP Spamhaus DROP Listed Traffic Inbound group 28
*   2400027
*   ET CINS Active Threat Intelligence Poor Reputation IP group 2
*   2403301
*   ET CINS Active Threat Intelligence Poor Reputation IP group 48
*   2403347
*   ET INFO CURL User Agent
*   2002824
*   ET SCAN Suspicious inbound to MSSQL port 1433
*   2010935
*   ET EXPLOIT Apache Obfuscated log4j RCE Attempt (tcp ldap) (CVE-2021-44228)
*   2034755
*   ET SCAN Suspicious inbound to PostgreSQL port 5432
*   2010939
*   ET CINS Active Threat Intelligence Poor Reputation IP group 12
*   2403311
*   ET DROP Spamhaus DROP Listed Traffic Inbound group 41
*   2400040
*   ET DROP Spamhaus DROP Listed Traffic Inbound group 32
*   2400031
*   ET CINS Active Threat Intelligence Poor Reputation IP group 66
*   2403365

**Users / Login Attempts:**
*   345gs5662d34/345gs5662d34
*   sysadmin/sysadmin@1
*   ubuntu/3245gs5662d34
*   developer/developer
*   ubuntu/Changeme!
*   user01/user01123
*   ranger/ranger123
*   esuser/123
*   ubuntu/letmein!
*   root/Password1
*   root/root123
*   elasticsearch/elasticsearch
*   sshuser/sshuser12345
*   ansible/ansible!
*   ftp/ftp123
*   gitlab/gitlab
*   guest/guest
*   app/app123
*   gpadmin/gpadmin
*   admin/admin123
*   root/123456789
*   esadmin/esadmin
*   es/es123
*   ftp/ftp
*   awsgui/awsgui
*   soporte/Password123
*   ubuntu/1122
*   ubuntu/Qwer1234!@#$
*   ubuntu/12345
*   ubuntu/123
*   ubuntu/Aa111111
*   ubuntu/P@ssw0rd@1
*   dolphinscheduler/dolphinscheduler123
*   pi/pi
*   dev/dev
*   elasticsearch/elasticsearch@123
*   oceanbase/oceanbase
*   ubuntu/Letmein.123
*   postgres/postgres
*   postgres/123
*   ubuntu/qwe123..
*   tomcat/tomcat123
*   tom/tom
*   ubuntu/hello
*   ubuntu/ubuntu.123
*   ubuntu/123qwe123
*   testuser/testuser
*   ubuntu/ubuntu*123
*   lighthouse/lighthouse123
*   ubuntu/Letmein1qaz
*   ubuntu/1111
*   oscar/oscar
*   ubuntu/000000
*   ubuntu/ucloud.cn

**Files Uploaded/Downloaded:**
*   wget.sh;
*   mips
*   w.sh;
*   c.sh;
*   parm;
*   parm5;
*   parm6;
*   parm7;
*   psh4;
*   parc;
*   pmips;
*   pmipsel;
*   psparc;
*   px86_64;
*   pi686;
*   pi586;

**HTTP User-Agents:**
*   (No data)

**SSH Clients and Servers:**
*   (No data)

**Top Attacker AS Organizations:**
*   (No data)

**Key Observations and Anomalies:**
*   The vast majority of commands are reconnaissance commands to understand the system architecture.
*   The repeated use of `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."` indicates a clear intent to establish persistent access.
*   The file downloads are mostly shell scripts, likely for automated attacks and malware installation.
*   The triggered Suricata signatures show a mix of scanning activity (NMAP), and traffic from known malicious IPs (Dshield, Spamhaus).
*   The presence of Log4j exploit attempts (CVE-2021-44228) is a noteworthy and ongoing threat.
