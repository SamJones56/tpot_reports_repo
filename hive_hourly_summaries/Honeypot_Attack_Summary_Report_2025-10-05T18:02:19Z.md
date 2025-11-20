# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-05T18:01:15Z
**Timeframe:** 2025-10-05T17:20:02Z to 2025-10-05T18:00:01Z
**Files Used:** agg_log_20251005T172002Z.json, agg_log_20251005T174001Z.json, agg_log_20251005T180001Z.json

## Executive Summary

This report summarizes 10,126 attacks recorded by our honeypot network. The majority of these attacks were captured by the Cowrie honeypot, indicating a high volume of SSH and Telnet-based threats. A significant number of attacks originated from IP address 176.65.141.117, primarily targeting port 25 (SMTP). The most frequently attempted commands involved creating and modifying SSH authorized_keys files, suggesting attempts to establish persistent access. Several CVEs were detected, with CVE-2005-4050 being the most common.

## Detailed Analysis

### Attacks by Honeypot

*   Cowrie: 5047
*   Suricata: 1509
*   Ciscoasa: 1279
*   Mailoney: 843
*   Honeytrap: 685
*   Sentrypeer: 453
*   Dionaea: 82
*   Adbhoney: 58
*   Tanner: 46
*   H0neytr4p: 32
*   ElasticPot: 26
*   Miniprint: 21
*   ConPot: 21
*   Dicompot: 9
*   Redishoneypot: 9
*   Honeyaml: 6

### Top Attacking IPs

*   176.65.141.117: 820
*   172.86.95.98: 396
*   212.33.235.243: 268
*   182.18.161.165: 248
*   118.194.230.211: 273
*   31.58.171.28: 227
*   129.212.184.138: 199
*   123.59.50.202: 172
*   178.62.19.223: 184
*   89.216.47.154: 179
*   34.96.180.174: 215
*   190.108.60.101: 219
*   103.183.75.135: 136
*   202.139.196.22: 155
*   152.32.172.146: 160
*   190.12.102.58: 135
*   27.150.188.148: 149
*   205.185.127.60: 107
*   223.247.218.112: 109
*   155.4.244.179: 98

### Top Targeted Ports/Protocols

*   25: 842
*   22: 785
*   5060: 453
*   TCP/5900: 243
*   TCP/80: 77
*   27017: 56
*   TCP/22: 30
*   80: 47
*   443: 32
*   1911: 42
*   TCP/5432: 21
*   9200: 26
*   23: 23
*   TCP/1433: 11
*   9100: 21
*   UDP/5060: 19
*   TCP/1080: 9
*   2404: 17
*   8001: 7
*   11300: 6
*   5666: 5
*   5555: 4
*   8888: 4
*   9000: 10
*   1433: 7
*   1445: 7
*   81: 6
*   TCP/8080: 6
*   1443: 6
*   4444: 6
*   TCP/3000: 6
*   8728: 13
*   9999: 7
*   6379: 6
*   TCP/5555: 6
*   TCP/13388: 6
*   TCP/27017: 5
*   TCP/465: 5

### Most Common CVEs

*   CVE-2005-4050: 19
*   CVE-2002-0013 CVE-2002-0012: 3
*   CVE-2021-3449 CVE-2021-3449: 2
*   CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 1
*   CVE-2019-16920 CVE-2019-16920: 1
*   CVE-2024-12856 CVE-2024-12856 CVE-2024-12885: 1
*   CVE-2014-6271: 1
*   CVE-2023-52163 CVE-2023-52163: 1
*   CVE-2023-47565 CVE-2023-47565: 1
*   CVE-2023-31983 CVE-2023-31983: 1
*   CVE-2024-10914 CVE-2024-10914: 1
*   CVE-2009-2765: 1
*   CVE-2015-2051 CVE-2024-33112 CVE-2022-37056 CVE-2019-10891 CVE-2015-2051: 1
*   CVE-2024-3721 CVE-2024-3721: 1
*   CVE-2006-3602 CVE-2006-4458 CVE-2006-4542: 1
*   CVE-2021-42013 CVE-2021-42013: 1

### Commands Attempted by Attackers

*   cd ~; chattr -ia .ssh; lockr -ia .ssh: 27
*   lockr -ia .ssh: 27
*   cd ~ && rm -rf .ssh && mkdir .ssh && echo \"ssh-rsa ... mdrfckr\">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~: 27
*   cat /proc/cpuinfo | grep name | wc -l: 20
*   cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}': 21
*   free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}': 21
*   ls -lh $(which ls): 21
*   which ls: 21
*   crontab -l: 21
*   w: 21
*   uname -m: 21
*   cat /proc/cpuinfo | grep model | grep name | wc -l: 21
*   top: 21
*   uname: 21
*   uname -a: 21
*   whoami: 21
*   lscpu | grep Model: 21
*   df -h | head -n 2 | awk 'FNR == 2 {print $2;}': 21
*   Enter new UNIX password: : 14
*   Enter new UNIX password:: 14

### Signatures Triggered

*   ET DROP Dshield Block Listed Source group 1: 295
*   2402000: 295
*   ET DROP Spamhaus DROP Listed Traffic Inbound group 41: 259
*   2400040: 259
*   ET SCAN NMAP -sS window 1024: 153
*   2009582: 153
*   ET INFO Reserved Internal IP Traffic: 57
*   2002752: 57
*   ET SCAN MS Terminal Server Traffic on Non-standard Port: 27
*   2023753: 27
*   ET CINS Active Threat Intelligence Poor Reputation IP group 46: 30
*   2403345: 30
*   ET CINS Active Threat Intelligence Poor Reputation IP group 44: 19
*   2403343: 19
*   ET CINS Active Threat Intelligence Poor Reputation IP group 48: 17
*   2403347: 17
*   ET CINS Active Threat Intelligence Poor Reputation IP group 47: 21
*   2403346: 21
*   ET CINS Active Threat Intelligence Poor Reputation IP group 49: 23
*   2403348: 23
*   ET INFO curl User-Agent Outbound: 12
*   2013028: 12
*   ET HUNTING curl User-Agent to Dotted Quad: 12
*   2034567: 12
*   ET CINS Active Threat Intelligence Poor Reputation IP group 43: 10
*   2403342: 10
*   ET CINS Active Threat Intelligence Poor Reputation IP group 50: 10
*   2403349: 10
*   ET VOIP MultiTech SIP UDP Overflow: 19
*   2003237: 19

### Users / Login Attempts

*   345gs5662d34/345gs5662d34: 24
*   root/nPSpP4PBW0: 18
*   root/LeitboGi0ro: 12
*   root/2glehe5t24th1issZs: 11
*   novinhost/novinhost.org: 8
*   test/zhbjETuyMffoL8F: 6
*   root/3245gs5662d34: 7
*   sa/: 5
*   deploy/deploy: 2
*   novinhost/3245gs5662d34: 2
*   thomas/thomas123: 2
*   root/Welcome@123: 2
*   pymes/pymes: 2
*   Airtel@123/otx: 2
*   anonymous/: 2
*   root/09N1RCa1Hs31: 2
*   wildfly/wildfly: 2
*   root/7758521: 2
*   user/JSLTrzx@2022: 2
*   user/JSLTrzx@2021: 2
*   user/JSDX@iptv123: 2
*   user/JQ5wlH123: 2
*   user/JLPwin2017%: 2
*   root/Wr123456: 2
*   root/He123456789: 2
*   root/Raju@123: 2
*   root/Aa112211.: 2
*   root/adminHW: 2
*   appuser/appuser@123: 2
*   mel/mel: 2
*   root/takashi: 2
*   debianuser/debian10svm: 2
*   root/Password123456: 2
*   root/huigu309: 2
*   root/5nWt3P-fF4WosQm5O: 2
*   liferay/liferay: 2
*   root/Abcd1234: 2
*   root/aDm8H%MdA: 2
*   root/Admin123: 2
*   root/Vivek@123: 2
*   castle/castle1!: 2
*   solana/solana: 2
*   root/Ahmed123: 2

### Files Uploaded/Downloaded

*   wget.sh;: 20
*   w.sh;: 5
*   c.sh;: 5
*   104.199.212.115: 4
*   rondo.dgx.sh||busybox: 3
*   rondo.dgx.sh||curl: 3
*   rondo.dgx.sh)|sh&: 3
*   apply.cgi: 2
*   rondo.tkg.sh|sh&echo: 2
*   rondo.qre.sh||busybox: 2
*   rondo.qre.sh||curl: 2
*   rondo.qre.sh)|sh: 2
*   cfg_system_time.htm: 2
*   server.cgi?func=server02_main_submit&counter=6.7496022225883&TEST_BTN4=: 2
*   login_pic.asp: 1
*   rondo.sbx.sh|sh&echo${IFS}: 1
*   `busybox: 1

### HTTP User-Agents

*No data recorded for this period.*

### SSH Clients

*No data recorded for this period.*

### SSH Servers

*No data recorded for this period.*

### Top Attacker AS Organizations

*No data recorded for this period.*

## Key Observations and Anomalies

*   The high number of login attempts using default or common credentials (e.g., root, admin, test) highlights the continued prevalence of brute-force attacks.
*   The commands executed post-login are primarily focused on reconnaissance (e.g., `uname -a`, `lscpu`) and establishing persistence (e.g., modifying `.ssh/authorized_keys`).
*   The significant number of attacks targeting port 25 (SMTP) from a single IP address (176.65.141.117) suggests a coordinated spam or mail-based attack campaign.
*   The presence of commands attempting to download and execute shell scripts (`wget.sh`, `w.sh`, `c.sh`) indicates attempts to install malware or backdoors on the compromised systems.
