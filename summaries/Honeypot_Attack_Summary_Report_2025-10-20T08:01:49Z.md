Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-20T08:01:28Z
**Timeframe:** 2025-10-20T07:20:01Z to 2025-10-20T08:00:01Z
**Log Files:** agg_log_20251020T072001Z.json, agg_log_20251020T074001Z.json, agg_log_20251020T080001Z.json

### Executive Summary
This report summarizes 4574 attacks recorded across three log files. The majority of attacks were captured by the Cowrie and Honeytrap honeypots. The most frequent attacker IP was 72.146.232.13. Port 22 (SSH) was the most targeted port. Several CVEs were detected, with CVE-2025-30208 being the most common. Attackers attempted a variety of commands, primarily focused on reconnaissance and establishing control.

### Detailed Analysis

**Attacks by Honeypot:**
*   Cowrie: 1825
*   Honeytrap: 1598
*   Suricata: 663
*   Sentrypeer: 258
*   Adbhoney: 38
*   H0neytr4p: 42
*   ConPot: 48
*   Dionaea: 35
*   Tanner: 23
*   Mailoney: 16
*   Redishoneypot: 12
*   ElasticPot: 5
*   Heralding: 6
*   Honeyaml: 3
*   Ciscoasa: 2

**Top Attacking IPs:**
*   72.146.232.13: 620
*   204.76.203.28: 164
*   196.12.203.185: 142
*   27.254.137.144: 114
*   165.154.200.14: 117
*   49.49.237.200: 109
*   74.208.133.247: 109
*   112.196.70.142: 104
*   122.35.192.61: 104
*   185.243.5.158: 178
*   107.170.36.5: 154
*   88.214.50.58: 93
*   68.183.149.135: 112

**Top Targeted Ports/Protocols:**
*   22: 366
*   5060: 258
*   8333: 105
*   1982: 78
*   5984: 53
*   5904: 78
*   5905: 78
*   443: 36
*   1434: 34
*   80: 20
*   TCP/5173: 25
*   5555: 17

**Most Common CVEs:**
*   CVE-2025-30208: 5
*   CVE-2019-11500: 3
*   CVE-2021-3449: 3

**Commands Attempted by Attackers:**
*   `cd ~; chattr -ia .ssh; lockr -ia .ssh`
*   `lockr -ia .ssh`
*   `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."`
*   `cat /proc/cpuinfo | grep name | wc -l`
*   `Enter new UNIX password:`
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
*   `echo "root:RO6i5MXOIf7r"|chpasswd|bash`
*   `rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts.deny; pkill -9 sleep;`

**Signatures Triggered:**
*   ET DROP Dshield Block Listed Source group 1
*   ET SCAN NMAP -sS window 1024
*   ET INFO Reserved Internal IP Traffic
*   ET WEB_SERVER /etc/passwd Detected in URI
*   GPL WEB_SERVER /etc/passwd
*   ET SCAN MS Terminal Server Traffic on Non-standard Port
*   ET CINS Active Threat Intelligence Poor Reputation IP group 44
*   ET WEB_SPECIFIC_APPS Vite Arbitrary File Read Via raw parameter (CVE-2025-30208)

**Users / Login Attempts:**
*   345gs5662d34/345gs5662d34
*   del/del123
*   root/888888
*   deploy/123123
*   root/Abc123456
*   root/aa02010201Bb
*   neil/neil123
*   root/Gj123456
*   zenith/123
*   hacluster/hacluster
*   test/test1234
*   root/A55443\x08\x042211
*   local/local1
*   teste/123
*   pujie/pujie123
*   root/1qazxsw2
*   root/A5544332211
*   mukul/mukul
*   wx/wx
*   user01/Password01
*   root/aaa
*   root/fuckfuck
*   postgres/postgres
*   root/a7med

**Files Uploaded/Downloaded:**
*   arm.urbotnetisass;
*   arm.urbotnetisass
*   arm5.urbotnetisass;
*   arm5.urbotnetisass
*   arm6.urbotnetisass;
*   arm6.urbotnetisass
*   arm7.urbotnetisass;
*   arm7.urbotnetisass
*   x86_32.urbotnetisass;
*   x86_32.urbotnetisass
*   mips.urbotnetisass;
*   mips.urbotnetisass
*   mipsel.urbotnetisass;
*   mipsel.urbotnetisass

**HTTP User-Agents:**
*   *No user agents recorded in this period.*

**SSH Clients:**
*   *No SSH clients recorded in this period.*

**SSH Servers:**
*   *No SSH servers recorded in this period.*

**Top Attacker AS Organizations:**
*   *No AS organizations recorded in this period.*

### Key Observations and Anomalies
- The volume of attacks remains consistent across the reporting period.
- A notable command sequence involves downloading and executing various `urbotnetisass` payloads for different architectures (ARM, x86, MIPS), suggesting an automated campaign to infect a wide range of IoT devices.
- Another common tactic observed is the attempt to modify the `.ssh/authorized_keys` file to grant the attacker persistent access.
- The CVE-2025-30208, related to Vite Arbitrary File Read, was the most frequently observed vulnerability, indicating active exploitation in the wild.
- The majority of login attempts use common or default credentials (e.g., `root/888888`, `test/test1234`, `postgres/postgres`).

This concludes the Honeypot Attack Summary Report.
