Here is your Honeypot Attack Summary Report.

**Report Title:** Honeypot Attack Summary Report
**Report Generation Time:** 2025-10-02T18:01:48Z
**Timeframe:** 2025-10-02T17:20:01Z to 2025-10-02T18:00:01Z

**Files Used:**
- agg_log_20251002T172001Z.json
- agg_log_20251002T174001Z.json
- agg_log_20251002T180001Z.json

**Executive Summary:**
This report summarizes 10,635 attacks recorded across the honeypot network. The majority of attacks were captured by the Cowrie honeypot. The most prominent attack vector was SSH, with a significant number of brute-force login attempts and subsequent command execution. A notable amount of activity was also seen on SMTP and Cisco ASA honeypots. The most frequent attacker IP was 176.65.141.117.

**Detailed Analysis:**

***Attacks by Honeypot:***
*   **Cowrie:** 4543
*   **Ciscoasa:** 2643
*   **Mailoney:** 1676
*   **Suricata:** 1176
*   **Honeytrap:** 228
*   **Dionaea:** 89
*   **Sentrypeer:** 93
*   **Adbhoney:** 33
*   **Tanner:** 46
*   **ElasticPot:** 24
*   **H0neytr4p:** 30
*   **Redishoneypot:** 15
*   **ConPot:** 17
*   **Honeyaml:** 8
*   **Dicompot:** 7
*   **Heralding:** 6
*   **Ipphoney:** 1

***Top Attacking IPs:***
*   176.65.141.117
*   118.194.230.211
*   185.156.73.166
*   92.63.197.55
*   77.221.156.190
*   92.63.197.59
*   122.155.0.205
*   159.65.154.92
*   177.130.248.114
*   160.251.197.41
*   114.255.89.155
*   24.144.124.91
*   1.214.197.163
*   210.211.97.226
*   38.47.94.38
*   121.204.220.5
*   39.109.116.40
*   118.193.43.244
*   112.196.70.142
*   59.36.219.248

***Top Targeted Ports/Protocols:***
*   25
*   22
*   5060
*   80
*   443
*   TCP/445
*   23
*   TCP/80
*   TCP/1433
*   TCP/8080
*   9200
*   TCP/22
*   445
*   TCP/88

***Most Common CVEs:***
*   CVE-2019-11500
*   CVE-2021-3449
*   CVE-2006-2369
*   CVE-2002-0013
*   CVE-2002-0012
*   CVE-1999-0517

***Commands Attempted by Attackers:***
*   `cd ~; chattr -ia .ssh; lockr -ia .ssh`
*   `lockr -ia .ssh`
*   `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."`
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
*   `uname -a`
*   `uname`
*   `whoami`
*   `lscpu | grep Model`
*   `df -h | head -n 2 | awk 'FNR == 2 {print $2;}'`
*   `Enter new UNIX password:`

***Signatures Triggered:***
*   ET DROP Dshield Block Listed Source group 1
*   2402000
*   ET SCAN NMAP -sS window 1024
*   2009582
*   ET INFO Reserved Internal IP Traffic
*   2002752
*   ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication
*   2024766
*   ET CINS Active Threat Intelligence Poor Reputation IP group 48
*   2403347
*   ET CINS Active Threat Intelligence Poor Reputation IP group 43
*   2403342

***Users / Login Attempts:***
*   `345gs5662d34/345gs5662d34`
*   `root/nPSpP4PBW0`
*   `superadmin/admin123`
*   `minecraft/3245gs5662d34`
*   `test/zhbjETuyMffoL8F`
*   `foundry/foundry`
*   `root/2glehe5t24th1issZs`
*   `foundry/3245gs5662d34`
*   `root/LeitboGi0ro`

***Files Uploaded/Downloaded:***
*   wget.sh;
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
*   w.sh;
*   c.sh;

**Key Observations and Anomalies:**
- A recurring attack pattern was observed where attackers, after gaining access via SSH, attempted to modify the `.ssh/authorized_keys` file to maintain persistent access.
- Attackers frequently run system reconnaissance commands like `uname -a`, `lscpu`, and `cat /proc/cpuinfo` to understand the environment they have compromised.
- Multiple attempts to download and execute malicious scripts (e.g., `urbotnetisass`, `wget.sh`) were observed, indicating attempts to deploy malware or enlist the server in a botnet.
- A significant number of security signatures were triggered, with "Dshield Block Listed Source" and "NMAP Scans" being the most common, indicating that many of the attacking IPs are known malicious actors.