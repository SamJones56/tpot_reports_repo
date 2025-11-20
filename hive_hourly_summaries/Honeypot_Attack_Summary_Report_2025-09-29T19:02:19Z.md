Honeypot Attack Summary Report

**Report Generation Time:** 2025-09-29T19:01:34Z
**Timeframe:** 2025-09-29T18:20:01Z to 2025-09-29T19:00:02Z
**Files Used:**
- agg_log_20250929T182001Z.json
- agg_log_20250929T184001Z.json
- agg_log_20250929T190002Z.json

**Executive Summary**
This report summarizes honeypot activity over a period of approximately 40 minutes, analyzing data from three consecutive log files. A total of 13,228 attacks were recorded, with the Cowrie honeypot detecting the highest volume of activity. The most frequent attacks originated from the IP address 137.184.169.79. The most targeted ports were 445 (SMB) and 22 (SSH). A variety of CVEs were exploited, and numerous commands were attempted by attackers, primarily focused on reconnaissance and establishing persistent access.

**Detailed Analysis**

**Attacks by Honeypot:**
*   **Cowrie:** 5862
*   **Honeytrap:** 2589
*   **Suricata:** 1559
*   **Ciscoasa:** 1461
*   **Dionaea:** 1227
*   **Redishoneypot:** 247
*   **Mailoney:** 101
*   **Adbhoney:** 58
*   **Tanner:** 34
*   **Sentrypeer:** 22
*   **H0neytr4p:** 18
*   **Heralding:** 16
*   **ssh-rsa:** 14
*   **ConPot:** 10
*   **Honeyaml:** 5
*   **Dicompot:** 3
*   **ElasticPot:** 1
*   **Ipphoney:** 1

**Top Attacking IPs:**
*   137.184.169.79
*   106.75.131.128
*   58.186.122.40
*   202.88.244.34
*   185.156.73.167
*   185.156.73.166
*   92.63.197.55
*   60.174.72.198
*   92.63.197.59
*   103.181.143.216

**Top Targeted Ports/Protocols:**
*   445
*   22
*   6379
*   8333
*   25
*   23
*   TCP/22
*   4433
*   TCP/80

**Most Common CVEs:**
*   CVE-2019-11500
*   CVE-2002-0013
*   CVE-2002-0012
*   CVE-2020-2551
*   CVE-2021-3449
*   CVE-1999-0517
*   CVE-1999-0265
*   CVE-2006-2369
*   CVE-2024-3721
*   CVE-2005-4050

**Commands Attempted by Attackers:**
*   `uname -a`
*   `cd ~; chattr -ia .ssh; lockr -ia .ssh`
*   `lockr -ia .ssh`
*   `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ...">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~`
*   `cat /proc/cpuinfo | grep name | wc -l`
*   `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`
*   `ls -lh $(which ls)`
*   `which ls`
*   `crontab -l`
*   `w`
*   `uname -m`
*   `top`
*   `whoami`
*   `lscpu | grep Model`
*   `df -h | head -n 2 | awk 'FNR == 2 {print $2;}'`

**Signatures Triggered:**
*   ET DROP Dshield Block Listed Source group 1
*   2402000
*   ET SCAN NMAP -sS window 1024
*   2009582
*   ET INFO Reserved Internal IP Traffic
*   2002752
*   ET SCAN Potential SSH Scan
*   2001219
*   ET DROP Spamhaus DROP Listed Traffic Inbound group 32
*   2400031

**Users / Login Attempts:**
*   345gs5662d34/345gs5662d34
*   root/
*   foundry/foundry
*   test/zhbjETuyMffoL8F
*   deposito/deposito123
*   root/nPSpP4PBW0
*   nurul/nurul
*   user/P@$$word
*   root/Admin123!@
*   root/3245gs5662d34

**Files Uploaded/Downloaded:**
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
*   k.php?a=x86_64,3V74AX6926R6GH83H

**HTTP User-Agents:**
- No user agents were recorded in this period.

**SSH Clients:**
- No specific SSH clients were recorded in this period.

**SSH Servers:**
- No specific SSH servers were recorded in this period.

**Top Attacker AS Organizations:**
- No attacker AS organizations were recorded in this period.

**Key Observations and Anomalies**
- A significant number of commands are focused on modifying the `.ssh/authorized_keys` file, indicating a clear intent to establish persistent SSH access.
- The attackers frequently use reconnaissance commands like `uname -a`, `lscpu`, and `cat /proc/cpuinfo` to gather system information.
- A recurring pattern of downloading and executing shell scripts (`wget.sh`, `w.sh`, `c.sh`) and binaries (`arm.urbotnetisass`, etc.) suggests automated attacks, likely from a botnet.
- The IP address 106.75.131.128 showed a very high volume of attacks in a short period in the last log file, suggesting a targeted or aggressive scan.
- The most common signatures triggered are related to known malicious IP blocklists (Dshield, Spamhaus), indicating that the attacks are coming from sources with a poor reputation.
