Here is the Honeypot Attack Summary Report.

**Honeypot Attack Summary Report**

**Report Generation Time:** 2025-10-26T11:01:25Z
**Timeframe:** 2025-10-26T10:20:01Z to 2025-10-26T11:00:02Z
**Files Used:**
*   `agg_log_20251026T102001Z.json`
*   `agg_log_20251026T104002Z.json`
*   `agg_log_20251026T110002Z.json`

**Executive Summary**

This report summarizes 19,617 events collected from the honeypot network over a period of approximately 40 minutes. The majority of attacks were captured by the Cowrie, Suricata, and Honeytrap honeypots. A significant portion of the attacks originated from the IP address `109.205.211.9`. The most frequently targeted ports were 445 (SMB) and 22 (SSH). A number of CVEs were detected, with the most common being related to older vulnerabilities. Attackers attempted a variety of commands, many of which appear to be related to reconnaissance and establishing persistence.

**Detailed Analysis**

**Attacks by Honeypot:**
*   Cowrie: 7,499
*   Suricata: 4,526
*   Honeytrap: 3,453
*   Ciscoasa: 1,833
*   Dionaea: 1,143
*   Sentrypeer: 802
*   Mailoney: 124
*   Adbhoney: 83
*   H0neytr4p: 62
*   Tanner: 29
*   Dicompot: 19
*   ConPot: 13
*   Honeyaml: 9
*   Redishoneypot: 6
*   ElasticPot: 5
*   Ipphoney: 4
*   Miniprint: 7

**Top Attacking IPs:**
*   `109.205.211.9`
*   `138.124.30.225`
*   `51.89.1.86`
*   `115.113.198.245`
*   `59.182.215.119`
*   `41.139.164.134`
*   `185.243.5.121`
*   `45.130.148.125`
*   `223.247.218.112`
*   `31.193.137.190`

**Top Targeted Ports/Protocols:**
*   445
*   22
*   5060
*   8333
*   5903
*   5901
*   25
*   TCP/445
*   TCP/22
*   UDP/5060

**Most Common CVEs:**
*   CVE-2002-0013
*   CVE-2002-0012
*   CVE-1999-0517
*   CVE-2021-3449
*   CVE-2019-11500
*   CVE-1999-0183
*   CVE-2005-4050

**Commands Attempted by Attackers:**
*   `cd ~; chattr -ia .ssh; lockr -ia .ssh`
*   `lockr -ia .ssh`
*   `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ... mdrfckr">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~`
*   `cat /proc/cpuinfo | grep name | wc -l`
*   `cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'`
*   `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`
*   `ls -lh $(which ls)`
*   `which ls`
*   `crontab -l`
*   `w`

**Signatures Triggered:**
*   ET SCAN MS Terminal Server Traffic on Non-standard Port
*   2023753
*   ET HUNTING RDP Authentication Bypass Attempt
*   2034857
*   ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication
*   2024766
*   ET DROP Dshield Block Listed Source group 1
*   2402000
*   ET SCAN NMAP -sS window 1024
*   2009582

**Users / Login Attempts:**
*   `345gs5662d34/345gs5662d34`
*   `root/3245gs5662d34`
*   `bash/Drag1823hcacatcuciocolataABC111`
*   `root/i8cj5cy9ep`
*   `root/gerp8020`
*   `root/02041992Ionela%^&`
*   `root/GestorAC8642352166`
*   `ubuntu/tizi@123`
*   `root/getconet`
*   `jla/xurros22$`

**Files Uploaded/Downloaded:**
*   `wget.sh;`
*   `w.sh;`
*   `c.sh;`
*   `arm.urbotnetisass;`
*   `arm.urbotnetisass`
*   `arm5.urbotnetisass;`
*   `arm5.urbotnetisass`
*   `arm6.urbotnetisass;`
*   `arm6.urbotnetisass`
*   `arm7.urbotnetisass;`
*   `arm7.urbotnetisass`
*   `x86_32.urbotnetisass;`
*   `x86_32.urbotnetisass`
*   `mips.urbotnetisass;`
*   `mips.urbotnetisass`
*   `mipsel.urbotnetisass;`
*   `mipsel.urbotnetisass`

**HTTP User-Agents:**
*   (No data in logs)

**SSH Clients and Servers:**
*   (No data in logs)

**Top Attacker AS Organizations:**
*   (No data in logs)

**Key Observations and Anomalies**

*   **High Volume of Cowrie Attacks:** The Cowrie honeypot, which emulates an SSH server, saw the highest number of attacks. This suggests a large amount of automated SSH scanning and brute-force activity.
*   **Reconnaissance and Persistence Commands:** The most common commands are focused on gathering system information (`uname`, `lscpu`, `free`, `df`), and attempting to establish persistence by adding an SSH key to `authorized_keys`.
*   **Malware Downloads:** The presence of `wget` and `curl` commands, along with the downloading of `.sh` and other executable files, indicates attempts to download and execute malware on the honeypot. The `urbotnetisass` files suggest an attempt to install a botnet client.
*   **Older CVEs:** The CVEs detected are relatively old, suggesting that attackers are still scanning for and attempting to exploit legacy vulnerabilities.
*   **Single Dominant Attacker:** The IP address `109.205.211.9` was responsible for a disproportionately large number of attacks, indicating a targeted or highly active attacker.

This concludes the Honeypot Attack Summary Report. Further analysis of the downloaded files and attacker IPs could provide more insight into the threat actors and their motives.