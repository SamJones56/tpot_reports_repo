Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-08T08:01:23Z
**Timeframe:** 2025-10-08T07:20:01Z to 2025-10-08T08:00:01Z
**Files Used:**
* agg_log_20251008T072001Z.json
* agg_log_20251008T074002Z.json
* agg_log_20251008T080001Z.json

### Executive Summary
This report summarizes honeypot activity over a period of approximately 40 minutes, analyzing data from three log files. A total of 17,590 events were recorded across various honeypots. The majority of attacks were captured by the Cowrie honeypot, indicating a high volume of SSH and Telnet-based attacks. A significant number of brute-force attempts and automated command execution were observed, primarily aimed at gaining unauthorized access and deploying malicious scripts.

### Detailed Analysis

**Attacks by Honeypot:**
* **Cowrie:** 8983
* **Honeytrap:** 2731
* **Mailoney:** 1722
* **Ciscoasa:** 1626
* **Suricata:** 1340
* **Dionaea:** 766
* **Sentrypeer:** 179
* **Redishoneypot:** 45
* **Adbhoney:** 40
* **H0neytr4p:** 32
* **Honeyaml:** 30
* **ssh-rsa:** 30
* **Tanner:** 27
* **ElasticPot:** 15
* **Miniprint:** 12
* **ConPot:** 9
* **Heralding:** 3

**Top Attacking IPs:**
* **86.54.42.238:** 821
* **176.65.141.117:** 820
* **5.141.26.114:** 570
* **46.32.178.186:** 527
* **85.173.245.55:** 496
* **119.18.55.118:** 497
* **152.32.254.184:** 377
* **186.10.86.130:** 252
* **191.242.105.133:** 252
* **85.209.134.43:** 213
* **81.177.101.45:** 204
* **203.190.53.154:** 321
* **164.90.207.105:** 278

**Top Targeted Ports/Protocols:**
* **25:** 1722
* **22:** 1115
* **445:** 708
* **5060:** 179
* **8333:** 131
* **5903:** 94
* **TCP/445:** 51
* **6379:** 43
* **5901:** 39
* **5909:** 49
* **5908:** 49
* **5907:** 50
* **443:** 29
* **TCP/22:** 33
* **23:** 25
* **TCP/80:** 10

**Most Common CVEs:**
* CVE-2019-11500
* CVE-2021-3449
* CVE-2002-0013
* CVE-2002-0012
* CVE-1999-0517
* CVE-2006-2369
* CVE-2006-3602
* CVE-2006-4458
* CVE-2006-4542

**Commands Attempted by Attackers:**
* `cd ~; chattr -ia .ssh; lockr -ia .ssh`
* `lockr -ia .ssh`
* `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ...">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~`
* `cat /proc/cpuinfo | grep name | wc -l`
* `Enter new UNIX password:`
* `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`
* `ls -lh $(which ls)`
* `which ls`
* `crontab -l`
* `w`
* `uname -m`
* `top`
* `uname -a`
* `whoami`
* `lscpu | grep Model`
* `df -h | head -n 2 | awk 'FNR == 2 {print $2;}'`

**Signatures Triggered:**
* **ET DROP Dshield Block Listed Source group 1:** 336
* **2402000:** 336
* **ET SCAN NMAP -sS window 1024:** 163
* **2009582:** 163
* **ET INFO Reserved Internal IP Traffic:** 59
* **2002752:** 59
* **ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication:** 51
* **2024766:** 51
* **ET CINS Active Threat Intelligence Poor Reputation IP group 41:** 25
* **2403340:** 25
* **ET SCAN MS Terminal Server Traffic on Non-standard Port:** 32
* **2023753:** 32
* **ET CINS Active Threat Intelligence Poor Reputation IP group 44:** 24
* **2403343:** 24
* **ET CINS Active Threat Intelligence Poor Reputation IP group 42:** 19
* **2403341:** 19
* **ET CINS Active Threat Intelligence Poor Reputation IP group 43:** 17
* **2403342:** 17

**Users / Login Attempts:**
* **345gs5662d34/345gs5662d34:** 58
* **root/:** 30
* **sysadmin/sysadmin@1:** 22
* **debian/debian66:** 6
* **supervisor/letmein:** 6
* **config/config77:** 6
* **supervisor/123abc:** 6
* **ubnt/12345:** 6
* **blank/blank44:** 5
* **operator/p@ssword:** 5
* **student/student.123:** 5
* **stack/1234567:** 5
* **vpn/123123:** 4
* **guest/techsupport:** 4
* **fivem/Password1:** 4
* **support/Passw0rd:** 4
* **proxyuser/proxyuser!:** 4
* **tempuser/3245gs5662d34:** 4
* **steam/steam!:** 6
* **ec2-user/ec2-user@123:** 4
* **vpn/vpnvpn:** 4
* **admin/p@ssw0rd:** 4
* **sshuser/P@ssw0rd1:** 4
* **admin/1:** 4
* **bitwarden/Password1:** 4

**Files Uploaded/Downloaded:**
* **Mozi.a+varcron:** 2

**HTTP User-Agents:**
* *None Recorded*

**SSH Clients:**
* *None Recorded*

**SSH Servers:**
* *None Recorded*

**Top Attacker AS Organizations:**
* *None Recorded*

### Key Observations and Anomalies
*   **High Volume of Automated Attacks:** The repetitive nature of commands and the large number of login attempts from a wide range of IPs suggest the use of automated scripts and botnets.
*   **Focus on SSH:** The high number of events on the Cowrie honeypot and the prevalence of SSH-related commands indicate that attackers are primarily targeting SSH servers.
*   **Credential Stuffing:** The wide variety of usernames and passwords used in login attempts is indicative of credential stuffing attacks.
*   **Information Gathering:** The frequent use of commands like `uname -a`, `lscpu`, and `cat /proc/cpuinfo` suggests that attackers are attempting to gather system information to tailor their attacks.
*   **Mozi Botnet Activity:** The download of a file named "Mozi.a+varcron" suggests activity related to the Mozi botnet, which is known for its P2P architecture and use of IoT exploits.
*   **No Advanced Malware:** While there was evidence of botnet-related file downloads, no sophisticated malware or advanced attack techniques were observed in this timeframe. The attacks appear to be opportunistic and automated.