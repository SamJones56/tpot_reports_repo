Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-09T01:01:31Z
**Timeframe:** 2025-10-09T00:20:01Z to 2025-10-09T01:00:01Z
**Files Used:**
- agg_log_20251009T002001Z.json
- agg_log_20251009T004001Z.json
- agg_log_20251009T010001Z.json

**Executive Summary**

This report summarizes 24,884 attacks recorded across multiple honeypots. The most targeted honeypots were Suricata, Honeytrap, and Heralding. A significant portion of the attacks originated from the IP address 188.253.1.20, which was responsible for over 4,000 events. The most frequently targeted port was vnc/5900, indicating a high volume of VNC-related scans and attacks. Attackers attempted to exploit several vulnerabilities, with CVE-2021-44228 (Log4j) and various older CVEs being notable. The most common activities involved reconnaissance, brute-force login attempts, and the execution of commands to add SSH keys for persistent access.

**Detailed Analysis**

**Attacks by Honeypot:**
*   Suricata: 6,515
*   Honeytrap: 4,202
*   Heralding: 4,195
*   Cowrie: 3,980
*   Dionaea: 2,624
*   Ciscoasa: 1,686
*   Mailoney: 873
*   ConPot: 460
*   Sentrypeer: 135
*   H0neytr4p: 70
*   Redishoneypot: 70
*   Adbhoney: 26
*   Tanner: 30
*   Honeyaml: 11
*   Dicompot: 4
*   Ipphoney: 2
*   ElasticPot: 1

**Top Attacking IPs:**
*   188.253.1.20: 4,192
*   94.187.170.251: 2,099
*   138.68.130.119: 1,620
*   189.203.86.125: 1,329
*   10.208.0.3: 962
*   86.54.42.238: 821
*   114.219.56.203: 1,125
*   10.17.0.5: 1,131
*   10.140.0.3: 965
*   49.145.220.252: 505

**Top Targeted Ports/Protocols:**
*   vnc/5900: 4,192
*   445: 2,133
*   TCP/445: 1,858
*   2121: 928
*   25: 877
*   22: 643
*   1025: 448
*   5060: 135
*   5903: 181
*   8333: 135

**Most Common CVEs:**
*   CVE-2021-44228
*   CVE-2006-2369
*   CVE-2002-0013
*   CVE-2002-0012
*   CVE-1999-0517
*   CVE-2019-11500
*   CVE-2021-35394
*   CVE-2005-4050

**Commands Attempted by Attackers:**
*   `cd ~; chattr -ia .ssh; lockr -ia .ssh`
*   `lockr -ia .ssh`
*   `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ...">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~`
*   `cat /proc/cpuinfo | grep name | wc -l`
*   `Enter new UNIX password:`
*   `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`
*   `ls -lh $(which ls)`
*   `crontab -l`
*   `uname -a`
*   `whoami`

**Signatures Triggered:**
*   ET INFO VNC Authentication Failure: 3,058
*   ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication: 1,853
*   ET DROP Dshield Block Listed Source group 1: 264
*   ET SCAN MS Terminal Server Traffic on Non-standard Port: 197
*   ET SCAN NMAP -sS window 1024: 155
*   ET FTP FTP PWD command attempt without login: 66
*   ET FTP FTP CWD command attempt without login: 66
*   ET HUNTING RDP Authentication Bypass Attempt: 48
*   ET SCAN Potential SSH Scan: 54
*   ET INFO Reserved Internal IP Traffic: 57

**Users / Login Attempts:**
*   345gs5662d34/345gs5662d34: 10
*   root/huawei123: 6
*   root/4444444: 6
*   centos/centos3: 4
*   /qwertyqwerty: 4
*   /12345qwe: 4
*   /zaqxswcde: 4
*   /qweqweqwe: 4
*   root/999: 4
*   /qwerty12: 9

**Files Uploaded/Downloaded:**
*   rondo.kqa.sh|sh&echo

**HTTP User-Agents:**
*   None observed.

**SSH Clients and Servers:**
*   None observed.

**Top Attacker AS Organizations:**
*   None observed.

**Key Observations and Anomalies**

*   **High-Volume VNC Scans:** The overwhelming number of events targeting vnc/5900 from the IP 188.253.1.20 suggests a large-scale, automated scanning operation, likely searching for unsecured VNC servers.
*   **Persistent SSH Access Attempts:** A recurring pattern of commands aimed at adding a specific SSH public key to the `authorized_keys` file was observed. This indicates a campaign to establish persistent access to compromised systems.
*   **DoublePulsar Activity:** The frequent triggering of the "DoublePulsar Backdoor" signature is a strong indicator of attempts to exploit SMB vulnerabilities, likely related to the EternalBlue exploit.
*   **Internal IP Traffic:** The presence of traffic from reserved internal IP addresses (e.g., 10.x.x.x) may indicate internal reconnaissance or misconfigured systems within the honeypot network.

This concludes the Honeypot Attack Summary Report.