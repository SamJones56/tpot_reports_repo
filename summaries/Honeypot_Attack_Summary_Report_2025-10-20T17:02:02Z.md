
# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-20T17:01:32Z
**Timeframe:** 2025-10-20T16:20:01Z to 2025-10-20T17:00:02Z
**Files Analyzed:**
- agg_log_20251020T162001Z.json
- agg_log_20251020T164001Z.json
- agg_log_20251020T170002Z.json

---

## Executive Summary

This report summarizes 19,667 events collected from the T-Pot honeypot network over the last hour. The majority of attacks were captured by the Cowrie and Sentrypeer honeypots. A significant surge in activity was observed targeting the Sentrypeer honeypot on port 5060 (SIP), originating overwhelmingly from the IP address `5.182.209.68`. SSH (port 22) remains a primary target, with attackers consistently attempting to deploy SSH keys for persistence and execute reconnaissance commands. Malware download attempts, particularly for `urbotnetisass` variants, were also prevalent.

---

## Detailed Analysis

### Attacks by Honeypot
- **Cowrie:** 7,289
- **Sentrypeer:** 5,741
- **Honeytrap:** 4,106
- **Suricata:** 1,372
- **Dionaea:** 779
- **Mailoney:** 126
- **Adbhoney:** 65
- **Tanner:** 58
- **Ciscoasa:** 33
- **H0neytr4p:** 53
- **Redishoneypot:** 17
- **ConPot:** 17
- **ElasticPot:** 4
- **Dicompot:** 3
- **Heralding:** 3
- **ssh-rsa:** 2

### Top Attacking IPs
- `5.182.209.68`
- `72.146.232.13`
- `181.12.133.131`
- `165.232.88.6`
- `38.25.39.212`
- `137.184.202.107`
- `175.126.166.172`
- `37.152.189.98`
- `12.189.234.28`
- `185.243.5.158`
- `107.170.36.5`

### Top Targeted Ports/Protocols
- `5060`
- `22`
- `445`
- `5903`
- `2000`
- `5985`
- `5901`
- `8333`
- `25`
- `TCP/80`

### Most Common CVEs
- `CVE-2002-1149`
- `CVE-2002-0013 CVE-2002-0012`
- `CVE-2024-4577 CVE-2002-0953`
- `CVE-2024-4577 CVE-2024-4577`
- `CVE-2002-0013 CVE-2002-0012 CVE-1999-0517`
- `CVE-2024-3721 CVE-2024-3721`
- `CVE-2021-3449 CVE-2021-3449`
- `CVE-2019-11500 CVE-2019-11500`
- `CVE-2021-35394 CVE-2021-35394`
- `CVE-2016-6563`
- `CVE-2021-41773 CVE-2021-41773 CVE-2021-41773 CVE-2021-41773`
- `CVE-2021-42013 CVE-2021-42013`

### Commands Attempted by Attackers
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..." >> .ssh/authorized_keys`
- `lockr -ia .ssh`
- `cd ~; chattr -ia .ssh; lockr -ia .ssh`
- `cat /proc/cpuinfo | grep name | wc -l`
- `free -m | grep Mem | ...`
- `uname -a`
- `whoami`
- `w`
- `top`
- `crontab -l`
- `Enter new UNIX password:`

### Signatures Triggered
- `ET SCAN MS Terminal Server Traffic on Non-standard Port`
- `ET DROP Dshield Block Listed Source group 1`
- `ET SCAN NMAP -sS window 1024`
- `ET HUNTING RDP Authentication Bypass Attempt`
- `ET INFO Reserved Internal IP Traffic`
- `ET DROP Spamhaus DROP Listed Traffic Inbound`
- `ET INFO CURL User Agent`
- `ET COMPROMISED Known Compromised or Hostile Host Traffic`
- `ET SCAN Suspicious inbound to PostgreSQL port 5432`

### Users / Login Attempts (User/Password)
- `345gs5662d34/345gs5662d34`
- `user01/Password01`
- `deploy/123123`
- `root/3245gs5662d34`
- `root/admin...` (various)
- `ubuntu/Qwerty123`
- `eagle/eagle`
- `prowlarr/prowlarr`
- `test/...` (various)

### Files Uploaded/Downloaded
- `sh`
- `wget.sh`
- `arm.urbotnetisass`
- `arm5.urbotnetisass`
- `arm6.urbotnetisass`
- `arm7.urbotnetisass`
- `x86_32.urbotnetisass`
- `mips.urbotnetisass`
- `mipsel.urbotnetisass`
- `w.sh`
- `c.sh`
- `Mozi.m`

### HTTP User-Agents
- No significant user agents recorded.

### SSH Clients and Servers
- No specific SSH client or server versions recorded.

### Top Attacker AS Organizations
- No AS organization data recorded.

---

## Key Observations and Anomalies

1.  **High-Volume SIP Scans:** The most significant activity was a massive scan/attack on port 5060 (SIP) from `5.182.209.68`, accounting for over a quarter of all events in this period. This indicates a targeted effort to find and exploit VoIP systems.
2.  **Persistent SSH Intrusion Attempts:** Attackers consistently used a multi-stage command to remove existing SSH configurations, add their own public key for persistent access, and then lock the directory to prevent other attackers from doing the same.
3.  **Automated Malware Deployment:** The repeated attempts to download and execute various `urbotnetisass` binaries suggest an automated campaign to build a botnet across multiple CPU architectures (ARM, x86, MIPS).
4.  **Reconnaissance Activity:** Standard reconnaissance commands (`uname -a`, `whoami`, `cat /proc/cpuinfo`, `w`) were universally present in successful SSH sessions, indicating attackers are profiling systems for further exploitation.
