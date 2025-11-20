# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-03T03:01:29Z
**Timeframe:** 2025-10-03T02:20:01Z to 2025-10-03T03:00:01Z
**Files Analyzed:**
- `agg_log_20251003T022001Z.json`
- `agg_log_20251003T024001Z.json`
- `agg_log_20251003T030001Z.json`

## Executive Summary

This report summarizes 20,236 events recorded across the honeypot network. The majority of attacks were captured by the Cowrie honeypot, indicating a high volume of SSH and Telnet bruteforce activity. The most prominent attacker IP was `203.172.130.107`, primarily targeting SMB services, triggering signatures related to the DoublePulsar backdoor. A significant number of login attempts were observed against SMTP (Mailoney) and SIP (Sentrypeer) services. A recurring pattern of an attacker attempting to add their SSH key to the `authorized_keys` file was noted across all monitored periods.

## Detailed Analysis

### Attacks by Honeypot
- **Cowrie:** 8624
- **Suricata:** 3269
- **Mailoney:** 2498
- **Ciscoasa:** 2617
- **Sentrypeer:** 1573
- **Honeytrap:** 1299
- **Tanner:** 74
- **Dionaea:** 72
- **Miniprint:** 86
- **H0neytr4p:** 36
- **Honeyaml:** 31
- **Redishoneypot:** 24
- **Dicompot:** 9
- **ConPot:** 8
- **ElasticPot:** 7
- **Heralding:** 6
- **Adbhoney:** 2
- **Ipphoney:** 1

### Top 20 Attacking IPs
- **203.172.130.107:** 1460
- **23.175.48.211:** 1232
- **176.65.141.117:** 1640
- **178.128.232.91:** 1244
- **86.54.42.238:** 821
- **36.77.220.197:** 442
- **52.187.61.159:** 369
- **88.210.63.16:** 444
- **185.156.73.166:** 347
- **39.109.116.40:** 305
- **159.203.46.134:** 273
- **113.193.234.210:** 232
- **92.63.197.55:** 337
- **147.93.189.166:** 343
- **121.238.17.151:** 256
- **161.35.75.99:** 237
- **154.203.166.161:** 238
- **4.240.96.126:** 203
- **128.199.24.112:** 212
- **92.63.197.59:** 301

### Top Targeted Ports/Protocols
- **25:** 2498 (SMTP)
- **22:** 1179 (SSH)
- **5060:** 1573 (SIP)
- **TCP/445:** 1506 (SMB)
- **9100:** 86
- **80:** 82
- **443:** 36
- **TCP/1080:** 24
- **23:** 18
- **6379:** 21

### Most Common CVEs
- **CVE-2002-0013, CVE-2002-0012:** 12
- **CVE-2002-0013, CVE-2002-0012, CVE-1999-0517:** 8
- **CVE-2021-3449:** 4
- **CVE-2020-2551:** 4
- **CVE-2019-11500:** 3
- **CVE-1999-0183:** 1

### Commands Attempted by Attackers
- **cd ~; chattr -ia .ssh; lockr -ia .ssh:** 49
- **lockr -ia .ssh:** 49
- **cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ... mdrfckr":** 49
- **cat /proc/cpuinfo | grep name | wc -l:** 48
- **free -m | grep Mem | awk ...:** 49
- **uname -a:** 50
- **w:** 49
- **crontab -l:** 49
- **whoami:** 49
- **uname -m:** 49
- **top:** 49
- **Enter new UNIX password: :** 27

### Top 10 Signatures Triggered
- **ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication (2024766):** 1502
- **ET DROP Dshield Block Listed Source group 1 (2402000):** 516
- **ET SCAN MS Terminal Server Traffic on Non-standard Port (2023753):** 256
- **ET SCAN NMAP -sS window 1024 (2009582):** 164
- **ET HUNTING RDP Authentication Bypass Attempt (2034857):** 116
- **ET INFO Reserved Internal IP Traffic (2002752):** 58
- **ET CINS Active Threat Intelligence Poor Reputation IP group 49 (2403348):** 15
- **ET CINS Active Threat Intelligence Poor Reputation IP group 46 (2403345):** 22
- **GPL INFO SOCKS Proxy attempt (2100615):** 17
- **ET DROP Spamhaus DROP Listed Traffic Inbound group 28 (2400027):** 15

### Top 10 Users / Login Attempts (user/password)
- **345gs5662d34/345gs5662d34:** 48
- **root/3245gs5662d34:** 20
- **root/2glehe5t24th1issZs:** 15
- **superadmin/admin123:** 13
- **root/nPSpP4PBW0:** 17
- **root/LeitboGi0ro:** 14
- **test/zhbjETuyMffoL8F:** 12
- **foundry/foundry:** 10
- **sunil/sunil:** 6
- **seekcy/Joysuch@Locate2024:** 4

### Files Uploaded/Downloaded
- **sh:** 6
- **11:** 2
- **fonts.gstatic.com:** 2
- **css?family=Libre+Franklin...:** 2
- **ie8.css?ver=1.0:** 2
- **html5.js?ver=3.7.3:** 2

### HTTP User-Agents
- No user agents were recorded in this period.

### SSH Clients and Servers
- No specific SSH clients or servers were identified in this period.

### Top Attacker AS Organizations
- No attacker AS organizations were recorded in this period.

## Key Observations and Anomalies

1.  **High Volume SMB Exploitation:** The IP `203.172.130.107` was responsible for a large number of events targeting SMB (TCP/445) and triggered the "DoublePulsar Backdoor" signature over 1,500 times. This indicates a targeted campaign to exploit the vulnerability associated with the EternalBlue/DoublePulsar malware family.
2.  **Persistent SSH Key Injection:** A recurring set of commands was observed across all log files, where attackers attempt to remove existing SSH configurations and inject a specific public SSH key into the `authorized_keys` file. This is a common tactic to establish persistent access.
3.  **Credential Stuffing on Multiple Protocols:** There is a clear indication of widespread credential stuffing attacks. The Cowrie honeypot captured numerous SSH login attempts, while Mailoney and Sentrypeer recorded significant activity on SMTP (port 25) and SIP (port 5060) respectively, suggesting automated attacks across different services.
4.  **Scanning Activity:** A variety of scanning signatures were triggered, including NMAP scans and probes for Microsoft Terminal Server on non-standard ports, indicating widespread reconnaissance activities by multiple actors.
5.  **Lack of Sophistication:** The majority of commands and login attempts appear to be automated and based on common, publicly known credentials and vulnerabilities. The CVEs detected are relatively old, suggesting attackers are targeting unpatched or legacy systems.
