
# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-23T18:01:36Z
**Timeframe:** 2025-10-23T17:20:01Z to 2025-10-23T18:00:01Z
**Log Files:**
- agg_log_20251023T172001Z.json
- agg_log_20251023T174001Z.json
- agg_log_20251023T180001Z.json

---

## Executive Summary

This report summarizes 16,695 events recorded across multiple honeypots. The most targeted services were Cowrie (SSH/Telnet) and Suricata (Network IDS). A significant portion of attacks originated from internal IP `10.140.0.3` and external IP `185.243.96.105`, primarily targeting VNC on port 5900. Attackers were observed attempting to add their SSH keys to the system for persistent access and executing reconnaissance commands to identify system architecture. Several CVEs were noted, with `CVE-2021-3449` being the most frequent.

---

## Detailed Analysis

### Attacks by Honeypot
- **Cowrie:** 5706
- **Suricata:** 3542
- **Heralding:** 2422
- **Honeytrap:** 2216
- **Ciscoasa:** 1741
- **Sentrypeer:** 734
- **Tanner:** 155
- **Dionaea:** 77
- **Miniprint:** 24
- **Redishoneypot:** 23
- **Mailoney:** 22
- **H0neytr4p:** 14
- **ConPot:** 12
- **Adbhoney:** 6
- **Honeyaml:** 1

### Top Attacking IPs
- **10.140.0.3:** 2433
- **185.243.96.105:** 2428
- **199.195.248.191:** 318
- **135.13.11.134:** 326
- **189.36.132.232:** 316
- **193.32.162.157:** 276
- **103.187.147.214:** 262
- **194.180.11.80:** 272
- **177.75.6.242:** 258
- **121.227.31.13:** 267
- **107.170.36.5:** 254
- **162.240.39.179:** 219
- **186.235.28.11:** 184
- **185.243.5.146:** 208
- **103.10.45.57:** 219

### Top Targeted Ports/Protocols
- **vnc/5900:** 2422
- **22:** 739
- **5060:** 734
- **5901:** 130
- **5903:** 135
- **8333:** 86
- **5905:** 79
- **5904:** 79
- **5908:** 49
- **5909:** 49
- **5907:** 49
- **5902:** 39
- **TCP/22:** 15
- **445:** 18
- **9100:** 24
- **11211:** 37
- **6379:** 17
- **25:** 10

### Most Common CVEs
- **CVE-2021-3449:** 6
- **CVE-2021-44228:** 5
- **CVE-2019-11500:** 4
- **CVE-2002-0013 CVE-2002-0012:** 7
- **CVE-2002-0013 CVE-2002-0012 CVE-1999-0517:** 6
- **CVE-2021-35394:** 1

### Commands Attempted by Attackers
- **System Reconnaissance (uname, lscpu, whoami, w):** 108
- **SSH Key Manipulation (adding authorized_keys):** 70
- **Password Change Attempts:** 48
- **File & Directory Listing/Manipulation:** 36
- **Network & Process Monitoring (top, netstat):** 36
- **Privilege Escalation/Backdoor Installation:** 2
- **File Download/Execution (wget, perl):** 1

### Signatures Triggered
- **ET INFO VNC Authentication Failure:** 2422
- **2002920 (SID for VNC Auth Failure):** 2422
- **ET DROP Dshield Block Listed Source group 1:** 258
- **2402000 (SID for Dshield Block):** 258
- **ET SCAN NMAP -sS window 1024:** 136
- **2009582 (SID for NMAP Scan):** 136
- **ET SCAN MS Terminal Server Traffic on Non-standard Port:** 119
- **2023753 (SID for MS Terminal Server Scan):** 119
- **ET HUNTING RDP Authentication Bypass Attempt:** 56
- **2034857 (SID for RDP Bypass):** 56
- **ET INFO Reserved Internal IP Traffic:** 50
- **2002752 (SID for Internal IP Traffic):** 50

### Users / Login Attempts
- **345gs5662d34/345gs5662d34:** 34
- **root/3245gs5662d34:** 11
- **/Passw0rd:** 12
- **/1q2w3e4r:** 8
- **/passw0rd:** 9
- **sa/:** 6
- **lee/lee:** 4
- **kabi/kabi:** 3

### Files Uploaded/Downloaded
- **FGx8SNCa4txePA.mips;**: 2
- **perl|perl**: 1

### HTTP User-Agents
- (No user agents recorded)

### SSH Clients and Servers
- (No specific clients or servers recorded)

### Top Attacker AS Organizations
- (No AS organizations recorded)

---

## Key Observations and Anomalies

1.  **High-Volume VNC Scans:** The overwhelming number of events targeting port 5900 (VNC) suggests a widespread, automated campaign searching for exposed remote desktop services.
2.  **Internal IP as Top Attacker:** The presence of `10.140.0.3` as a top source IP is anomalous and could indicate a compromised machine within the network, being used to pivot and attack the honeypot.
3.  **Persistent Access Attempts:** A common tactic observed was the attempt to remove existing SSH configurations and install a new `authorized_keys` file. This indicates a clear objective to establish persistent, passwordless access to compromised systems.
4.  **Reconnaissance Commands:** Attackers consistently ran a series of commands (`uname`, `lscpu`, `whoami`, `w`, `crontab -l`, `df -h`) immediately after gaining access. This is a standard procedure for attackers to understand the environment they have compromised before deciding on the next steps.

This concludes the Honeypot Attack Summary Report.
