
# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-18T22:01:36Z
**Timeframe:** 2025-10-18T21:20:01Z to 2025-10-18T22:00:01Z
**Log Files:**
- agg_log_20251018T212001Z.json
- agg_log_20251018T214001Z.json
- agg_log_20251018T220001Z.json

---

## Executive Summary

This report summarizes 20,177 events collected from multiple honeypots over a 40-minute period. The majority of activity was logged by the Cowrie, Suricata, and Honeytrap honeypots. A significant portion of the traffic targeted SMB (TCP/445) and SIP (UDP/5060) services. Attackers from various locations were observed, with IPs from Egypt and the United States being the most frequent. Several SSH brute-force attempts and reconnaissance commands were recorded, alongside attempts to exploit known vulnerabilities, most notably a 2005 vulnerability in SIP (CVE-2005-4050). A notable command sequence involved clearing SSH keys and adding a new authorized key, indicating attempts to establish persistent access.

---

## Detailed Analysis

### Attacks by Honeypot
- **Cowrie:** 6,898
- **Suricata:** 5,739
- **Honeytrap:** 3,209
- **Dionaea:** 989
- **Sentrypeer:** 2,023
- **Ciscoasa:** 1,220
- **Redishoneypot:** 39
- **Tanner:** 16
- **Mailoney:** 13
- **H0neytr4p:** 9
- **ConPot:** 9
- **Adbhoney:** 4
- **Dicompot:** 3
- **ElasticPot:** 3
- **Ipphoney:** 2
- **Wordpot:** 1

### Top Attacking IPs
- **41.38.91.194:** 1,446
- **197.59.74.70:** 1,295
- **176.9.111.156:** 1,258
- **72.146.232.13:** 1,224
- **198.23.190.58:** 1,202
- **23.94.26.58:** 1,158
- **194.50.16.73:** 987
- **193.168.196.68:** 882
- **186.10.24.214:** 868
- **198.12.68.114:** 845
- **66.29.143.67:** 473
- **88.210.63.16:** 415
- **107.170.36.5:** 251
- **68.183.43.246:** 240
- **103.172.205.139:** 133
- **61.14.236.230:** 118
- **185.40.30.168:** 103
- **167.250.224.25:** 101
- **172.200.228.35:** 93
- **116.193.190.103:** 93

### Top Targeted Ports/Protocols
- **TCP/445:** 3,603
- **5060:** 2,023
- **22:** 1,677
- **UDP/5060:** 1,376
- **5903:** 225
- **8333:** 149
- **1977:** 117
- **5901:** 115
- **81:** 81
- **TCP/22:** 71
- **5904:** 78
- **5905:** 78
- **5984:** 57
- **5908:** 49
- **5909:** 48
- **5902:** 41
- **6379:** 33
- **TCP/5432:** 30
- **2323:** 20
- **23:** 20

### Most Common CVEs
- **CVE-2005-4050:** 1,373
- **CVE-2024-3721 CVE-2024-3721:** 10
- **CVE-2002-0013 CVE-2002-0012:** 6
- **CVE-2019-11500 CVE-2019-11500:** 2
- **CVE-2021-35395 CVE-2021-35395:** 2
- **CVE-2016-20017 CVE-2016-20017:** 2
- **CVE-2002-0013 CVE-2002-0012 CVE-1999-0517:** 1
- **CVE-2006-2369:** 1

### Commands Attempted by Attackers
- **cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ...":** 12
- **uname -a:** 12
- **lockr -ia .ssh:** 12
- **cd ~; chattr -ia .ssh; lockr -ia .ssh:** 12
- **whoami:** 12
- **uname:** 11
- **top:** 11
- **uname -m:** 11
- **w:** 11
- **crontab -l:** 11
- **which ls:** 11
- **ls -lh $(which ls):** 11
- **free -m | grep Mem | awk ...:** 11
- **cat /proc/cpuinfo | grep name | head ...:** 11
- **cat /proc/cpuinfo | grep name | wc -l:** 11
- **cat /proc/cpuinfo | grep model | grep name | wc -l:** 11
- **rm -rf /tmp/secure.sh; ...:** 7
- **Enter new UNIX password: :** 5
- **uname -s -v -n -r -m:** 4

### Signatures Triggered
- **ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication:** 2,733
- **2024766:** 2,733
- **ET VOIP MultiTech SIP UDP Overflow:** 1,373
- **2003237:** 1,373
- **ET DROP Dshield Block Listed Source group 1:** 326
- **2402000:** 326
- **ET SCAN MS Terminal Server Traffic on Non-standard Port:** 275
- **2023753:** 275
- **ET SCAN NMAP -sS window 1024:** 164
- **2009582:** 164
- **ET HUNTING RDP Authentication Bypass Attempt:** 117
- **2034857:** 117
- **ET SCAN Potential SSH Scan:** 60
- **2001219:** 60
- **ET INFO Reserved Internal IP Traffic:** 60
- **2002752:** 60

### Users / Login Attempts
- **345gs5662d34/345gs5662d34:** 11
- **root/3245gs5662d34:** 7
- **user/7777777:** 6
- **debian/2222222:** 6
- **guest/test:** 6
- **nobody/nobody66:** 6
- **admin/3333:** 6
- **default/default2023:** 4
- **root/3807105:** 4
- **support/support2013:** 4
- **debian/00000:** 4
- **root/38563441:** 4
- **unknown/888:** 6
- **root/395451:** 4
- **root/3cn4w9psv:** 4
- **ubnt/123321:** 4
- **admin/5555555:** 4
- **root/3EDD4rfv6YHN:** 4

### Files Uploaded/Downloaded
- **rondo.rwx.sh|sh;**: 2
- **&currentsetting.htm=1**: 1

### HTTP User-Agents
- (No data)

### SSH Clients and Servers
- (No data)

### Top Attacker AS Organizations
- (No data)

---

## Key Observations and Anomalies

1.  **High Volume of SMB Exploitation:** The most frequent signature triggered was for the DoublePulsar backdoor, indicating widespread, automated scanning and exploitation attempts against the SMB protocol (TCP/445).
2.  **Persistent Access Attempts:** A recurring command sequence involved removing existing SSH configurations (`rm -rf .ssh`), creating a new `.ssh` directory, and adding a specific public SSH key to `authorized_keys`. This is a clear and aggressive tactic to gain persistent, passwordless access to a compromised machine.
3.  **SIP Vulnerability Scanning:** A very high number of events targeted UDP port 5060, specifically triggering a signature for a 2005 MultiTech SIP UDP Overflow (CVE-2005-4050). This highlights that legacy vulnerabilities are still actively exploited in the wild.
4.  **Extensive System Reconnaissance:** Following initial access via Cowrie, attackers consistently ran a battery of commands (`uname`, `lscpu`, `free`, `df`, `crontab -l`, etc.) to gather detailed information about the system's hardware, OS, and configuration.

---
