
# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-14T10:01:44Z
**Timeframe of Analysis:** 2025-10-14T09:20:01Z to 2025-10-14T10:00:01Z
**Log Files Processed:**
- agg_log_20251014T092001Z.json
- agg_log_20251014T094001Z.json
- agg_log_20251014T100001Z.json

---

### Executive Summary

This report summarizes 22,486 malicious events captured by the honeypot network. The majority of attacks were detected by the Cowrie, Suricata, and Honeytrap honeypots. A significant portion of the traffic involved attempts to exploit SMB and SIP services, with the DoublePulsar backdoor being a commonly detected threat. Attackers were observed attempting to download and execute malware, add SSH keys for persistence, and perform system reconnaissance.

---

### Detailed Analysis

#### Attacks by Honeypot
- Cowrie: 5208
- Suricata: 5020
- Honeytrap: 4573
- Sentrypeer: 3305
- Dionaea: 1501
- Ciscoasa: 1809
- Mailoney: 903
- Tanner: 45
- H0neytr4p: 44
- Redishoneypot: 15
- Honeyaml: 21
- ConPot: 15
- Adbhoney: 8
- ElasticPot: 9
- Miniprint: 6
- Wordpot: 1
- Dicompot: 3

#### Top Attacking IPs
- 154.242.102.242: 1945
- 202.164.134.34: 1338
- 51.89.1.86: 1253
- 206.191.154.180: 1356
- 185.243.5.146: 1254
- 42.119.232.181: 805
- 176.65.141.119: 821
- 185.243.5.148: 778
- 41.226.251.192: 425
- 45.236.188.4: 540
- 46.32.178.186: 408
- 172.86.95.98: 407
- 172.86.95.115: 396
- 88.210.63.16: 339
- 62.141.43.183: 324

#### Top Targeted Ports/Protocols
- TCP/445: 3277
- 5060: 3305
- 445: 1411
- 22: 915
- 25: 879
- 5903: 189
- 8333: 111
- 5908: 83
- 5909: 82
- UDP/5060: 83
- 5901: 76
- 80: 44
- 23: 39
- 443: 36

#### Most Common CVEs
- CVE-2005-4050
- CVE-2006-0189
- CVE-2022-27255
- CVE-2016-20016
- CVE-1999-0183

#### Commands Attempted by Attackers
- cd ~; chattr -ia .ssh; lockr -ia .ssh: 22
- lockr -ia .ssh: 22
- cd ~ && rm -rf .ssh && mkdir .ssh && echo ... >> .ssh/authorized_keys ...: 22
- cat /proc/cpuinfo | grep name | wc -l: 10
- cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}': 10
- uname -s -v -n -r -m: 4
- cd /data/local/tmp/; rm *; busybox wget ...: 2
- Enter new UNIX password: : 5
- Enter new UNIX password:: 5

#### Signatures Triggered
- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication: 3269
- 2024766: 3269
- ET DROP Dshield Block Listed Source group 1: 486
- 2402000: 486
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 229
- 2023753: 229
- ET SCAN NMAP -sS window 1024: 163
- 2009582: 163
- ET HUNTING RDP Authentication Bypass Attempt: 85
- 2034857: 85
- ET VOIP MultiTech SIP UDP Overflow: 73
- 2003237: 73
- ET INFO Reserved Internal IP Traffic: 57
- 2002752: 57

#### Users / Login Attempts
- 345gs5662d34/345gs5662d34: 20
- root/3245gs5662d34: 12
- support/000000: 6
- exceed/exceed: 6
- infocus/infocus: 6
- hsi/wstinol: 6
- centos/333: 6
- root/root111: 6
- root/00000: 7
- root/8: 6
- root/Qaz123qaz: 7
- user/marketing: 4
- blank/blank2023: 4
- debian/22: 4

#### Files Uploaded/Downloaded
- ?format=json: 2
- arm.urbotnetisass;: 2
- arm.urbotnetisass: 2
- arm5.urbotnetisass;: 2
- arm5.urbotnetisass: 2
- arm6.urbotnetisass;: 2
- arm6.urbotnetisass: 2
- arm7.urbotnetisass;: 2
- arm7.urbotnetisass: 2
- x86_32.urbotnetisass;: 2
- x86_32.urbotnetisass: 2
- mips.urbotnetisass;: 2
- mips.urbotnetisass: 2
- mipsel.urbotnetisass;: 2
- mipsel.urbotnetisass: 2

#### HTTP User-Agents
- No user agents were recorded in this period.

#### SSH Clients and Servers
- No specific SSH clients or servers were recorded in this period.

#### Top Attacker AS Organizations
- No attacker AS organizations were recorded in this period.

---

### Key Observations and Anomalies

- **High Volume of SMB Exploitation:** A large number of events were related to the DoublePulsar backdoor, indicating widespread scanning and exploitation attempts targeting the SMB protocol (TCP/445).
- **SIP Scanning:** The Sentrypeer honeypot recorded a high volume of traffic on port 5060, suggesting large-scale scanning for vulnerable SIP services.
- **Malware Delivery:** The Cowrie honeypot captured attempts to download and execute the 'urbotnetisass' malware, a known botnet variant.
- **Credential Stuffing:** A wide variety of usernames and passwords were attempted, with a focus on default credentials for various devices and services. The username 'root' remains the most common target.
- **Persistence Attempts:** Attackers consistently attempted to add their SSH public key to the `authorized_keys` file to maintain access to compromised systems.
---
