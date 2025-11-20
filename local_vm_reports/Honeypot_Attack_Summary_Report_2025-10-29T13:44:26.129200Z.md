# Honeypot Attack Summary Report - 2025-10-27

**Report Generation Time:** 2025-10-28T14:00:00Z
**Timeframe of Analysis:** 2025-10-27T00:00:00Z to 2025-10-27T23:59:59Z
**Files Used to Generate Report:**
- All `Honeypot_Attack_Summary_Report_2025-10-27T*.md` files.

## Executive Summary

On October 27th, 2025, the honeypot network recorded over 300,000 malicious events. The attack patterns were consistent with previous days, with a strong focus on compromising VoIP systems, as evidenced by the high number of attacks targeting SIP. SSH brute-force attacks and attempts to exploit web vulnerabilities also remained prevalent. The most active attacker was `198.23.190.58`, an IP address with a history of malicious activity. A new malware downloader, `rondo.whm.sh`, was observed, indicating a potential new campaign or a variant of a previous one.

## Detailed Analysis

### Our IPs

| Honeypot | Private IP | Public IP |
|---|---|---|
| hive-us | 10.128.0.3 | 34.123.129.205 |
| sens-tai | 10.140.0.3 | 104.199.212.115 |
| sens-tel | 10.208.0.3 | 34.165.197.224 |
| sens-dub | 172.31.36.128| 3.253.97.195 |
| sens-ny | 10.108.0.2 | 161.35.180.163 |

### Attacks by Honeypot

| Honeypot | Attack Count |
|---|---|
| Sentrypeer | 82,054 |
| Cowrie | 77,066 |
| Ciscoasa | 53,663 |
| Honeytrap | 46,806 |
| Suricata | 44,950 |
| Mailoney | 2,407 |
| Dionaea | 957 |
| Tanner | 580 |
| H0neytr4p | 377 |
| Adbhoney | 377 |

### Top Attacking IPs

| IP Address | Attack Count |
|---|---|
| 198.23.190.58 | 46,094 |
| 144.172.108.231| 23,867 |
| 167.172.36.39 | 20,532 |
| 185.243.5.148 | 12,905 |
| 121.142.87.218| 9,019 |
| 185.243.5.158 | 8,845 |
| 193.24.211.28 | 3,712 |
| 200.6.48.51 | 5,423 |
| 220.205.122.62 | 3,422 |
| 115.190.11.142| 3,045 |

### Top Targeted Ports/Protocols

| Port/Protocol | Attack Count |
|---|---|
| 5060 (SIP) | 82,054 |
| 22 (SSH) | 12,528 |
| TCP/22 (SSH) | 2,175 |
| 5905 (VNC) | 2,262 |
| 5904 (VNC) | 2,262 |
| 25 (SMTP) | 2,407 |
| 8000 | 1,798 |

### Most Common CVEs

| CVE |
|---|
| CVE-2005-4050 |
| CVE-2002-0013, CVE-2002-0012 |
| CVE-2002-0013, CVE-2002-0012, CVE-1999-0517 |
| CVE-2013-2135 |
| CVE-2018-11776 (Apache Struts 2) |
| CVE-2023-22527 (Atlassian Confluence) |
| CVE-2021-35394 |

### Commands Attempted by Attackers

| Command |
|---|
| `cd ~; chattr -ia .ssh; lockr -ia .ssh` |
| `lockr -ia .ssh` |
| `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ...">>.ssh/authorized_keys` |
| System information gathering (`uname`, `lscpu`, etc.) |
| `crontab -l` |
| `w` |
| `top` |
| `Enter new UNIX password:` |

### Signatures Triggered

| Signature |
|---|
| ET VOIP MultiTech SIP UDP Overflow |
| ET DROP Dshield Block Listed Source group 1 |
| ET SCAN MS Terminal Server Traffic on Non-standard Port |
| ET SCAN NMAP -sS window 1024 |
| ET HUNTING RDP Authentication Bypass Attempt |
| ET INFO Reserved Internal IP Traffic |
| ET SCAN Potential SSH Scan |

### Users / Login Attempts

| Username/Password |
|---|
| `root/...` (various passwords) |
| `345gs5662d34/345gs5662d34` |
| `admin/...` (various passwords) |

### Files Uploaded/Downloaded

| Filename |
|---|
| `rondo.whm.sh|sh` |
| `wget.sh;` |
| `loader.sh|sh;#` |
| `w.sh;` |
| `c.sh;` |

### HTTP User-Agents

*No HTTP user-agents were recorded in the logs for this day.*

### SSH Clients and Servers

*No specific SSH clients or servers were recorded in the logs for this day.*

### Top Attacker AS Organizations

*No attacker AS organizations were recorded in the logs for this day.*

### OSINT All Commands captured

| Command | Insight |
|---|---|
| `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ...">>.ssh/authorized_keys` | Attackers continue to use this command to install their SSH keys for persistent access. |

### OSINT High frequency IPs and low frequency IPs Captured

| IP Address | Insight |
|---|---|
| 198.23.190.58 | This IP, associated with ColoCrossing, is a known source of malicious activity, particularly SIP attacks. |
| 144.172.108.231| This IP has been reported for various types of abuse, including SSH brute-force attacks. |
| 167.172.36.39 | Another IP with a history of malicious activity, including spam and phishing. |
| Low-frequency IPs | A large number of unique, low-frequency IPs were observed, likely individual scanners or smaller, less aggressive botnets. |

### OSINT on CVE's

| CVE | Insight |
|---|---|
| CVE-2013-2135 | A vulnerability in the `less` command, which can be used for privilege escalation. |
| CVE-2018-11776 (Apache Struts 2) | A critical remote code execution vulnerability in Apache Struts 2. |
| CVE-2023-22527 (Atlassian Confluence) | A critical remote code execution vulnerability in Atlassian Confluence. |
| CVE-2021-35394 | A vulnerability in Realtek's SDK, affecting a wide range of IoT devices. |

## Key Observations and Anomalies

- **Focus on VoIP:** The high volume of attacks targeting SIP indicates a strong interest in compromising VoIP systems. This could be for the purpose of making fraudulent calls, launching denial-of-service attacks, or using the compromised systems as a pivot point for further attacks.
- **New Malware Downloader:** The appearance of the `rondo.whm.sh` downloader suggests a new or evolving malware campaign. This script is likely used to download and install a more complex malware payload.
- **Targeting of Enterprise Software:** The scanning for vulnerabilities in Apache Struts 2 and Atlassian Confluence shows that attackers are targeting enterprise software, which can be a lucrative target due to the value of the data they hold.
- **IoT Vulnerabilities:** The scanning for the Realtek SDK vulnerability (CVE-2021-35394) highlights the continued threat to IoT devices. These devices are often unpatched and can be easily compromised to form botnets.

This concludes the report for October 27th, 2025. I will now proceed with the analysis for the next day.
I have completed the report for 2025-10-27. I will now proceed to the final day, 2025-10-28.

**Plan for 2025-10-28:**
1.  Read all files for 2025-10-28.
2.  Aggregate the data.
3.  Perform OSINT on key observables.
4.  Generate the daily report.
5.  Save the report.

I will start by reading the first file for 2025-10-28.
