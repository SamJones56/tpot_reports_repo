# Honeypot Attack Summary Report

## Report Information

| **Field** | **Value** |
| :--- | :--- |
| **Report ID** | T-Pot-Summary-20250929T110138Z |
| **Date** | 2025-09-29 11:01:38 UTC |
| **Analyst** | Cybersecurity Analyst |
| **Period Covered** | 2025-09-29 10:20:01 UTC to 2025-09-29 11:00:01 UTC |

## Executive Summary

This report summarizes the findings from the T-Pot honeypot network over a period of approximately 40 minutes on September 29, 2025. During this time, a total of **10,241** malicious events were logged across various honeypot services. The threat landscape was dominated by automated attacks, with a significant focus on exploiting vulnerabilities in SMB and VOIP services.

The most prominent activity originated from the IP address **109.165.11.117**, which was responsible for over 15% of the total attack volume, primarily targeting the SMB service on TCP port 445. This, along with other indicators, suggests a widespread, automated campaign likely related to worms or botnets. The Suricata IPS engine detected the highest number of events, indicating a large volume of reconnaissance and exploit attempts.

Attackers were observed attempting to exploit several known vulnerabilities, including Log4Shell (CVE-2021-44228). Additionally, post-exploitation commands indicate attempts to download and execute malicious payloads, disable security measures, and add SSH keys for persistent access.

## Detailed Analysis

### Attacks by Honeypot Service

The following table shows the distribution of attacks across the different honeypot services deployed. Suricata, the Intrusion Prevention System, logged the most events, followed by Honeytrap and Cowrie.

| **Honeypot Service** | **Number of Attacks** |
| :--- | :--- |
| Suricata | 3540 |
| Honeytrap | 2361 |
| Cowrie | 1488 |
| Ciscoasa | 1474 |
| Sentrypeer | 1012 |
| Dionaea | 109 |
| Miniprint | 65 |
| Mailoney | 49 |
| Adbhoney | 37 |
| H0neytr4p | 32 |
| Tanner | 27 |
| ConPot | 16 |
| Redishoneypot | 15 |
| Honeyaml | 12 |
| ElasticPot | 4 |

### Top 10 Attacking IP Addresses

The following table lists the top 10 most active IP addresses observed during the reporting period. These IPs were responsible for a significant portion of the attack traffic.

| **Source IP Address** | **Number of Connections** |
| :--- | :--- |
| 109.165.11.117 | 1598 |
| 208.109.190.200 | 962 |
| 45.140.17.52 | 843 |
| 185.156.73.167 | 380 |
| 185.156.73.166 | 380 |
| 92.63.197.55 | 362 |
| 92.63.197.59 | 345 |
| 59.36.219.241 | 172 |
| 46.191.141.152 | 172 |
| 34.71.52.51 | 168 |

### Top 10 Targeted Ports

The table below shows the top 10 most targeted TCP/UDP ports. The high number of connections to port 445 (SMB) and 5060 (SIP) are particularly noteworthy.

| **Port** | **Number of Attempts** |
| :--- | :--- |
| TCP/445 | 1593 |
| 5060 | 1012 |
| 22 | 275 |
| 8333 | 105 |
| 9100 | 65 |
| 445 | 64 |
| 25 | 49 |
| TCP/22 | 44 |
| TCP/80 | 40 |
| 80 | 27 |

### Observed CVEs

The following Common Vulnerabilities and Exposures (CVEs) were detected in the attack traffic. This indicates that attackers are actively trying to exploit these known vulnerabilities.

*   CVE-2021-44228 (Log4Shell)
*   CVE-2019-11500
*   CVE-2021-3449
*   CVE-2019-12263
*   CVE-2019-12261
*   CVE-2019-12260
*   CVE-2019-12255
*   CVE-2002-0013
*   CVE-2002-0012
*   CVE-1999-0517

### Top 10 Credentials Used in Brute-force Attacks

The following are the top 10 username/password combinations observed in brute-force attempts, primarily against the Cowrie (SSH) honeypot.

| **Username/Password** | **Count** |
| :--- | :--- |
| 345gs5662d34/345gs5662d34 | 9 |
| root/Linux@123 | 7 |
| root/3245gs5662d34 | 7 |
| root/nPSpP4PBW0 | 5 |
| test/zhbjETuyMffoL8F | 3 |
| front-user/front-user123 | 2 |
| hduser/hadoop | 2 |
| root/!23QweAsdZxc | 2 |
| sa/ | 2 |
| ester/ester | 2 |

### Top 10 Commands Executed

After gaining access to the Cowrie honeypot, attackers executed a variety of commands. The following table lists the top 10 most frequently observed commands. These commands indicate attempts to escalate privileges, download additional malware, and establish persistence.

| **Command** | **Count** |
| :--- | :--- |
| `cd ~; chattr -ia .ssh; lockr -ia .ssh` | 9 |
| `lockr -ia .ssh` | 9 |
| `cd ~ && rm -rf .ssh && ...` | 9 |
| `system` | 4 |
| `shell` | 4 |
| `q` | 4 |
| `cd /data/local/tmp/; rm *; ...` | 3 |
| `uname -s -v -n -r -m` | 3 |
| `cd /data/local/tmp/; busybox wget ...` | 2 |
| `cat /proc/uptime 2 > /dev/null | cut -d. -f1` | 2 |

## Notes & Limitations

*   The data in this report is sourced from a T-Pot honeypot, which is designed to attract and log automated and opportunistic attacks. The findings may not be representative of targeted attacks against our specific organization.
*   The analysis is based on a short timeframe of approximately 40 minutes and may not reflect long-term trends.
*   The source IP addresses may be spoofed or belong to compromised systems, and should be treated with caution.

This report provides a snapshot of the current threat landscape as seen by our honeypot deployment. Continuous monitoring is recommended to identify emerging threats and patterns.