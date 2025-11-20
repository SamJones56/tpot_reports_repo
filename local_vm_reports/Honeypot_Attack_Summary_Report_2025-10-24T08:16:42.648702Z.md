**Honeypot Attack Summary Report**

**Report Generation Time:** 2025-10-24T08:00:56.154640Z
**Timeframe:** 2025-10-23T08:00:56.154640Z to 2025-10-24T08:00:56.154640Z

**Data Sources:** Live Elasticstack queries and Google OSINT searches.

### Executive Summary

This report provides a 24-hour overview of attack activity observed across our honeypot network, spanning from 2025-10-23T08:00:56.154640Z to 2025-10-24T08:00:56.154640Z. The network has registered a substantial volume of malicious interactions, predominantly characterized by automated scanning and brute-force attempts. Key findings indicate that honeypots emulating common services like SSH and VNC are heavily targeted, with a notable concentration of activity originating from the United States and Romania. A critical observation is the presence of attempted exploitation related to the DoublePulsar backdoor, a tool associated with significant past cyberattacks, and the continued targeting of known vulnerabilities such as Log4Shell. While direct evidence of zero-day exploits is not conclusively identifiable from the aggregated data, the persistent and varied attack vectors underscore a continuous and evolving threat landscape. The intelligence gathered from this period highlights the prevalence of known attacker infrastructure and the ongoing risk posed by established vulnerabilities.

### Detailed Analysis:

**Our IPs**

| Honeypot Name | Private IP    | Public IP        |
| :------------ | :------------ | :--------------- |
| hive-us       | 10.128.0.3    | 34.123.129.205   |
| sens-tai      | 10.140.0.3    | 104.199.212.115  |
| sens-tel      | 10.208.0.3    | 34.165.197.224   |
| sens-dub      | 172.31.36.128 | 3.253.97.195     |
| sens-ny       | 10.108.0.2    | 161.35.180.163   |

**Attacks by Honeypot**

| Honeypot    | Attack Count |
| :---------- | :----------- |
| Cowrie      | 94886        |
| Sentrypeer  | 81486        |
| Honeytrap   | 81175        |
| Ciscoasa    | 42431        |
| Dionaea     | 35605        |
| Heralding   | 15155        |
| Tanner      | 11360        |
| H0neytr4p   | 6360         |
| Redishoneypot | 638          |
| Mailoney    | 633          |
| ConPot      | 423          |
| Miniprint   | 277          |
| Adbhoney    | 196          |
| ElasticPot  | 179          |
| Honeyaml    | 129          |
| Dicompot    | 74           |
| Ipphoney    | 41           |
| Wordpot     | 5            |
| Medpot      | 2            |

**Top Source Countries**

| Country         | Attack Count |
| :-------------- | :----------- |
| United States   | 101182       |
| Romania         | 71472        |
| The Netherlands | 17228        |
| Ukraine         | 17185        |
| Hong Kong       | 16862        |
| Brazil          | 13541        |
| Indonesia       | 12596        |
| France          | 11791        |
| Vietnam         | 11447        |
| China           | 10582        |

**Top Attacking IPs**

| IP Address      | Attack Count |
| :-------------- | :----------- |
| 2.57.121.61     | 65799        |
| 139.87.113.204  | 16194        |
| 185.243.96.105  | 15252        |
| 45.171.150.123  | 7554         |
| 114.35.170.253  | 6494         |
| 107.170.36.5    | 4958         |
| 113.180.212.88  | 4917         |
| 80.94.95.238    | 4096         |
| 109.205.211.9   | 3956         |
| 167.249.35.48   | 3148         |

**Top Targeted Ports/Protocols**

| Country         | Port | Count |
| :-------------- | :--- | :---- |
| United States   | 80   | 9313  |
| United States   | 443  | 5842  |
| United States   | 5060 | 2482  |
| United States   | 5905 | 1865  |
| United States   | 5904 | 1864  |
| United States   | 22   | 1499  |
| United States   | 5901 | 997   |
| United States   | 5903 | 886   |
| United States   | 5902 | 875   |
| United States   | 5908 | 629   |
| Romania         | 5060 | 65800 |
| Romania         | 22   | 216   |
| Romania         | 17000 | 62    |
| Romania         | 4942 | 18    |
| Romania         | 6036 | 18    |
| Romania         | 5186 | 16    |
| Romania         | 17001 | 16    |
| Romania         | 5470 | 14    |
| Romania         | 5513 | 14    |
| Romania         | 5544 | 14    |
| The Netherlands | 22   | 1836  |
| The Netherlands | 80   | 406   |
| The Netherlands | 23   | 254   |
| The Netherlands | 5060 | 175   |
| The Netherlands | 443  | 118   |
| The Netherlands | 8728 | 118   |
| The Netherlands | 1153 | 90    |
| The Netherlands | 1170 | 90    |
| The Netherlands | 1215 | 90    |
| The Netherlands | 1222 | 90    |
| Ukraine         | 5900 | 15083 |
| Ukraine         | 1157 | 43    |
| Ukraine         | 1171 | 43    |
| Ukraine         | 1177 | 43    |
| Ukraine         | 1182 | 43    |
| Ukraine         | 1195 | 43    |
| Ukraine         | 1229 | 43    |
| Ukraine         | 1252 | 43    |
| Ukraine         | 1253 | 43    |
| Ukraine         | 1265 | 43    |
| Hong Kong       | 5060 | 8407  |
| Hong Kong       | 22   | 558   |
| Hong Kong       | 80   | 102   |
| Hong Kong       | 8000 | 67    |
| Hong Kong       | 9200 | 58    |
| Hong Kong       | 9100 | 57    |
| Hong Kong       | 6379 | 32    |
| Hong Kong       | 1025 | 23    |
| Hong Kong       | 27017 | 23    |
| Hong Kong       | 8265 | 20    |
| Brazil          | 445  | 7554  |
| Brazil          | 986  | 22    |
| Brazil          | 5902 | 16    |
| Brazil          | 23   | 15    |
| Brazil          | 443  | 12    |
| Brazil          | 8008 | 9     |
| Brazil          | 5006 | 8     |
| Brazil          | 8069 | 7     |
| Brazil          | 8100 | 7     |
| Brazil          | 24442 | 7     |
| Indonesia       | 2748 | 445   |
| Indonesia       | 1272 | 22    |
| Indonesia       | 85   | 80    |
| Indonesia       | 10   | 27017 |
| Indonesia       | 9    | 50050 |
| Indonesia       | 7    | 8058  |
| Indonesia       | 7    | 8580  |
| Indonesia       | 4    | 23    |
| Indonesia       | 1    | 1433  |
| Indonesia       | 1    | 4995  |
| France          | 1468 | 5060  |
| France          | 271  | 22    |
| France          | 90   | 1152  |
| France          | 90   | 1164  |
| France          | 90   | 1175  |
| France          | 90   | 1209  |
| France          | 90   | 1217  |
| France          | 90   | 1235  |
| France          | 90   | 1306  |
| France          | 90   | 1340  |
| Vietnam         | 8085 | 445   |
| Vietnam         | 389  | 22    |
| Vietnam         | 86   | 5901  |
| Vietnam         | 40   | 5903  |
| Vietnam         | 39   | 5902  |
| Vietnam         | 39   | 6000  |
| Vietnam         | 36   | 6001  |
| Vietnam         | 36   | 6002  |
| Vietnam         | 9    | 80    |
| Vietnam         | 8    | 50001 |
| China           | 1667 | 22    |
| China           | 226  | 6379  |
| China           | 174  | 80    |
| China           | 152  | 25    |
| China           | 81   | 23    |
| China           | 46   | 2375  |
| China           | 29   | 1433  |
| China           | 25   | 2323  |
| China           | 20   | 8086  |
| China           | 15   | 8001  |

**Most Common CVEs**

| CVE ID                           | Count |
| :------------------------------- | :---- |
| CVE-2006-2369                    | 15086 |
| CVE-2021-44228 CVE-2021-44228    | 1286  |
| CVE-2002-0013 CVE-2002-0012      | 316   |
| CVE-2002-0013 CVE-2002-0012 CVE-1999-0517 | 260   |
| CVE-2002-1149                    | 88    |
| CVE-2006-3602 CVE-2006-4458 CVE-2006-4542 | 80    |
| CVE-2021-3449 CVE-2021-3449      | 73    |
| CVE-2005-4050                    | 63    |
| CVE-2019-11500 CVE-2019-11500    | 60    |
| CVE-2020-14882 CVE-2020-14883 CVE-2020-14882 | 34    |

**Commands attempted by attackers**
No specific command data was aggregated for this 24-hour period from FTP or SMB protocols. This may be due to the nature of the honeypot's interaction or how the command data is logged. Further deep-dive analysis on specific honeypot logs would be required for a more detailed understanding of attempted commands.

**Signatures Triggered**

| Alert ID | Signature                                            | Count |
| :------- | :--------------------------------------------------- | :---- |
| 2100560  | GPL INFO VNC server response                         | 171405 |
| 2100384  | GPL ICMP PING                                        | 33883 |
| 2002923  | ET EXPLOIT VNC Server Not Requiring Authentication (case 2) | 15082 |
| 2002920  | ET INFO VNC Authentication Failure                   | 15081 |
| 2023753  | ET SCAN MS Terminal Server Traffic on Non-standard Port | 14170 |
| 2210051  | SURICATA STREAM Packet with broken ack               | 10510 |
| 2024766  | ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication | 10390 |
| 2402000  | ET DROP Dshield Block Listed Source group 1          | 7155  |
| 2034857  | ET HUNTING RDP Authentication Bypass Attempt         | 5458  |
| 2024897  | ET USER_AGENTS Go HTTP Client User-Agent             | 4123  |

**Users / Login Attempts**

| Username | Count | Password   | Count |
| :------- | :---- | :--------- | :---- |
| root     | 3863  | 123456     | 1317  |
| user     | 549   | 345gs5662d34 | 432   |
| admin    | 408   | 3245gs5662d34 | 427   |
| postgres | 208   | password   | 210   |
| test     | 166   | 123        | 173   |
| ubuntu   | 117   | Password   | 162   |
| oracle   | 100   | 12345678   | 122   |
| git      | 92    | 1234       | 99    |
| mysql    | 72    | 12345      | 90    |
|          |       | admin      | 88    |

**Files Uploaded/Downloaded**
No file upload/download activity (filenames or MD5 hashes) was detected in the reports for this 24-hour period.

**HTTP User-Agents**
No specific HTTP User-Agent data was aggregated for this 24-hour period. This suggests that HTTP-based attacks or reconnaissance during this period did not consistently use specific or notable user-agent strings that were captured in the top 10.

**SSH clients and servers**
No specific SSH client or server software version information was available for aggregation. This may be due to limitations in the data logging or the nature of the SSH connections.

**Top Attacker AS Organizations**

| ASN    | Organization Name                 | Count |
| :----- | :-------------------------------- | :---- |
| 47890  | Unmanaged Ltd                     | 67344 |
| 215540 | Global Connectivity Solutions Llp | 42785 |
| 14061  | DIGITALOCEAN-ASN                  | 23986 |
| 6142   | SUN-JAVA                          | 16194 |
| 48693  | Rices Privately owned enterprise  | 15375 |
| 396982 | GOOGLE-CLOUD-PLATFORM             | 9972  |
| 23470  | RELIABLESITE                      | 8690  |
| 45899  | VNPT Corp                         | 8307  |
| 135377 | UCLOUD INFORMATION TECHNOLOGY HK LIMITED | 7988  |
| 52892  | COPREL TELECOM LTDA               | 7554  |

**OSINT High frequency IPs and Low frequency IPs Captured**

*   **2.57.121.61 (UNMANAGED LTD, Slovakia - AS47890):** Identified as a source of malicious scanning activity, specifically SIP OPTIONS queries, which are often precursors to VoIP system attacks. The associated ASN has a "High" abuse score, indicating a history of problematic activity. The IP is linked to the hostname "smtp61.kcmoa.com".

*   **139.87.113.204 (SUN-JAVA, Tanzania - AS6142):** Flagged for attacks on Industrial Control Systems (ICS), particularly on port 161 (SNMP). TZ-CERT honeypots reported this IP distributing malicious software.

*   **185.243.96.105 (GTT Communications Inc., United States):** Associated with VNC and RDP brute-force and scanning activities on port 5900. It has a low reputation score from Network Entity Reputation Database (NERD).

**OSINT on CVEs**

*   **CVE-2006-2369:** This is a very old vulnerability affecting various products, particularly related to VNC authentication bypass. Its continued presence in attack attempts highlights a focus on legacy systems or unpatched, internet-exposed VNC services.
*   **CVE-2021-44228 (Log4Shell):** This is a critical, high-impact remote code execution vulnerability in the Apache Log4j library. Its detection in honeypot traffic indicates active attempts to exploit this severe flaw, underscoring the ongoing threat even for vulnerabilities with available patches.
*   **CVE-2020-14882 / CVE-2020-14883 (Oracle WebLogic Server):** These CVEs point to vulnerabilities in Oracle WebLogic Server that can allow authenticated attackers to achieve remote code execution. Their presence suggests targeting of enterprise environments running potentially unpatched WebLogic instances.

### Key Observations and Anomalies

1.  **High Volume of Automated Attacks:** The sheer number of attacks, particularly on common services like SSH (Cowrie) and generalized honeypots (Sentrypeer, Honeytrap), indicates widespread automated scanning and botnet activity.
2.  **Concentrated SIP and VNC Activity:** Romania shows a remarkably high concentration of attacks on port 5060 (SIP), while Ukraine exhibits a strong focus on VNC (port 5900). This geographical specialization points to dedicated campaigns targeting these specific protocols.
3.  **Persistence of Legacy Vulnerabilities:** The continued high count of CVE-2006-2369 and older VNC-related alerts signifies that attackers are still actively probing for and attempting to exploit aged, potentially unpatched systems.
4.  **Critical Exploit Attempts (DoublePulsar and Log4Shell):** The detection of "ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication" is a significant concern. DoublePulsar is a known backdoor used in major attacks like WannaCry. Its appearance suggests attempts to deploy or communicate with this backdoor. The presence of CVE-2021-44228 (Log4Shell) also highlights active exploitation attempts against a recently disclosed critical vulnerability, which requires immediate attention for any vulnerable production systems.
5.  **Brute-Force with Common Credentials:** The prevalence of "root" and "user" as usernames, combined with weak passwords like "123456" and "password," confirms that attackers are relying on basic brute-force techniques to gain initial access.
6.  **Cloud Provider and Unmanaged Network Abuse:** Several top attacking ASNs belong to cloud providers (DigitalOcean, Google Cloud Platform) or "unmanaged" services. This aligns with the expectation that attackers leverage virtual infrastructure and potentially compromised machines within these networks for their operations.

### Unusual Attacker Origins - IP addresses from non-traditional sources

While the top attacking countries include the United States, which is a common source of both legitimate and malicious traffic, some of the specific IP addresses and their associated ASNs warrant closer inspection for being "non-traditional" or highly indicative of malicious intent:

*   **2.57.121.61 (UNMANAGED LTD, Slovakia):** The OSINT confirms this IP is registered to "UNMANAGED LTD" in Slovakia with a "High" abuse score. While Slovakia isn't an unheard-of origin, the explicit classification as an "unmanaged" network with a history of abuse makes it a suspicious origin for extensive scanning, particularly for VoIP services.
*   **139.87.113.204 (SUN-JAVA, Tanzania):** The Tanzanian origin in conjunction with documented ICS attacks on SNMP (port 161) is particularly unusual. Tanzania is not typically a primary hub for cyberattack origination, and targeting ICS suggests a specific, potentially state-sponsored or highly motivated actor. The TZ-CERT report specifically calling out this IP and its association with malicious software distribution further emphasizes its atypical and concerning nature.

The presence of these IPs from less conventional or "unmanaged" network segments, coupled with their specific malicious activities and high abuse scores, indicates that attackers are utilizing diverse and sometimes obscure infrastructure to conduct their operations. This makes attribution and blocking more challenging but highlights the value of honeypots in identifying these sources.

**ZeroDay Fingerprints Analysis:**

The aggregated data from the honeypots and OSINT searches primarily reveals exploitation attempts against **known vulnerabilities** (e.g., CVE-2006-2369, Log4Shell, Oracle WebLogic CVEs) and **known attack patterns** (VNC scanning, SIP OPTIONS queries, DoublePulsar communication).

There is **no conclusive evidence of zero-day exploits** directly identifiable within this 24-hour reporting period. Zero-day attacks are characterized by the exploitation of previously unknown vulnerabilities. Identifying such attacks would typically require:

*   Detection of highly unusual or never-before-seen network traffic patterns.
*   Execution of shellcode or commands that bypass known security mechanisms and do not correspond to publicly documented exploits.
*   Analysis of unique malware payloads that are not detected by existing signatures.

Given that the searches for `payload_printable`, `http.user_agent`, `ftp.command`, `smb.command`, `files.filename`, and `files.md5` did not yield any significant or anomalous results in the top 10 buckets, we lack the granular data necessary to confidently assert the presence of a zero-day fingerprint. The observed activity largely falls into categories of common reconnaissance, brute-force, and exploitation of well-documented vulnerabilities. While the "Misc Attack" category and high "Misc activity" alert count could potentially hide novel attack vectors, without further deep-dive analysis into the raw logs and packet captures, a definitive conclusion regarding zero-day exploitation is not possible at this level of aggregation.