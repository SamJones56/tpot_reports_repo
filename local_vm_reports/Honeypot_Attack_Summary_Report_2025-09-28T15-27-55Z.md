# Honeypot Attack Summary Report

**Report Generation Time:** 2025-09-28T15-27-10Z
**Timeframe:** 2025-09-28T14:14:01Z to 2025-09-28T14:34:34Z
**Files Used:**
- `Honeypot_Attack_Summary_Report_2025-09-28T14-37-09Z.md`

---

### Executive Summary

This report provides a comprehensive analysis of 8,501 malicious events detected across our distributed honeypot network during a highly active 20-minute period on September 28, 2025. The activity indicates a significant volume of automated and opportunistic attacks, reflecting a broad spectrum of current cyber threats.

The primary targets were services exposed by the `Honeytrap` (various network services) and `Cowrie` (SSH) honeypots, which together absorbed over 51% of all recorded attacks. This highlights a strong focus by adversaries on compromising network services and gaining shell access through brute-force attacks. The `Suricata` and `Ciscoasa` honeypots also recorded substantial activity, indicating widespread network scanning and attempts to exploit web application and firewall vulnerabilities.

Geographically, the attacks originated from a diverse set of countries. Open-source intelligence on the top attacking IP addresses confirms their malicious nature, with IPs such as `185.216.116.99` (Hong Kong) and `91.237.163.113` (Russia) having known histories of involvement in SSH brute-force campaigns and other web-based attacks. Another top attacker, `185.156.73.166` (Netherlands), is linked to RDP probes and ransomware deployment campaigns.

The most frequently targeted ports were `445/TCP` (SMB), `5060/UDP` (SIP), and `22/TCP` (SSH). The high number of attempts on port 5060 aligns with the most commonly observed exploit, `CVE-2005-4050`, a buffer overflow vulnerability in SIP services, suggesting attackers are actively targeting VoIP systems.

Post-compromise activity, captured primarily by the `Cowrie` honeypot, reveals clear attacker objectives. Executed commands show attempts to establish persistence by modifying SSH authorized keys, perform system reconnaissance to identify the environment, and disable security attributes on files. The credential lists show a reliance on default or weak passwords, underscoring the ongoing threat of poor password hygiene.

In summary, the observed activity paints a picture of a relentless, automated threat landscape where attackers continuously scan for vulnerable services, exploit old and new vulnerabilities, and use compromised systems to launch further attacks.

---

### Detailed Analysis

#### Our IPs

| Honeypot | Private IP    | Public IP       |
|----------|---------------|-----------------|
| hive-us  | 10.128.0.3    | 34.123.129.205  |
| sens-tai | 10.140.0.3    | 104.199.212.115 |
| sens-tel | 10.208.0.3    | 34.165.197.224  |
| sens-dub | 172.31.36.128 | 3.253.97.195    |
| sens-ny  | 10.108.0.2    | 161.35.180.163  |

#### Attacks by Honeypot

| Honeypot      | Attack Count | Percentage |
|---------------|--------------|------------|
| Honeytrap     | 2,212        | 26.02%     |
| Cowrie        | 2,181        | 25.66%     |
| Suricata      | 1,510        | 17.76%     |
| Ciscoasa      | 1,489        | 17.52%     |
| Sentrypeer    | 500          | 5.88%      |
| Dionaea       | 469          | 5.52%      |
| Tanner        | 49           | 0.58%      |
| H0neytr4p     | 25           | 0.29%      |
| Adbhoney      | 16           | 0.19%      |
| Redishoneypot | 15           | 0.18%      |
| Mailoney      | 13           | 0.15%      |
| Honeyaml      | 11           | 0.13%      |
| ConPot        | 6            | 0.07%      |
| ElasticPot    | 3            | 0.04%      |
| Ipphoney      | 2            | 0.02%      |
| **Total**     | **8,501**    | **100%**   |

#### Top Source Countries
*(Based on OSINT analysis of top attacking IPs)*
| Country |
|---|
| Hong Kong |
| Russia |
| Indonesia |
| Netherlands |
| Spain |

#### Top Attacking IPs

| IP Address        | Attack Count |
|-------------------|--------------|
| 185.216.116.99    | 484          |
| 91.237.163.113    | 435          |
| 117.102.100.58    | 430          |
| 78.30.2.66        | 442          |
| 185.156.73.166    | 379          |
| 185.156.73.167    | 373          |
| 196.251.72.53     | 372          |
| 92.63.197.55      | 361          |
| 92.63.197.59      | 344          |
| 23.94.26.58       | 306          |
| 198.12.68.114     | 204          |
| 190.108.77.129    | 257          |
| 185.243.5.68      | 126          |
| 130.83.245.115    | 63           |
| 3.130.96.91       | 67           |
| 204.76.203.28     | 66           |
| 185.243.5.21      | 51           |
| 3.143.33.63       | 43           |
| 3.132.23.201      | 39           |
| 198.23.190.58     | 33           |

#### Top Targeted Ports/Protocols

| Port       | Protocol | Attack Count |
|------------|----------|--------------|
| 5060       | TCP/UDP  | 500          |
| 445        | TCP      | 440          |
| UDP/5060   | UDP      | 314          |
| 22         | TCP      | 314          |
| 8333       | TCP      | 86           |
| 80         | TCP      | 53           |
| TCP/80     | TCP      | 25           |
| 22222      | TCP      | 24           |
| 7000       | TCP      | 24           |
| 8888       | TCP      | 21           |
| 5080       | TCP      | 22           |
| 7788       | TCP      | 22           |
| 8729       | TCP      | 20           |
| 11453      | TCP      | 18           |
| 55756      | TCP      | 19           |
| 5709       | TCP      | 18           |
| 9080       | TCP      | 15           |
| 8181       | TCP      | 15           |
| 25         | TCP      | 13           |
| 443        | TCP      | 13           |

#### Most Common CVEs

| CVE ID                                    | Count |
|-------------------------------------------|-------|
| CVE-2005-4050                             | 253   |
| CVE-2022-27255 CVE-2022-27255              | 50    |
| CVE-2021-3449 CVE-2021-3449               | 6     |
| CVE-2019-11500 CVE-2019-11500              | 5     |
| CVE-2002-0013 CVE-2002-0012               | 3     |
| CVE-1999-0265                             | 3     |
| CVE-2019-9621 CVE-2021-2109 CVE-2019-9621 | 2     |
| CVE-2019-9670 CVE-2019-9670               | 2     |
| CVE-2006-2369                             | 2     |

#### Commands Attempted by Attackers

| Command                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   | Count |
|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-------|
| `cd ~; chattr -ia .ssh; lockr -ia .ssh`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      | 13    |
| `lockr -ia .ssh`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          | 13    |
| `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~` | 13    |
| `cat /proc/cpuinfo | grep name | wc -l`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      | 10    |
| `uname -a`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  | 10    |
| `whoami`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    | 10    |
| `w`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         | 10    |

#### Signatures Triggered
*No specific signature data was available in the provided summary.*

#### Users / Login Attempts

| Username/Password             | Attempts |
|-------------------------------|----------|
| 345gs5662d34/345gs5662d34     | 13       |
| root/nPSpP4PBW0               | 4        |
| postfixtester/postfixtester   | 4        |
| johnny/johnny123              | 4        |
| exx/exxact@1                  | 3        |
| exx/3245gs5662d34             | 3        |
| root/LeitboGi0ro              | 3        |
| root/zz123456.                | 3        |
| test/zhbjETuyMffoL8F          | 2        |
| opc/opc123                    | 2        |

#### Files Uploaded/Downloaded
*No specific file transfer data was available in the provided summary.*

#### HTTP User-Agents
*No specific HTTP User-Agent data was available in the provided summary.*

#### SSH Clients and Servers
*No specific SSH version data was available in the provided summary.*

#### Top Attacker AS Organizations
*(Based on OSINT analysis of top attacking IPs)*
| AS Organization | IP Address |
|---|---|
| HongKong Cloud Plus Technology Limited | 185.216.116.99 |
| Systematica LLC | 91.237.163.113 |
| BIZNET NETWORKS | 117.102.100.58 |
| MASMOVIL | 78.30.2.66 |
| Telkom Internet LTD | 185.156.73.166 |

---

### Google Searches

- **CVE-2005-4050**: Research confirmed this is a high-severity buffer overflow vulnerability in the Session Initiation Protocol (SIP) affecting Multi-Tech Systems MultiVOIP devices. The high count of this CVE in the report directly correlates with the frequent targeting of port 5060, indicating a focused campaign against VoIP infrastructure.
- **Threat Intelligence on 185.216.116.99**: This IP, registered in Hong Kong, is flagged by multiple threat intelligence platforms for extensive abuse, including web application attacks and SSH brute-force attempts. This aligns with its position as the top attacker in this report.
- **Threat Intelligence on 91.237.163.113**: This Russian IP (Systematica LLC) is blacklisted and known for engaging in SSH brute-force attacks, corroborating the activity observed against the Cowrie honeypot.
- **Threat Intelligence on 117.102.100.58**: This Indonesian IP (BIZNET NETWORKS) is blacklisted and associated with SSH-based attacks and other suspicious network behavior.
- **Threat Intelligence on 78.30.2.66**: No direct public threat intelligence was found for this IP, which is associated with "static.masmovil.com". However, the high volume of attacks originating from it warrants caution and further monitoring.
- **Threat Intelligence on 185.156.73.166**: This IP from the Netherlands is flagged for malicious port scanning and RDP brute-force attacks, often as a precursor to ransomware deployment.

---

### Notes/Limitations

- The data presented in this report is derived exclusively from a network of honeypots. Honeypots are designed to be attractive targets and may not fully represent the entirety of an organization's attack surface or the full spectrum of real-world threats.
- The analysis is based on a very short timeframe (approximately 20 minutes). While the volume of data is high, it should be considered a snapshot of activity and may not reflect long-term trends.
- IP address attribution can be misleading due to the use of proxies, VPNs, and compromised systems by attackers. The locations associated with these IPs should be considered indicators rather than definitive proof of an attacker's physical location.
- The classification of events and attacks is based on the signatures and heuristics of the honeypot and intrusion detection systems, which may be subject to false positives or negatives.
