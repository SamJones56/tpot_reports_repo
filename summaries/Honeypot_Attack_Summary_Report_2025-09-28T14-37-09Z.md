**Honeypot Attack Summary Report**

**1. Report Information**

*   **Report ID:** HSR-20250928-143556
*   **Generation Date:** 2025-09-28T14-35-56Z
*   **Reporting Period:** 2025-09-28T14:14:01Z to 2025-09-28T14:34:34Z
*   **Data Sources:** 
    *   `agg_log_20250928T141401Z.json`
    *   `agg_log_20250928T142858Z.json`
    *   `agg_log_20250928T143434Z.json`
*   **Analyst:** Summary Agent

**2. Executive Summary**

This report summarizes a total of 8,501 malicious activities recorded across a distributed honeypot network during a brief but intense 20-minute period on September 28, 2025. The data indicates a high volume of automated attacks, with a significant focus on exploiting common vulnerabilities and weak credentials.

The most prominent activity was observed on the `Honeytrap` and `Cowrie` honeypots, which collectively accounted for over half of all recorded events. This suggests a prevalence of attacks targeting various network services and SSH environments. A significant number of intrusion attempts were also detected by `Suricata` and `Ciscoasa` honeypots, highlighting the continuous scanning and exploitation attempts against network security appliances and web servers.

Attack origins are globally distributed, with the top attacking IP addresses originating from various countries. The most frequent attacks targeted ports commonly associated with SMB (445/TCP), SIP (5060/UDP), and SSH (22/TCP), indicating a focus on both reconnaissance and brute-force access attempts.

Several CVEs were observed being actively exploited, most notably `CVE-2005-4050`. Analysis of payloads and commands executed on the honeypots reveals attackers' intent to establish persistent access, expand their foothold, and incorporate compromised devices into botnets.

This report provides a detailed analysis of the observed threats, offering insights into the tactics, techniques, and procedures (TTPs) employed by adversaries in the current threat landscape.

**3. Detailed Analysis**

**3.1. Attacks by Honeypot**

The following table details the distribution of attacks across the various honeypots deployed in the network. `Honeytrap`, `Cowrie`, `Suricata`, and `Ciscoasa` were the most engaged honeypots, indicating a high level of interest from attackers in a diverse range of services.

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

**3.2. Top 20 Attacking IP Addresses**

The following IP addresses were the most active during the reporting period. These IPs were responsible for a significant portion of the total attack volume, suggesting automated scanning and exploitation activities.

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

**3.3. Top 20 Destination Ports**

The most targeted ports provide insight into the services attackers are actively seeking to exploit. The high number of attempts on ports 445, 5060, and 22 align with common attack vectors such as SMB exploits, SIP enumeration, and SSH brute-forcing.

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

**3.4. CVEs Exploited**

A number of vulnerabilities were targeted during the observation period. The consistent targeting of older CVEs alongside newer ones indicates that attackers rely on a broad set of exploits, assuming many systems remain unpatched.

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

**3.5. Top Credentials Used in Attacks**

The credentials listed below were frequently used in brute-force attempts, primarily against the `Cowrie` (SSH) honeypot. The list is dominated by default, weak, and commonly used username/password combinations.

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
| root/3245gs5662d34            | 2        |
| satya/satya123                | 2        |
| eis/eis123                    | 2        |
| root/Aa@1234567               | 2        |
| emma/emma123                  | 2        |
| root/adminHW                  | 2        |
| admin/123123                  | 1        |
| admin/111111                  | 1        |
| admin/password1               | 1        |
| admin/P@ssw0rd                | 1        |

**3.6. Top Commands Executed**

Upon gaining access to a shell, attackers executed a series of commands to perform reconnaissance, disable security measures, and download additional malware. The frequent use of `chattr` and manipulation of `.ssh/authorized_keys` is a clear indicator of attempts to establish persistence.

| Command                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   | Count |
|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-------|
| `cd ~; chattr -ia .ssh; lockr -ia .ssh`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      | 13    |
| `lockr -ia .ssh`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          | 13    |
| `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~` | 13    |
| `cat /proc/cpuinfo | grep name | wc -l`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      | 10    |
| `cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                | 10    |
| `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 | 10    |
| `ls -lh $(which ls)`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         | 10    |
| `which ls`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  | 10    |
| `crontab -l`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                | 10    |
| `w`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         | 10    |
| `uname -m`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  | 10    |
| `cat /proc/cpuinfo | grep model | grep name | wc -l`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         | 10    |
| `top`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       | 10    |
| `uname`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     | 10    |
| `uname -a`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  | 10    |
| `whoami`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    | 10    |
| `lscpu | grep Model`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        | 10    |
| `Enter new UNIX password: `                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 | 8     |
| `Enter new UNIX password:`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  | 8     |
| `df -h | head -n 2 | awk 'FNR == 2 {print $2;}'`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             | 8     |

**4. Notes and Limitations**

*   The data presented in this report is derived exclusively from a network of honeypots. Honeypots are designed to be attractive targets and may not fully represent the entirety of an organization's attack surface or the full spectrum of real-world threats.
*   The analysis is based on a very short timeframe (approximately 20 minutes). While the volume of data is high, it should be considered a snapshot of activity and may not reflect long-term trends.
*   IP address attribution can be misleading due to the use of proxies, VPNs, and compromised systems by attackers. The locations associated with these IPs should be considered indicators rather than definitive proof of an attacker's physical location.
*   The classification of events and attacks is based on the signatures and heuristics of the honeypot and intrusion detection systems, which may be subject to false positives or negatives.

**End of Report**