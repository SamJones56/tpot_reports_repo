Honeypot Attack Summary Report

1.  **Report Information**
    *   **Report ID:** HSR-20250929-001
    *   **Generation Date:** 2025-09-29T12-01-28Z
    *   **Reporting Period:** 2025-09-29T11:20:01Z to 2025-09-29T12:00:01Z
    *   **Data Sources:** `agg_log_20250929T112001Z.json`, `agg_log_20250929T114001Z.json`, `agg_log_20250929T120001Z.json`

2.  **Executive Summary**
    This report summarizes the analysis of honeypot data collected over a period of approximately 40 minutes on September 29, 2025. During this timeframe, a total of 12,337 malicious events were recorded across a distributed network of honeypots. The primary attack vectors observed were SSH brute-force attempts, SMB exploits, and SIP scanning. The majority of attacks originated from IP addresses located in Russia, the United States, and China. A significant number of malware samples were dropped, and several known vulnerabilities were targeted, including Log4Shell (CVE-2021-44228). The findings in this report indicate a high level of automated and opportunistic attacks, which is consistent with the current threat landscape.

3.  **Detailed Analysis**
    The following sections provide a detailed breakdown of the attack data collected during the reporting period.

    *   **Attacks by Honeypot**
        The Cowrie honeypot, which emulates an SSH and Telnet server, recorded the highest number of events, with 3,673 interactions. This was followed by the Honeytrap and Suricata honeypots, which recorded 2,143 and 1,963 events, respectively. The high number of events on Cowrie suggests that SSH brute-force attacks remain a popular method for gaining initial access to systems.

| Honeypot | Events |
| :--- | :--- |
| Cowrie | 3673 |
| Honeytrap | 2143 |
| Suricata | 1963 |
| Ciscoasa | 1452 |
| Dionaea | 1096 |
| Sentrypeer | 998 |
| Mailoney | 827 |
| Tanner | 49 |
| Heralding | 47 |
| H0neytr4p | 40 |
| Adbhoney | 17 |
| Redishoneypot | 14 |
| Ipphoney | 6 |
| ConPot | 4 |
| Honeyaml | 4 |
| ElasticPot | 4 |

    *   **Top Attacking IP Addresses**
        The most aggressive IP address observed was 142.93.159.126, which was responsible for 1,258 events. This was followed by 81.183.253.80 and 45.140.17.52, with 1,014 and 1,013 events, respectively. These three IP addresses accounted for over 25% of all recorded events.

| IP Address | Events |
| :--- | :--- |
| 142.93.159.126 | 1258 |
| 81.183.253.80 | 1014 |
| 45.140.17.52 | 1013 |
| 4.144.169.44 | 955 |
| 208.109.190.200 | 955 |
| 86.54.42.238 | 821 |
| 185.156.73.167 | 374 |
| 185.156.73.166 | 370 |
| 92.63.197.55 | 362 |
| 92.63.197.59 | 337 |

    *   **Top Targeted Ports**
        The most frequently targeted port was 445 (SMB), with 1,017 events. This was followed by port 5060 (SIP) and port 22 (SSH), with 998 and 635 events, respectively. The targeting of port 445 is likely indicative of attempts to exploit SMB vulnerabilities, such as EternalBlue.

| Port | Events |
| :--- | :--- |
| 445 | 1017 |
| 5060 | 998 |
| 25 | 820 |
| 22 | 635 |
| 8333 | 125 |
| 23 | 64 |
| vnc/5900 | 47 |
| 80 | 43 |
| 1433 | 31 |
| 443 | 29 |

    *   **Common Vulnerabilities and Exposures (CVEs) Exploited**
        The most frequently targeted CVE was CVE-2021-44228, also known as Log4Shell. This vulnerability was targeted 43 times during the reporting period. Other targeted CVEs included CVE-2002-0013, CVE-2002-0012, CVE-2021-3449, and CVE-2019-11500.

| CVE | Events |
| :--- | :--- |
| CVE-2021-44228 | 43 |
| CVE-2002-0013, CVE-2002-0012 | 8 |
| CVE-2021-3449 | 5 |
| CVE-2019-11500 | 3 |
| CVE-2002-0013, CVE-2002-0012, CVE-1999-0517 | 1 |

    *   **Top Credentials Used**
        A variety of default and weak credentials were used in brute-force attacks. The most common username and password combination was `sa` with a blank or simple password, which was attempted 20 times. Other common credentials included `345gs5662d34`/`345gs5662d34`, `root`/`Password2025`, and `root`/`Passw0rd`.

| Username/Password | Attempts |
| :--- | :--- |
| sa / (blank) & sa/12345 | 20 |
| 345gs5662d34/345gs5662d34 | 7 |
| root/Password2025 & root/Passw0rd | 6 |
| ubuntu/1234567890 & root/1234567890 | 5 |
| root/3245gs5662d34 & titu/3245gs5662d34 | 4 |
| root/123456qwerty | 2 |
| titu/Ahgf3487@rtjhskl854hd47893@#a4nC | 2 |
| root/zhbjETuyMffoL8F | 2 |
| ubuntu/ubuntu | 2 |
| root/1225 | 2 |

    *   **Top Commands Executed**
        Upon gaining access to a honeypot, attackers executed a variety of commands to enumerate the system and download malware. The most common commands were `uname -a` (to get system information) and a series of commands to modify the `.ssh/authorized_keys` file to maintain persistent access.

| Command | Executions |
| :--- | :--- |
| `cd ~; chattr -ia .ssh; lockr -ia .ssh` | 9 |
| `lockr -ia .ssh` | 9 |
| `cd ~ && rm -rf .ssh && ...` | 9 |
| `uname -a` | 5 |
| `cat /proc/cpuinfo | grep name | wc -l` | 5 |
| `cat /proc/cpuinfo | grep name | head -n 1 | ...` | 5 |
| `free -m | grep Mem | ...` | 5 |
| `ls -lh $(which ls)` | 5 |
| `which ls` | 5 |
| `crontab -l` | 5 |

4.  **Notes and Limitations**
    The data in this report is based on a limited set of honeypots and may not be representative of the entire threat landscape. The report is intended for informational purposes only and should not be used to make decisions about security policies or procedures. It is recommended that organizations use a variety of security tools and techniques to protect their systems from attack.
