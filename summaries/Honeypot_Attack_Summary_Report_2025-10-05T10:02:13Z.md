**Honeypot Attack Summary Report**

**Report Generation Time:** 2025-10-05T10:01:40Z
**Timeframe:** 2025-10-05T09:20:01Z to 2025-10-05T10:00:02Z
**Files Used:**
- `agg_log_20251005T092001Z.json`
- `agg_log_20251005T094001Z.json`
- `agg_log_20251005T100002Z.json`

**Executive Summary**

This report summarizes honeypot activity over a 40-minute period, based on data from three log files. A total of 13,835 attacks were recorded. The most targeted services were SSH (Cowrie) and email (Mailoney). A significant amount of traffic was also observed on SMB (port 445). The most prominent attack vector appears to be brute-force login attempts and exploitation of known vulnerabilities. The most frequently observed CVE was CVE-2005-4050.

**Detailed Analysis**

***Attacks by Honeypot:***
*   Cowrie: 4763
*   Suricata: 3521
*   Mailoney: 2468
*   Ciscoasa: 1430
*   Dionaea: 545
*   Sentrypeer: 468
*   Honeytrap: 388
*   Redishoneypot: 71
*   H0neytr4p: 48
*   Adbhoney: 33
*   ssh-rsa: 30
*   Tanner: 29
*   Honeyaml: 26
*   ConPot: 7
*   Dicompot: 4
*   Heralding: 3
*   Wordpot: 1

***Top Attacking IPs:***
*   176.65.141.117: 1640
*   78.166.116.158: 1316
*   118.194.230.211: 783
*   92.51.75.246: 713
*   42.112.80.183: 375
*   86.54.42.238: 821
*   45.155.103.70: 214
*   167.172.111.7: 313
*   157.66.34.56: 313
*   103.210.21.178: 316
*   206.189.131.118: 330
*   205.185.115.224: 257
*   103.189.235.65: 287
*   198.12.68.114: 218
*   152.32.144.167: 158
*   91.229.245.46: 219
*   40.83.182.122: 228
*   81.192.87.130: 163
*   191.242.105.131: 150

***Top Targeted Ports/Protocols:***
*   TCP/445: 2556
*   25: 2468
*   22: 740
*   5060: 468
*   TCP/5900: 280
*   6379: 68
*   23: 57
*   UDP/5060: 86
*   443: 48
*   80: 38
*   27017: 21

***Most Common CVEs:***
*   CVE-2005-4050: 81
*   CVE-2002-0013 CVE-2002-0012: 16
*   CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 11
*   CVE-2024-4577 CVE-2024-4577: 2
*   CVE-2024-4577 CVE-2002-0953: 2
*   CVE-2021-3449 CVE-2021-3449: 2
*   CVE-2021-41773 CVE-2021-41773 CVE-2021-41773 CVE-2021-41773: 1
*   CVE-2021-42013 CVE-2021-42013: 1

***Commands Attempted by Attackers:***
*   `cd ~; chattr -ia .ssh; lockr -ia .ssh`: 21
*   `lockr -ia .ssh`: 21
*   `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."`: 21
*   `uname -a`: 16
*   `cat /proc/cpuinfo | grep name | wc -l`: 15
*   `Enter new UNIX password: `: 9
*   `Enter new UNIX password:`: 9

***Signatures Triggered:***
*   ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication / 2024766: 2062
*   ET DROP Dshield Block Listed Source group 1 / 2402000: 324
*   ET DROP Spamhaus DROP Listed Traffic Inbound group 41 / 2400040: 291
*   ET SCAN NMAP -sS window 1024 / 2009582: 122
*   ET VOIP MultiTech SIP UDP Overflow / 2003237: 81
*   ET INFO Reserved Internal IP Traffic / 2002752: 56

***Users / Login Attempts:***
*   345gs5662d34/345gs5662d34: 21
*   root/nPSpP4PBW0: 15
*   root/2glehe5t24th1issZs: 11
*   root/LeitboGi0ro: 9
*   novinhost/novinhost.org: 11
*   test/3245gs5662d34: 10

***Files Uploaded/Downloaded:***
*   sh: 90
*   wget.sh;: 12
*   w.sh;: 3
*   c.sh;: 3

***HTTP User-Agents:***
*   No user agents recorded in this period.

***SSH Clients:***
*   No SSH clients recorded in this period.

***SSH Servers:***
*   No SSH servers recorded in this period.

***Top Attacker AS Organizations:***
*   No AS organizations recorded in this period.

**Key Observations and Anomalies**

*   A high number of attacks are attributed to a small number of IP addresses, suggesting targeted attacks or botnet activity.
*   The `DoublePulsar Backdoor` signature was triggered an exceptionally high number of times, indicating a significant number of attempts to exploit this vulnerability.
*   The commands executed by attackers are typical of initial reconnaissance and establishing persistence, such as gathering system information and adding SSH keys.
*   No data for HTTP User-Agents, SSH clients/servers, and AS organizations were present in the logs for this period. This could be due to the nature of the attacks or a gap in logging.

This concludes the Honeypot Attack Summary Report for this period.