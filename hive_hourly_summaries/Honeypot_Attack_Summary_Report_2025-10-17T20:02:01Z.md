Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-17T20:01:33Z
**Timeframe:** 2025-10-17T19:20:01Z to 2025-10-17T20:00:01Z
**Files Used:**
- agg_log_20251017T192001Z.json
- agg_log_20251017T194001Z.json
- agg_log_20251017T200001Z.json

**Executive Summary:**
This report summarizes 10,971 events collected from the honeypot network over a period of approximately 40 minutes. The majority of attacks were captured by the Cowrie, Honeytrap, and Suricata honeypots. A significant amount of scanning and exploitation activity was observed, with a large number of events related to the DoublePulsar backdoor. The most targeted ports were 5060 (SIP) and 445 (SMB).

**Detailed Analysis:**

**Attacks by Honeypot:**
- Cowrie: 3011
- Honeytrap: 2246
- Suricata: 2007
- Sentrypeer: 1048
- Dionaea: 1001
- Ciscoasa: 960
- ElasticPot: 564
- Tanner: 46
- H0neytr4p: 38
- ConPot: 13
- Adbhoney: 13
- Miniprint: 9
- Mailoney: 7
- Redishoneypot: 6
- Honeyaml: 2

**Top Attacking IPs:**
- 72.146.232.13: 912
- 186.10.24.214: 794
- 196.251.80.29: 431
- 172.86.95.115: 390
- 172.86.95.98: 371

**Top Targeted Ports/Protocols:**
- 5060: 1048
- 445: 938
- TCP/445: 905
- 22: 629
- 9200: 564

**Most Common CVEs:**
- CVE-1999-0183
- CVE-2002-0013
- CVE-2002-0012
- CVE-2021-35394
- CVE-2019-11500
- CVE-1999-0517

**Commands Attempted by Attackers:**
- `cd ~; chattr -ia .ssh; lockr -ia .ssh`
- `lockr -ia .ssh`
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."`
- `cat /proc/cpuinfo | grep name | wc -l`
- `Enter new UNIX password:`
- `echo "cat /proc/1/mounts && ls /proc/1/; curl2; ps aux; ps" | sh`

**Signatures Triggered:**
- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication: 952
- ET DROP Dshield Block Listed Source group 1: 242
- ET SCAN NMAP -sS window 1024: 122
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 85
- ET INFO Reserved Internal IP Traffic: 49

**Users / Login Attempts (user/pass):**
- centos/centos12345678
- config/config123
- ubnt/ubnt2021
- centos/6666666
- default/default2003
- root/555
- admin/666666
- test/test2021
- nobody/toor

**Files Uploaded/Downloaded:**
- wget.sh;
- w.sh;
- c.sh;
- &currentsetting.htm=1
- ohsitsvegawellrip.sh

**HTTP User-Agents:**
- No user agents were recorded in this timeframe.

**SSH Clients and Servers:**
- SSH Clients: No specific clients recorded.
- SSH Servers: No specific servers recorded.

**Top Attacker AS Organizations:**
- No AS organizations were recorded in this timeframe.

**Key Observations and Anomalies:**
- The high number of events related to the DoublePulsar backdoor (Signature ID 2024766) suggests a targeted campaign or widespread automated exploitation attempts against SMB services.
- Attackers on the Cowrie honeypot frequently attempted to modify SSH authorized_keys to maintain persistent access.
- A wide variety of generic login credentials were attempted, indicating brute-force attacks against common services.
- The commands executed suggest attackers are performing reconnaissance to understand the system architecture and available tools.
