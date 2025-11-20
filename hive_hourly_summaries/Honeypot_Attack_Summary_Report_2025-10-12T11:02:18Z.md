Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-12T11:01:54Z
**Timeframe:** 2025-10-12 10:20:01Z to 2025-10-12 11:00:01Z
**Log Files:**
- agg_log_20251012T102001Z.json
- agg_log_20251012T104001Z.json
- agg_log_20251012T110001Z.json

**Executive Summary**

This report summarizes honeypot activity over a period of approximately 40 minutes. A total of 28,149 attacks were recorded across various honeypots. The most targeted services were on ports 5038 and 445. The majority of attacks were initiated from the IP address 173.239.216.40. A number of CVEs were targeted, and attackers attempted to run various commands, including efforts to add their SSH keys for persistent access.

**Detailed Analysis**

***Attacks by Honeypot:***
- Honeytrap: 9,417
- Cowrie: 8,097
- Dionaea: 6,381
- Ciscoasa: 1,682
- Suricata: 1,285
- Sentrypeer: 1,057
- Mailoney: 107
- Redishoneypot: 47
- Tanner: 24
- H0neytr4p: 16
- Honeyaml: 15
- Adbhoney: 9
- Dicompot: 6
- ElasticPot: 4
- ConPot: 2

***Top Attacking IPs:***
- 173.239.216.40
- 202.88.244.34
- 40.90.161.91
- 223.100.22.69
- 45.128.199.212

***Top Targeted Ports/Protocols:***
- 5038
- 445
- 22
- 5060
- TCP/21

***Most Common CVEs:***
- CVE-2002-0013 CVE-2002-0012
- CVE-2019-11500 CVE-2019-11500
- CVE-2021-3449 CVE-2021-3449
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517
- CVE-2005-4050
- CVE-2022-27255 CVE-2022-27255

***Commands Attempted by Attackers:***
- cd ~; chattr -ia .ssh; lockr -ia .ssh
- lockr -ia .ssh
- uname
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ... mdrfckr">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~
- uname -a

***Signatures Triggered:***
- ET DROP Dshield Block Listed Source group 1
- ET SCAN NMAP -sS window 1024
- ET FTP FTP PWD command attempt without login
- ET FTP FTP CWD command attempt without login
- ET INFO Reserved Internal IP Traffic

***Users / Login Attempts:***
- cron/
- 345gs5662d34/345gs5662d34
- Enter new UNIX password:
- Enter new UNIX password:
- root/3245gs5662d34

***Files Uploaded/Downloaded:***
- arm.urbotnetisass;
- arm.urbotnetisass
- arm5.urbotnetisass;
- arm5.urbotnetisass
- arm6.urbotnetisass;
- arm6.urbotnetisass
- arm7.urbotnetisass;
- arm7.urbotnetisass
- x86_32.urbotnetisass;
- x86_32.urbotnetisass
- mips.urbotnetisass;
- mips.urbotnetisass
- mipsel.urbotnetisass;
- mipsel.urbotnetisass
- )

***HTTP User-Agents:***
- No user agents recorded.

***SSH Clients and Servers:***
- No SSH clients or servers recorded.

***Top Attacker AS Organizations:***
- No attacker AS organizations recorded.

**Key Observations and Anomalies**

- A significant number of commands are focused on reconnaissance (e.g., `uname`, `lscpu`, `whoami`) and establishing persistence by adding an SSH key to `authorized_keys`.
- The file downloads observed (`.urbotnetisass`) suggest an attempt to install a botnet client on the compromised system.
- The high number of attacks on ports 5038 and 445 indicates widespread scanning for specific vulnerabilities or services.
- A large number of login attempts used common or default credentials, such as `cron/`, `root/`, and `admin/`.
- The attackers appear to be automated, given the high volume and repetitive nature of the attacks.
- No HTTP User-Agents, SSH clients, or server versions were recorded in this period, which might indicate that the attacks did not reach a stage where this information would be logged, or that the honeypots did not capture this information.
