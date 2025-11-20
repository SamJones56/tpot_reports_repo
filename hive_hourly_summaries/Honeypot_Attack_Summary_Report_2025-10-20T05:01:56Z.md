Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-20T05:01:35Z
**Timeframe:** Approximately 2025-10-20T04:20:01Z to 2025-10-20T05:00:01Z
**Files Used:**
- agg_log_20251020T042001Z.json
- agg_log_20251020T044001Z.json
- agg_log_20251020T050001Z.json

### Executive Summary
This report summarizes 7,169 attacks recorded across multiple honeypots. The most targeted services were SSH (Cowrie) and SMB/Windows shares (Suricata). A significant portion of the activity originated from the IP address 2.145.46.129, which was linked to exploit attempts for the DoublePulsar backdoor. Attackers predominantly used brute-force techniques against SSH, followed by reconnaissance commands to profile the system. Several CVEs were triggered, indicating attempts to exploit known vulnerabilities.

### Detailed Analysis

**Attacks by Honeypot:**
- Cowrie: 3644
- Honeytrap: 1534
- Suricata: 1224
- Ciscoasa: 487
- Sentrypeer: 116
- Dionaea: 65
- Mailoney: 37
- ConPot: 23
- Tanner: 21
- H0neytr4p: 11
- Dicompot: 3
- ElasticPot: 3
- Honeyaml: 1

**Top Attacking IPs:**
- 2.145.46.129: 618
- 72.146.232.13: 609
- 165.232.88.113: 604
- 108.247.217.156: 232
- 202.4.106.201: 224
- 103.179.217.33: 168
- 64.23.180.137: 168
- 12.189.234.27: 153
- 154.70.102.114: 153
- 114.130.85.36: 136

**Top Targeted Ports/Protocols:**
- 22: 736
- TCP/445: 615
- 8333: 142
- 5060: 112
- 5905: 77
- 5904: 76
- 445: 44
- 8888: 40
- 25: 37
- TCP/22: 23

**Most Common CVEs:**
- CVE-2024-3721
- CVE-2021-3449
- CVE-2019-11500
- CVE-2002-0013
- CVE-2002-0012

**Commands Attempted by Attackers:**
- cd ~; chattr -ia .ssh; lockr -ia .ssh: 20
- lockr -ia .ssh: 20
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ...": 20
- cat /proc/cpuinfo | grep name | wc -l: 6
- cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}': 6
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}': 6
- ls -lh $(which ls): 6
- which ls: 6
- crontab -l: 6
- w: 6

**Signatures Triggered:**
- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication / 2024766: 612
- ET DROP Dshield Block Listed Source group 1 / 2402000: 183
- ET SCAN NMAP -sS window 1024 / 2009582: 76
- ET INFO Reserved Internal IP Traffic / 2002752: 37
- ET SCAN MS Terminal Server Traffic on Non-standard Port / 2023753: 24
- ET SCAN Potential SSH Scan / 2001219: 19
- ET CINS Active Threat Intelligence Poor Reputation IP group 47 / 2403346: 7
- ET CINS Active Threat Intelligence Poor Reputation IP group 44 / 2403343: 7
- ET INFO CURL User Agent / 2002824: 7
- ET CINS Active Threat Intelligence Poor Reputation IP group 43 / 2403342: 9

**Users / Login Attempts:**
- 345gs5662d34/345gs5662d34: 19
- user01/Password01: 10
- deploy/123123: 8
- user01/3245gs5662d34: 5
- sinusbot/sinusbot: 3
- root/1qazxsw2@: 3
- hendra/123: 3
- centos/qwer1234: 3
- remote/remote: 3
- jordan/123: 2

**Files Uploaded/Downloaded:**
- json: 1
- soap-envelope: 1
- addressing: 1
- discovery: 1
- devprof: 1
- soap:Envelope>: 1

**HTTP User-Agents:**
- No user agents recorded.

**SSH Clients and Servers:**
- No specific SSH clients or servers recorded.

**Top Attacker AS Organizations:**
- No AS organization data recorded.

### Key Observations and Anomalies
- **High-Volume SMB Exploit Attempts:** A single IP, 2.145.46.129, was responsible for 618 events, all triggering the "DoublePulsar Backdoor" signature. This indicates a targeted campaign to exploit a known SMB vulnerability.
- **Consistent SSH Reconnaissance:** The most common commands are part of a recurring pattern where attackers, after a successful or unsuccessful login, attempt to modify SSH keys and then run a series of commands to profile the system's hardware and configuration.
- **Brute-Force Activity:** The high number of login attempts with common and default credentials across a wide range of usernames (root, deploy, user01, etc.) highlights the persistent nature of automated brute-force attacks against SSH.
- **Diverse Honeypot Engagement:** A wide variety of honeypots were triggered, showing that attackers are scanning for multiple services beyond just SSH, including industrial control systems (ConPot), mail relays (Mailoney), and databases (ElasticPot).
