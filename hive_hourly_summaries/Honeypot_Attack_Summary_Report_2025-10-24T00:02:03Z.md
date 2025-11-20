Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-24T00:01:32Z
**Timeframe:** 2025-10-23T23:20:01Z to 2025-10-24T00:00:01Z
**Files Used:**
- agg_log_20251023T232001Z.json
- agg_log_20251023T234001Z.json
- agg_log_20251024T000001Z.json

**Executive Summary**

This report summarizes 12,157 events collected from the honeypot network over a period of approximately 40 minutes. The majority of attacks targeted the Dionaea and Cowrie honeypots, with a significant focus on SMB (port 445) and SSH (port 22). The most prolific attacker IP was 114.35.170.253. A number of CVEs were targeted, and attackers attempted a variety of commands, primarily focused on reconnaissance and establishing persistent access.

**Detailed Analysis**

***Attacks by Honeypot***

- Dionaea: 4488
- Cowrie: 3143
- Ciscoasa: 1794
- Honeytrap: 1548
- Suricata: 910
- Sentrypeer: 116
- Redishoneypot: 47
- H0neytr4p: 43
- Tanner: 19
- Miniprint: 15
- Honeyaml: 10
- Mailoney: 9
- ElasticPot: 5
- ssh-rsa: 4
- Heralding: 3
- Adbhoney: 2
- Ipphoney: 1

***Top Attacking IPs***

- 114.35.170.253: 4436
- 80.94.95.238: 489
- 34.122.106.61: 287
- 138.124.20.112: 283
- 157.10.160.102: 273
- 103.250.10.128: 268
- 128.199.168.119: 207
- 186.10.86.130: 194
- 85.133.193.72: 177
- 107.170.36.5: 155
- 68.183.149.135: 112

***Top Targeted Ports/Protocols***

- 445: 4470
- 22: 398
- 5060: 116
- 8333: 104
- 6379: 47
- TCP/445: 45
- TCP/22: 41

***Most Common CVEs***

- CVE-2021-3449 CVE-2021-3449: 5
- CVE-2019-11500 CVE-2019-11500: 3
- CVE-2002-0013 CVE-2002-0012: 1
- CVE-2001-0414: 1
- CVE-2025-34036 CVE-2025-34036: 1

***Commands Attempted by Attackers***

- A variety of shell commands were executed 18 times each, including: `cd ~; chattr -ia .ssh; lockr -ia .ssh`, `lockr -ia .ssh`, `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ... mdrfckr">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~`, `cat /proc/cpuinfo | grep name | wc -l`, `free -m | grep Mem ...`, `ls -lh $(which ls)`, `crontab -l`, `w`, `uname -a`, `whoami`, `lscpu | grep Model`, `df -h | head -n 2 | awk 'FNR == 2 {print $2;}'`, and others.
- `Enter new UNIX password: `: 13
- `Enter new UNIX password:`: 10
- `rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts.deny; pkill -9 sleep;`: 3

***Signatures Triggered***

- ET SCAN MS Terminal Server Traffic on Non-standard Port / 2023753: 223
- ET DROP Dshield Block Listed Source group 1 / 2402000: 178
- ET SCAN NMAP -sS window 1024 / 2009582: 92
- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication / 2024766: 44
- ET INFO Reserved Internal IP Traffic / 2002752: 41
- ET SCAN Potential SSH Scan / 2001219: 27

***Users / Login Attempts***

- 345gs5662d34/345gs5662d34: 18
- User-Agent: Go-http-client/1.1/Connection: close: 15
- root/3245gs5662d34: 3

***Files Uploaded/Downloaded***

- ): 1
- string.js: 1

***HTTP User-Agents***

- None observed.

***SSH Clients and Servers***

- None observed.

***Top Attacker AS Organizations***

- None observed.

**Key Observations and Anomalies**

- The high volume of attacks from a single IP (114.35.170.253) suggests a targeted or automated campaign.
- The commands executed indicate a clear pattern of attempting to gain and maintain persistent access to the compromised system.
- The presence of commands to remove security scripts (`secure.sh`, `auth.sh`) and clear `hosts.deny` indicates a more sophisticated attacker.
- The DoublePulsar backdoor signature indicates potential exploitation of SMB vulnerabilities.
