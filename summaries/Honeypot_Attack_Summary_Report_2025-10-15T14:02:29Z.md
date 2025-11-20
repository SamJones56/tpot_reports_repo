Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-15T14:01:36Z
**Timeframe:** 2025-10-15T13:20:01Z to 2025-10-15T14:00:01Z
**Files Used:**
- agg_log_20251015T132001Z.json
- agg_log_20251015T134001Z.json
- agg_log_20251015T140001Z.json

### Executive Summary
This report summarizes 29,970 attacks recorded by the honeypot network over a 40-minute period. The majority of attacks were detected by the Suricata IDS, with VNC (port 5900) and SMB (port 445) being the most targeted services. A significant number of attacks originated from the IP address 45.134.26.47. Several CVEs were exploited, and attackers attempted a variety of commands, primarily focused on reconnaissance and establishing persistent access.

### Detailed Analysis

**Attacks by Honeypot:**
- Suricata: 7706
- Cowrie: 5002
- Heralding: 5072
- Dionaea: 4182
- Honeytrap: 3467
- Sentrypeer: 2796
- Ciscoasa: 1295
- Redishoneypot: 114
- Miniprint: 94
- Dicompot: 23
- H0neytr4p: 23
- ConPot: 13
- Mailoney: 15
- Tanner: 13
- ElasticPot: 5
- Honeyaml: 6
- Adbhoney: 3
- Sentrypeer: 743
- Ipphoney: 1

**Top Attacking IPs:**
- 45.134.26.47: 5074
- 197.27.124.239: 2999
- 186.96.67.207: 1601
- 45.171.150.123: 1128
- 10.208.0.3: 3071
- 185.243.5.121: 1577
- 10.140.0.3: 1688
- 206.191.154.180: 1166
- 138.197.43.50: 1171
- 172.86.95.98: 424
- 172.86.95.115: 418
- 181.225.64.116: 417
- 36.229.173.39: 292
- 103.126.161.213: 240
- 35.210.61.208: 266
- 10.17.0.5: 185
- 103.181.143.99: 237
- 119.246.15.94: 152
- 62.141.43.183: 206
- 12.156.67.18: 169

**Top Targeted Ports/Protocols:**
- vnc/5900: 5072
- 445: 4136
- TCP/445: 1599
- 5060: 2796
- 22: 743
- 5903: 165
- 8333: 153
- 6379: 111
- 9100: 86
- UDP/5060: 79
- TCP/22: 79
- 1337: 92
- 5908: 74
- 5909: 72
- 5901: 73
- 23: 21
- 25: 16
- 13355: 10
- 2222: 10
- 8000: 18

**Most Common CVEs:**
- CVE-2002-0013 CVE-2002-0012: 3
- CVE-2019-12263 CVE-2019-12261 CVE-2019-12260 CVE-2019-12255: 2
- CVE-2019-11500 CVE-2019-11500: 1
- CVE-2001-0414: 1

**Commands Attempted by Attackers:**
- cd ~; chattr -ia .ssh; lockr -ia .ssh: 22
- lockr -ia .ssh: 22
- cd ~ && rm -rf .ssh && mkdir .ssh && echo ...: 22
- cat /proc/cpuinfo | grep name | wc -l: 22
- cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}': 22
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}': 22
- ls -lh $(which ls): 22
- which ls: 22
- crontab -l: 22
- w: 22
- uname -m: 22
- cat /proc/cpuinfo | grep model | grep name | wc -l: 22
- top: 22
- uname: 21
- uname -a: 20
- whoami: 20
- lscpu | grep Model: 20
- df -h | head -n 2 | awk 'FNR == 2 {print $2;}': 20
- Enter new UNIX password: : 10
- rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; ...: 11
- Enter new UNIX password:: 5
- uname -s -v -n -r -m: 1
- INFO PRODINFO: 1
- echo -e \"password\\nMkN0YNC32fj6\\nMkN0YNC32fj6\"|passwd|bash: 1
- echo \"password\\nMkN0YNC32fj6\\nMkN0YNC32fj6\\n\"|passwd: 1

**Signatures Triggered:**
- ET INFO VNC Authentication Failure: 4942
- 2002920: 4942
- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication: 1595
- 2024766: 1595
- ET DROP Dshield Block Listed Source group 1: 477
- 2402000: 477
- ET SCAN NMAP -sS window 1024: 137
- 2009582: 137
- ET INFO Reserved Internal IP Traffic: 52
- 2002752: 52
- ET SCAN Potential SSH Scan: 43
- 2001219: 43
- ET VOIP Modified Sipvicious Asterisk PBX User-Agent: 36
- 2012296: 36
- ET VOIP Possible Inbound VOIP Scan/Misuse With User-Agent Zoiper: 35
- 2012297: 35
- ET DROP Spamhaus DROP Listed Traffic Inbound group 28: 23
- 2400027: 23
- ET INFO CURL User Agent: 20
- 2002824: 20

**Users / Login Attempts:**
- root/Password@2025: 13
- 345gs5662d34/345gs5662d34: 19
- root/123@@@: 12
- root/Qaz123qaz: 9
- root/3245gs5662d34: 11
- test/2222222: 4
- config/5: 4
- support/22: 6
- unknown/unknown999: 6
- centos/22222: 6
- nobody/nobody2018: 6
- ubnt/ubnt2021: 4
- root/M@Gfh3691: 4
- root/Passw{rd1: 4
- blank/777777: 4
- default/1234567: 4
- unknown/55: 4
- root/*@SS3L179!: 4
- ubnt/ubnt2000: 4
- admin/Right2025: 3

**Files Uploaded/Downloaded:**
- arm.urbotnetisass;: 1
- arm.urbotnetisass: 1
- arm5.urbotnetisass;: 1
- arm5.urbotnetisass: 1
- arm6.urbotnetisass;: 1
- arm6.urbotnetisass: 1
- arm7.urbotnetisass;: 1
- arm7.urbotnetisass: 1
- x86_32.urbotnetisass;: 1
- x86_32.urbotnetisass: 1
- mips.urbotnetisass;: 1
- mips.urbotnetisass: 1
- mipsel.urbotnetisass;: 1
- mipsel.urbotnetisass: 1
- ): 1

**HTTP User-Agents:**
- None Observed

**SSH Clients:**
- None Observed

**SSH Servers:**
- None Observed

**Top Attacker AS Organizations:**
- None Observed

### Key Observations and Anomalies
- The high volume of VNC and SMB traffic suggests widespread scanning for these services.
- The command `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."` indicates attempts to install a persistent SSH key for backdoor access.
- The download of multiple `*.urbotnetisass` files suggests an attempt to infect the system with a botnet, with payloads for various architectures.
- The presence of DoublePulsar related signatures indicates attempts to exploit SMB vulnerabilities, likely related to the EternalBlue exploit.
- The variety of credentials used in brute-force attacks highlights the continued use of common and default passwords.