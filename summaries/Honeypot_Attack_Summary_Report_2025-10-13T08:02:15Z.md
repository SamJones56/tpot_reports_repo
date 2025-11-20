Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-13T08:01:28Z
**Timeframe:** 2025-10-13T07:20:01Z to 2025-10-13T08:00:01Z
**Files Used:**
- agg_log_20251013T072001Z.json
- agg_log_20251013T074001Z.json
- agg_log_20251013T080001Z.json

**Executive Summary**

This report summarizes 16,209 malicious events recorded across the honeypot network. The most targeted services were SMB (TCP/445) and SSH (TCP/22). The majority of attacks were detected by the Suricata and Cowrie honeypots. A significant portion of the traffic originated from IP addresses 218.1.29.254 and 183.197.133.58. A large number of alerts for the "DoublePulsar Backdoor" were triggered, indicating attempts to exploit the EternalBlue vulnerability. Additionally, there were numerous attempts to add a malicious SSH key to the `authorized_keys` file.

**Detailed Analysis**

***Attacks by Honeypot***
- Cowrie: 5782
- Suricata: 5499
- Ciscoasa: 1825
- Mailoney: 851
- Sentrypeer: 800
- Dionaea: 784
- Heralding: 307
- Honeytrap: 180
- Tanner: 88
- H0neytr4p: 47
- Adbhoney: 23
- Redishoneypot: 9
- Honeyaml: 7
- ConPot: 2
- Ipphoney: 2
- Dicompot: 3

***Top Attacking IPs***
- 218.1.29.254: 1362
- 183.197.133.58: 1386
- 31.173.84.68: 1360
- 203.78.147.68: 1513
- 86.54.42.238: 820
- 95.170.68.246: 461
- 46.32.178.190: 377
- 178.255.151.130: 301
- 172.31.36.128: 304
- 221.121.100.32: 586
- 67.71.55.75: 381
- 62.141.43.183: 323
- 118.193.46.102: 218
- 200.196.50.91: 277
- 172.86.95.98: 225
- 172.86.95.115: 227
- 137.184.111.54: 243
- 118.26.36.241: 139
- 113.164.66.10: 129
- 103.159.199.42: 183

***Top Targeted Ports/Protocols***
- TCP/445: 4099
- 22: 910
- 25: 851
- 5060: 800
- 445: 714
- vnc/5900: 301
- 80: 90
- TCP/22: 75
- TCP/5432: 47
- 443: 45
- 135: 12
- 23: 22
- TCP/80: 49
- TCP/8080: 13
- UDP/161: 15

***Most Common CVEs***
- CVE-2002-0013 CVE-2002-0012: 10
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 7
- CVE-2005-4050: 4
- CVE-2024-4577 CVE-2002-0953: 2
- CVE-2024-4577 CVE-2024-4577: 2
- CVE-2021-41773 CVE-2021-41773 CVE-2021-41773 CVE-2021-41773: 1
- CVE-2021-42013 CVE-2021-42013: 1

***Commands Attempted by Attackers***
- `cat /proc/cpuinfo | grep name | wc -l`: 20
- `cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'`: 20
- `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`: 20
- `which ls`: 20
- `ls -lh $(which ls)`: 20
- `crontab -l`: 20
- `w`: 20
- `uname -m`: 20
- `cat /proc/cpuinfo | grep model | grep name | wc -l`: 20
- `top`: 20
- `uname`: 19
- `uname -a`: 19
- `whoami`: 19
- `lscpu | grep Model`: 19
- `df -h | head -n 2 | awk 'FNR == 2 {print $2;}'`: 19
- `cd ~; chattr -ia .ssh; lockr -ia .ssh`: 19
- `lockr -ia .ssh`: 19
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ... mdrfckr">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~`: 19
- `Enter new UNIX password: `: 13
- `Enter new UNIX password:`: 11
- `uname -s -v -n -r -m`: 4

***Signatures Triggered***
- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication: 4090
- 2024766: 4090
- ET DROP Dshield Block Listed Source group 1: 300
- 2402000: 300
- ET INFO VNC Authentication Failure: 300
- 2002920: 300
- ET SCAN NMAP -sS window 1024: 160
- 2009582: 160
- ET SCAN Potential SSH Scan: 65
- 2001219: 65
- ET INFO Reserved Internal IP Traffic: 51
- 2002752: 51
- ET SCAN Suspicious inbound to PostgreSQL port 5432: 30
- 2010939: 30
- ET CINS Active Threat Intelligence Poor Reputation IP group 44: 22
- 2403343: 22
- ET CINS Active Threat Intelligence Poor Reputation IP group 47: 17
- 2403346: 17
- ET CINS Active Threat Intelligence Poor Reputation IP group 49: 8
- 2403348: 8
- GPL SNMP request udp: 8
- 2101417: 8
- ET CINS Active Threat Intelligence Poor Reputation IP group 50: 11
- 2403349: 11

***Users / Login Attempts***
- 345gs5662d34/345gs5662d34: 19
- admin1234/admin1234: 6
- holu/holu: 6
- mega/123: 5
- deploy/123123: 5
- vpn/vpnpass: 5
- ubnt/ubnt2024: 4
- root/3245gs5662d34: 6
- ubnt/letmein: 4
- test/test2017: 4
- ftpuser/ftppassword: 6
- root/mgknight: 5

***Files Uploaded/Downloaded***
- sh: 98
- wget.sh;: 4
- discovery: 2
- w.sh;: 1
- c.sh;: 1
- soap-envelope: 1
- soap-encoding: 1
- addressing: 1
- a:ReplyTo><a:To: 1
- wsdl: 1
- no_avatar-849f9c04a3a0d0cea2424ae97b27447dc64a7dbfae83c036c45b403392f0e8ba.png: 1
- 172.20.254.127: 1
- 11: 1
- fonts.gstatic.com: 1
- css?family=Libre+Franklin%3A300%2C300i%2C400%2C400i%2C600%2C600i%2C800%2C800i&amp;subset=latin%2Clatin-ext: 1
- ie8.css?ver=1.0: 1
- html5.js?ver=3.7.3: 1

***HTTP User-Agents***
- None observed

***SSH Clients***
- None observed

***SSH Servers***
- None observed

***Top Attacker AS Organizations***
- None observed

**Key Observations and Anomalies**

- A large number of attacks are attempting to exploit the EternalBlue vulnerability, as indicated by the "DoublePulsar Backdoor" signature.
- There is a persistent campaign to compromise the honeypots by adding a specific SSH key to the `authorized_keys` file. This indicates a targeted effort to gain persistent access.
- Attackers are frequently using system reconnaissance commands like `uname`, `lscpu`, and `cat /proc/cpuinfo` to identify the environment they are in.
- The most frequent login attempt is with the username/password combination `345gs5662d34/345gs5662d34`.

This concludes the Honeypot Attack Summary Report.