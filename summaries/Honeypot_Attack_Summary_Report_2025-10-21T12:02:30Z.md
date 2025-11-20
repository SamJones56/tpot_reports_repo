Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-21T12:01:52Z
**Timeframe:** 2025-10-21T11:20:01Z to 2025-10-21T12:00:01Z
**Files Used:**
- agg_log_20251021T1120:01Z.json
- agg_log_20251021T11:40:01Z.json
- agg_log_20251021T12:00:01Z.json

**Executive Summary**

This report summarizes 14,735 attacks recorded by the honeypot network. The majority of attacks were detected by the Suricata honeypot. The most active attacking IP address was 103.232.245.118, and the most targeted port was TCP/445. Several CVEs were detected, with CVE-2002-0013 and CVE-2002-0012 being the most common. A variety of commands were attempted by attackers, many of which were aimed at system enumeration and establishing persistence.

**Detailed Analysis**

***Attacks by Honeypot***
- Suricata: 5281
- Cowrie: 4586
- Honeytrap: 3785
- Sentrypeer: 551
- Dionaea: 256
- Tanner: 67
- Miniprint: 47
- H0neytr4p: 29
- Mailoney: 32
- Ciscoasa: 30
- Redishoneypot: 21
- Heralding: 21
- Adbhoney: 17
- Honeyaml: 10
- ConPot: 2

***Top Attacking IPs***
- 103.232.245.118
- 103.134.101.87
- 72.146.232.13
- 134.122.45.20
- 196.203.109.209
- 209.141.41.212
- 196.251.115.80
- 107.170.36.5
- 185.243.5.158
- 186.122.177.140

***Top Targeted Ports/Protocols***
- TCP/445
- 22
- 5060
- TCP/1080
- 5903
- UDP/5060
- 2006
- 80
- 5901
- 8333

***Most Common CVEs***
- CVE-2002-0013 CVE-2002-0012
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517
- CVE-2021-3449 CVE-2021-3449
- CVE-2024-4577 CVE-2024-4577
- CVE-2024-4577 CVE-2002-0953
- CVE-2019-11500 CVE-2019-11500
- CVE-2021-41773 CVE-2021-41773 CVE-2021-41773 CVE-2021-41773
- CVE-2021-42013 CVE-2021-42013

***Commands Attempted by Attackers***
- cat /proc/cpuinfo | grep name | wc -l
- cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
- ls -lh $(which ls)
- which ls
- crontab -l
- w
- uname -m
- cat /proc/cpuinfo | grep model | grep name | wc -l
- top
- uname
- uname -a
- whoami
- lscpu | grep Model
- df -h | head -n 2 | awk 'FNR == 2 {print $2;}'
- cd ~; chattr -ia .ssh; lockr -ia .ssh
- lockr -ia .ssh
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."
- Enter new UNIX password:
- /ip cloud print
- uname -s -v -n -r -m
- echo 'SSH check'
- ifconfig
- cat /proc/cpuinfo
- ps | grep '[Mm]iner'
- ps -ef | grep '[Mm]iner'
- ls -la ~/.local/share/TelegramDesktop/tdata /home/*/.local/share/TelegramDesktop/tdata /dev/ttyGSM* /dev/ttyUSB-mod* /var/spool/sms/* /var/log/smsd.log /etc/smsd.conf* /usr/bin/qmuxd /var/qmux_connect_socket /etc/config/simman /dev/modem* /var/config/sms/*
- locate D877F783D5D3EF8Cs
- echo Hi | cat -n

***Signatures Triggered***
- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication
- ET SCAN Sipsak SIP scan
- ET DROP Dshield Block Listed Source group 1
- GPL INFO SOCKS Proxy attempt
- ET SCAN MS Terminal Server Traffic on Non-standard Port
- ET SCAN NMAP -sS window 1024
- ET INFO Reserved Internal IP Traffic
- ET HUNTING RDP Authentication Bypass Attempt
- ET SCAN Potential SSH Scan
- ET SCAN Suspicious inbound to PostgreSQL port 5432

***Users / Login Attempts***
- 345gs5662d34/345gs5662d34
- root/AmsiEscuelA2014
- root/AMTADMINISTRADOR
- odoo17/odoo17
- tmpuser/1234
- root/1234$asdf
- system/Password1
- root/Gj123456
- root/adminHW
- moodle/moodle
- root/amtech*123
- root/amtech123
- local/local1
- postgres/123
- root/ANDMElastix
- root/angel1234
- telecomadmin/admintelecom
- root/l0cat344

***Files Uploaded/Downloaded***
- wget.sh;
- w.sh;
- c.sh;
- sh

***HTTP User-Agents***
- No HTTP User-Agents were logged in this period.

***SSH Clients***
- No SSH clients were logged in this period.

***SSH Servers***
- No SSH servers were logged in this period.

***Top Attacker AS Organizations***
- No attacker AS organizations were logged in this period.

**Key Observations and Anomalies**

- The high number of attacks on TCP/445, along with the "ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication" signature, suggests a significant amount of scanning and exploitation activity related to the EternalBlue vulnerability.
- Attackers are using a variety of generic and default credentials, indicating that they are targeting systems with weak or default passwords.
- The commands attempted by attackers show a clear pattern of system enumeration, checking for system resources, and attempting to establish persistence by adding SSH keys.
- There were several attempts to download and execute shell scripts, indicating that attackers are attempting to install malware on compromised systems.
