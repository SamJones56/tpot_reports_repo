Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-06T12:01:22Z
**Timeframe:** 2025-10-06T11:20:01Z to 2025-10-06T12:00:01Z
**Files:** agg_log_20251006T112001Z.json, agg_log_20251006T114002Z.json, agg_log_20251006T120001Z.json

### Executive Summary
This report summarizes 16,122 events collected from T-Pot honeypots over a 40-minute period. The majority of attacks were captured by the Cowrie and Sentrypeer honeypots. The most prominent attack vector was via port 5060, with the top attacking IP address being 108.174.63.94. A number of CVEs were detected, with CVE-2021-44228 (Log4j) being the most common. A significant number of commands were attempted by attackers, primarily focused on reconnaissance and establishing persistent access.

### Detailed Analysis

**Attacks by honeypot:**
* Cowrie: 7118
* Sentrypeer: 2181
* Suricata: 2472
* Honeytrap: 1502
* Ciscoasa: 1242
* Mailoney: 865
* Dionaea: 477
* H0neytr4p: 64
* Adbhoney: 31
* Heralding: 47
* Redishoneypot: 54
* Tanner: 35
* ElasticPot: 9
* ssh-rsa: 8
* Honeyaml: 9
* ConPot: 4
* Dicompot: 3
* Ipphoney: 1

**Top attacking IPs:**
* 108.174.63.94
* 222.89.237.42
* 8.219.248.7
* 176.65.141.117
* 170.64.159.245
* 198.98.56.227
* 104.244.74.84
* 114.242.9.121
* 37.120.247.172
* 101.47.5.97
* 172.86.95.98
* 103.234.151.178
* 37.120.247.198
* 171.249.153.209
* 192.250.226.151
* 103.52.114.138
* 147.50.103.212
* 43.160.193.23
* 103.59.94.62
* 185.81.152.174

**Top targeted ports/protocols:**
* 5060
* 22
* TCP/445
* 445
* 25
* 8333
* 5902
* 5903
* vnc/5900
* 3306
* 6379
* 80
* TCP/80
* 443
* 23
* 9090
* 8888
* 8123
* TCP/8080
* 8002

**Most common CVEs:**
* CVE-2021-44228
* CVE-2002-0013
* CVE-2002-0012
* CVE-1999-0517
* CVE-2023-26801
* CVE-2024-3721
* CVE-2018-11776
* CVE-2021-35394
* CVE-2016-6563

**Commands attempted by attackers:**
* cd ~; chattr -ia .ssh; lockr -ia .ssh
* lockr -ia .ssh
* cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ... mdrfckr">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~
* cat /proc/cpuinfo | grep name | wc -l
* Enter new UNIX password:
* Enter new UNIX password:
* cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
* free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
* ls -lh $(which ls)
* which ls
* crontab -l
* w
* uname -m
* cat /proc/cpuinfo | grep model | grep name | wc -l
* top
* uname
* uname -a
* whoami
* lscpu | grep Model
* df -h | head -n 2 | awk 'FNR == 2 {print $2;}'
* tftp; wget; /bin/busybox FZZNK

**Signatures triggered:**
* ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication
* ET DROP Dshield Block Listed Source group 1
* ET SCAN NMAP -sS window 1024
* ET INFO Reserved Internal IP Traffic
* ET INFO VNC Authentication Failure
* ET SCAN MS Terminal Server Traffic on Non-standard Port
* ET DROP Spamhaus DROP Listed Traffic Inbound group 28
* ET CINS Active Threat Intelligence Poor Reputation IP group 68
* GPL SNMP request udp
* ET INFO CURL User Agent
* ET CINS Active Threat Intelligence Poor Reputation IP group 69
* GPL SNMP public access udp
* ET WEB_SERVER Possible HTTP 404 XSS Attempt (Local Source)
* ET DROP Spamhaus DROP Listed Traffic Inbound group 32
* ET VOIP REGISTER Message Flood UDP
* ET HUNTING RDP Authentication Bypass Attempt
* ET DROP Spamhaus DROP Listed Traffic Inbound group 11

**Users / login attempts:**
* appuser/
* 345gs5662d34/345gs5662d34
* root/
* simple/simple
* simple/3245gs5662d34
* maria/maria123
* isis/isis
* suzanne/suzanne
* enzyme/enzyme@123
* create/create@123
* nicole/123
* nicole/3245gs5662d34
* kim/123
* laura/laura123
* math/math@123
* mgr/mgr@123
* markus/markus@123
* camille/camille123
* mary/123
* inna/inna123

**Files uploaded/downloaded:**
* wget.sh;
* w.sh;
* c.sh;
* 11
* fonts.gstatic.com
* css?family=Libre+Franklin%3A300%2C300i%2C400%2C400i%2C600%2C600i%2C800%2C800i&amp;subset=latin%2Clatin-ext
* ie8.css?ver=1.0
* html5.js?ver=3.7.3
* ?format=json
* soap-envelope
* addressing
* discovery
* env:Envelope>
* `cd
* Mozi.m
* XMLSchema-instance
* XMLSchema
* boatnet.mpsl;

**HTTP User-Agents:**
* No HTTP User-Agents were logged in this timeframe.

**SSH clients:**
* No SSH clients were logged in this timeframe.

**SSH servers:**
* No SSH servers were logged in this timeframe.

**Top attacker AS organizations:**
* No attacker AS organizations were logged in this timeframe.

### Key Observations and Anomalies
* A significant amount of scanning activity was observed on port 5060, suggesting a focus on VoIP infrastructure.
* The commands attempted by attackers indicate a clear pattern of reconnaissance, privilege escalation, and establishing persistence. The repeated use of commands to modify SSH authorized_keys files is particularly noteworthy.
* The high number of events related to the DoublePulsar backdoor suggests that some attackers are attempting to exploit older, unpatched systems.
* The presence of commands related to downloading and executing shell scripts (e.g., `wget.sh`, `w.sh`, `c.sh`) indicates that attackers are attempting to deploy malware on compromised systems.
* The variety of usernames and passwords attempted suggests that attackers are using common credential lists and brute-force techniques.
