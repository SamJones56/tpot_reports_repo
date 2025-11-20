Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-11T11:01:44Z
**Timeframe:** 2025-10-11T10:20:02Z to 2025-10-11T11:00:01Z
**Files Used:**
- agg_log_20251011T102002Z.json
- agg_log_20251011T104001Z.json
- agg_log_20251011T110001Z.json

**Executive Summary**

This report summarizes honeypot activity over a period of approximately 40 minutes, based on data from three log files. A total of 14,151 attacks were recorded. The most targeted services were SSH (port 22) and HTTP (ports 80, 443, 8080). A significant number of attacks were carried out by a small number of IP addresses, with 209.38.37.15 being the most active. Attackers attempted to exploit several vulnerabilities, with CVEs from 1999 to 2022 being targeted. A variety of commands were executed on the honeypots, including attempts to download and execute malicious files, and to add SSH keys for persistent access.

**Detailed Analysis**

***Attacks by honeypot***
* Cowrie: 4638
* Honeytrap: 4462
* Suricata: 2299
* Ciscoasa: 1935
* H0neytr4p: 294
* Sentrypeer: 185
* Dionaea: 138
* Tanner: 68
* Mailoney: 40
* Adbhoney: 16
* ConPot: 16
* Honeyaml: 15
* Redishoneypot: 15
* Ipphoney: 11
* Miniprint: 10
* Dicompot: 3
* Heralding: 3
* ElasticPot: 3

***Top attacking IPs***
* 209.38.37.15: 455
* 37.204.226.204: 365
* 101.36.113.80: 296
* 103.77.243.109: 295
* 167.71.221.242: 292
* 103.49.238.104: 289
* 110.42.70.108: 276
* 45.121.147.47: 245
* 102.222.184.4: 196
* 129.226.147.146: 123
* 154.221.16.135: 119

***Top targeted ports/protocols***
* 22: 690
* TCP/8080: 335
* 443: 287
* TCP/445: 192
* 5903: 190
* 5060: 185
* TCP/443: 109

***Most common CVEs***
* CVE-2021-3449 CVE-2021-3449: 3
* CVE-2002-0013 CVE-2020-0012: 3
* CVE-2019-11500 CVE-2019-11500: 2
* CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 2
* CVE-2019-12263 CVE-2019-12261 CVE-2019-12260 CVE-2019-12255: 1
* CVE-2005-4050: 1
* CVE-2022-27255 CVE-2022-27255: 1
* CVE-2002-0953: 1

***Commands attempted by attackers***
* `cd ~; chattr -ia .ssh; lockr -ia .ssh`: 25
* `lockr -ia .ssh`: 25
* `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."...`: 25
* `cat /proc/cpuinfo | grep name | wc -l`: 22
* `cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'`: 22

***Signatures triggered***
* ET DROP Dshield Block Listed Source group 1: 461
* 2402000: 461
* ET SCAN MS Terminal Server Traffic on Non-standard Port: 163
* ET SCAN NMAP -sS window 1024: 146
* 2009582: 146

***Users / login attempts***
* 345gs5662d34/345gs5662d34: 24
* root/3245gs5662d34: 12
* root/Ahgf3487@rtjhskl854hd47893@#a4nC: 11
* root/ubuntu: 7
* jenkins/jenkins: 5

***Files uploaded/downloaded***
* config.all.php?: 30
* 11: 5
* fonts.gstatic.com: 5
* `css?family=Libre+Franklin%3A300%2C300i%2C400%2C400i%2C600%2C600i%2C800%2C800i&amp;subset=latin%2Clatin-ext`: 5
* Mozi.m: 4

**Key Observations and Anomalies**

* A significant number of commands were focused on manipulating the `.ssh` directory, indicating a clear intent to establish persistent access to the compromised systems.
* The attackers used a variety of techniques to download and execute malicious payloads, including `wget` and `curl`.
* The presence of commands to gather system information, such as `lscpu` and `free -m`, suggests that attackers are profiling the systems they compromise.
* The wide range of CVEs targeted indicates that attackers are using a broad set of exploits to maximize their chances of success.
* The high number of "ET DROP Dshield Block Listed Source group 1" signatures suggests that many of the attacking IPs are known bad actors.
