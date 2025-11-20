Here is a summary of the aggregated data from the honeypot logs for the specified time period.

### **Honeypot Attack Summary Report**

**Report Generation Time:** 2025-09-30T18:01:27Z
**Timeframe:** 2025-09-30T17:20:02Z to 2025-09-30T18:00:01Z

**Files Used:**
*   agg_log_20250930T172002Z.json
*   agg_log_20250930T174001Z.json
*   agg_log_20250930T180001Z.json

---

### **Executive Summary**

A total of **23,296** events were recorded across the honeypot infrastructure. The majority of these attacks were captured by the **Cowrie** honeypot, indicating a high volume of SSH and Telnet-based brute-force attempts. A significant portion of the attacks originated from IP address **88.214.50.58**. The most frequently targeted port was **22 (SSH)**. Attackers were observed attempting to download and execute malicious scripts, as well as attempting to add their SSH keys to the authorized_keys file.

---

### **Detailed Analysis**

**Attacks by Honeypot:**
*   Cowrie: 16,966
*   Honeytrap: 2,505
*   Suricata: 2,140
*   Ciscoasa: 1,395
*   Adbhoney: 44
*   ElasticPot: 40
*   Tanner: 41
*   H0neytr4p: 29
*   Dionaea: 31
*   Redishoneypot: 18
*   Sentrypeer: 19
*   Mailoney: 21
*   Honeyaml: 14
*   ConPot: 12
*   Miniprint: 16
*   Ipphoney: 3
*   ssh-rsa: 2

**Top Attacking IPs:**
*   88.214.50.58: 844
*   222.253.40.231: 360
*   27.79.43.27: 296
*   45.252.249.158: 269
*   49.49.237.87: 264
*   171.231.194.48: 266
*   122.155.223.9: 255
*   117.102.100.58: 251
*   103.48.84.147: 245
*   103.200.25.197: 240
*   14.224.199.187: 239
*   14.225.220.107: 237
*   165.154.168.234: 237
*   36.95.194.51: 225
*   103.48.84.29: 212
*   103.48.84.20: 208
*   103.130.218.117: 206
*   103.200.25.215: 192
*   103.165.236.29: 178
*   178.128.80.162: 168

**Top Targeted Ports/Protocols:**
*   22: 2,288
*   8333: 91
*   TCP/445: 62
*   80: 47
*   9200: 40
*   23: 30
*   TCP/80: 52
*   15671: 34
*   TCP/22: 43
*   443: 26
*   6001: 13
*   4911: 12
*   TCP/5432: 9
*   6379: 9
*   TCP/3390: 9
*   1443: 16
*   11741: 8
*   TCP/3391: 7
*   TCP/1433: 7
*   1139: 7

**Most Common CVEs:**
*   CVE-2016-5696: 8
*   CVE-2024-1709 CVE-2024-1709: 6
*   CVE-2021-3449 CVE-2021-3449: 4
*   CVE-2024-3721 CVE-2024-3721: 3
*   CVE-2002-0013 CVE-2002-0012: 2
*   CVE-2019-11500 CVE-2019-11500: 2
*   CVE-2019-16920 CVE-2019-16920: 1
*   CVE-2024-12856 CVE-2024-12856 CVE-2024-12885: 1
*   CVE-2014-6271: 1
*   CVE-2023-52163 CVE-2023-52163: 1
*   CVE-2023-47565 CVE-2023-47565: 1
*   CVE-2023-31983 CVE-2023-31983: 1
*   CVE-2024-10914 CVE-2024-10914: 1
*   CVE-2009-2765: 1
*   CVE-2015-2051 CVE-2024-33112 CVE-2022-37056 CVE-2019-10891 CVE-2015-2051: 1
*   CVE-2006-3602 CVE-2006-4458 CVE-2006-4542: 1
*   CVE-2021-42013 CVE-2021-42013: 1
*   CVE-2016-20016 CVE-2016-20016: 1

**Commands Attempted by Attackers:**
*   `cd ~; chattr -ia .ssh; lockr -ia .ssh`: 325
*   `lockr -ia .ssh`: 325
*   `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ...">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~`: 324
*   `cat /proc/cpuinfo | grep name | wc -l`: 59
*   `cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'`: 58
*   `w`: 58
*   `uname -m`: 58
*   `cat /proc/cpuinfo | grep model | grep name | wc -l`: 58
*   `top`: 58
*   `uname`: 58
*   `uname -a`: 58
*   `whoami`: 58
*   `lscpu | grep Model`: 58
*   `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`: 57
*   `crontab -l`: 57
*   `df -h | head -n 2 | awk 'FNR == 2 {print $2;}'`: 56
*   `ls -lh $(which ls)`: 56
*   `which ls`: 56
*   `Enter new UNIX password: `: 30
*   `Enter new UNIX password:`: 30

**Signatures Triggered:**
*   ET SCAN MS Terminal Server Traffic on Non-standard Port: 496
*   2023753: 496
*   ET DROP Dshield Block Listed Source group 1: 356
*   2402000: 356
*   ET HUNTING RDP Authentication Bypass Attempt: 213
*   2034857: 213
*   ET SCAN NMAP -sS window 1024: 208
*   2009582: 208
*   ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication: 60
*   2024766: 60
*   ET INFO Reserved Internal IP Traffic: 58
*   2002752: 58
*   ET CINS Active Threat Intelligence Poor Reputation IP group 42: 30
*   2403341: 30
*   ET CINS Active Threat Intelligence Poor Reputation IP group 44: 15
*   2403343: 15
*   ET SCAN Potential SSH Scan: 15
*   2001219: 15
*   ET CINS Active Threat Intelligence Poor Reputation IP group 45: 11
*   2403344: 11
*   ET CINS Active Threat Intelligence Poor Reputation IP group 46: 10
*   2403345: 10
*   ET CINS Active Threat Intelligence Poor Reputation IP group 40: 10
*   2403339: 10

**Users / Login Attempts:**
*   345gs5662d34/345gs5662d34: 314
*   root/3245gs5662d34: 145
*   root/2glehe5t24th1issZs: 41
*   test/zhbjETuyMffoL8F: 38
*   superadmin/admin123: 33
*   root/LeitboGi0ro: 36
*   splunk/splunk123: 27
*   foundry/foundry: 26
*   appuser/appuser123: 27
*   root/test12345: 26
*   matrix/matrix: 23
*   superadmin/3245gs5662d34: 28
*   station/station123: 21
*   root/1qaz@WSX: 23
*   root/rootpassword: 27
*   arjun/3245gs5662d34: 23
*   root/qwertyuiop12345: 22
*   root/abcd1234#: 18
*   mehedi/mehedi: 17
*   root/@Aa123456: 17

**Files Uploaded/Downloaded:**
*   wget.sh;: 8
*   arm.urbotnetisass;: 5
*   arm.urbotnetisass: 5
*   arm5.urbotnetisass;: 5
*   arm5.urbotnetisass: 5
*   arm6.urbotnetisass;: 5
*   arm6.urbotnetisass: 5
*   arm7.urbotnetisass;: 5
*   arm7.urbotnetisass: 5
*   x86_32.urbotnetisass;: 5
*   x86_32.urbotnetisass: 5
*   mips.urbotnetisass;: 5
*   mips.urbotnetisass: 5
*   mipsel.urbotnetisass;: 5
*   mipsel.urbotnetisass: 5
*   34.165.197.224: 4
*   rondo.dgx.sh||busybox: 3
*   rondo.dgx.sh||curl: 3
*   rondo.dgx.sh)|sh&: 3
*   apply.cgi: 2
*   w.sh;: 1
*   c.sh;: 1

**HTTP User-Agents:**
*   (No user agents recorded)

**SSH Clients:**
*   (No SSH clients recorded)

**SSH Servers:**
*   (No SSH servers recorded)

**Top Attacker AS Organizations:**
*   (No AS organizations recorded)

---

### **Key Observations and Anomalies**

*   **High Volume of SSH Activity:** The dominance of the Cowrie honeypot and the high number of attempts on port 22 indicate a sustained and automated SSH brute-force campaign.
*   **Repetitive Commands:** A large number of attackers are attempting the same set of commands, primarily focused on disabling security features (`chattr`), clearing and adding their own SSH key to `authorized_keys`, and gathering system information. This suggests the use of common, publicly available attack scripts.
*   **Malware Delivery:** The commands and file downloads observed indicate attempts to download and execute malware, specifically the "urbotnetisass" family of malware.
*   **Targeted Credentials:** The attackers are using a common list of default and weak credentials, with `root`, `admin`, and other common usernames being frequently targeted.

This report is automatically generated.
