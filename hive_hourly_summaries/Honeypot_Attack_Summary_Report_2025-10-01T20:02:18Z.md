Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-01T20:01:28Z
**Timeframe:** 2025-10-01T19:20:02Z to 2025-10-01T20:00:01Z
**Log Files:**
- agg_log_20251001T192002Z.json
- agg_log_20251001T194001Z.json
- agg_log_20251001T200001Z.json

### Executive Summary

This report summarizes 29,992 events collected from the honeypot network over the last hour. The majority of attacks were captured by the Sentrypeer and Cowrie honeypots. The most prominent attack vector was repeated attempts to connect to port 5060, likely related to VoIP scanning. A significant number of SSH brute-force attempts and reconnaissance commands were also observed. The most active attacking IP was 92.205.59.208.

### Detailed Analysis

**Attacks by Honeypot:**
*   Sentrypeer: 18,169
*   Cowrie: 8,507
*   Honeytrap: 1,183
*   Suricata: 931
*   Ciscoasa: 710
*   Dionaea: 338
*   H0neytr4p: 64
*   Tanner: 22
*   Mailoney: 17
*   Adbhoney: 14
*   Redishoneypot: 12
*   Honeyaml: 10
*   ElasticPot: 5
*   ConPot: 4
*   Heralding: 3
*   Dicompot: 3

**Top Attacking IPs:**
*   92.205.59.208: 18,245
*   103.130.215.15: 2,749
*   159.89.20.223: 1,247
*   5.167.79.4: 1,015
*   81.192.46.29: 355
*   138.68.171.6: 302
*   41.202.91.244: 238
*   88.210.63.16: 217
*   36.40.79.122: 168
*   185.156.73.167: 188
*   185.156.73.166: 186

**Top Targeted Ports/Protocols:**
*   5060: 18,169
*   22: 1,433
*   445: 313
*   UDP/5060: 89
*   443: 70
*   8333: 43
*   1433: 25
*   TCP/1433: 18
*   25: 14
*   TCP/22: 16

**Most Common CVEs:**
*   CVE-2002-0013 CVE-2002-0012: 8
*   CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 3
*   CVE-2019-11500 CVE-2019-11500: 1
*   CVE-2021-35394 CVE-2021-35394: 1

**Commands Attempted by Attackers:**
*   `cd ~; chattr -ia .ssh; lockr -ia .ssh`: 26
*   `lockr -ia .ssh`: 26
*   `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."`: 26
*   `cat /proc/cpuinfo | grep name | wc -l`: 26
*   `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`: 25
*   `ls -lh $(which ls)`: 25
*   `which ls`: 25
*   `crontab -l`: 25
*   `w`: 25
*   `uname -m`: 25
*   `cat /proc/cpuinfo | grep model | grep name | wc -l`: 25
*   `top`: 25
*   `uname`: 25
*   `uname -a`: 25
*   `whoami`: 25
*   `lscpu | grep Model`: 25
*   `df -h | head -n 2 | awk 'FNR == 2 {print $2;}'`: 25
*   `Enter new UNIX password: `: 18
*   `Enter new UNIX password:`: 15

**Signatures Triggered:**
*   ET SCAN MS Terminal Server Traffic on Non-standard Port: 162
*   2023753: 162
*   ET DROP Dshield Block Listed Source group 1: 129
*   2402000: 129
*   ET SCAN NMAP -sS window 1024: 88
*   2009582: 88
*   ET VOIP REGISTER Message Flood UDP: 87
*   2009699: 87
*   ET HUNTING RDP Authentication Bypass Attempt: 66
*   2034857: 66
*   ET INFO Reserved Internal IP Traffic: 31
*   2002752: 31

**Users / Login Attempts:**
*   345gs5662d34/345gs5662d34: 25
*   test/zhbjETuyMffoL8F: 10
*   root/nPSpP4PBW0: 9
*   root/LeitboGi0ro: 8
*   superadmin/admin123: 7
*   foundry/foundry: 6
*   lx/lx: 6
*   user/User1234: 4
*   root/3245gs5662d34: 5
*   superadmin/3245gs5662d34: 4

**Files Uploaded/Downloaded:**
*   arm.urbotnetisass;: 4
*   arm.urbotnetisass: 4
*   arm5.urbotnetisass;: 4
*   arm5.urbotnetisass: 4
*   arm6.urbotnetisass;: 4
*   arm6.urbotnetisass: 4
*   arm7.urbotnetisass;: 4
*   arm7.urbotnetisass: 4
*   x86_32.urbotnetisass;: 4
*   x86_32.urbotnetisass: 4
*   mips.urbotnetisass;: 4
*   mips.urbotnetisass: 4
*   mipsel.urbotnetisass;: 4
*   mipsel.urbotnetisass: 4
*   Mozi.a+varcron: 2
*   boatnet.mpsl;: 1
*   json: 1

**HTTP User-Agents:**
*   None observed.

**SSH Clients:**
*   None observed.

**SSH Servers:**
*   None observed.

**Top Attacker AS Organizations:**
*   None observed.

### Key Observations and Anomalies

*   The overwhelming majority of traffic is directed at port 5060 (Sentrypeer), indicating widespread scanning for vulnerable VoIP systems. The IP address 92.205.59.208 is the primary source of this traffic.
*   The commands executed within the Cowrie honeypot are consistent with automated scripts performing reconnaissance and attempting to install malware. The repeated use of `chattr` and modification of `.ssh/authorized_keys` is a common tactic to maintain persistence.
*   Attackers are attempting to download and execute files with names like `arm.urbotnetisass`, `mips.urbotnetisass`, and `Mozi.a+varcron`, which are associated with IoT botnets.
*   The Suricata IDS signatures for "MS Terminal Server Traffic on Non-standard Port" and "Dshield Block Listed Source" were the most frequently triggered, highlighting the prevalence of scanning for remote desktop services and traffic from known malicious IPs.
*   A variety of CVEs were targeted, although in low numbers, suggesting some opportunistic scanning for older vulnerabilities.

Final report generated.