## Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-05T13:01:44Z
**Timeframe:** 2025-10-05T12:20:01Z to 2025-10-05T13:00:01Z

**Files Used to Generate Report:**
- agg_log_20251005T122001Z.json
- agg_log_20251005T124002Z.json
- agg_log_20251005T130001Z.json

### Executive Summary

This report summarizes 13,569 events collected from the honeypot network over a period of approximately 40 minutes. The majority of attacks were captured by the Cowrie, Suricata, and Mailoney honeypots. A significant amount of activity was observed targeting SMB (port 445/TCP) and SMTP (port 25). The most prominent attack signature was for the DoublePulsar backdoor. Most of the command execution attempts are related to setting up SSH access and reconnaissance.

### Detailed Analysis

**Attacks by Honeypot:**
- Cowrie: 5,143
- Suricata: 2,504
- Mailoney: 1,648
- Dionaea: 1,546
- Ciscoasa: 1,460
- Sentrypeer: 587
- Honeytrap: 459
- Adbhoney: 90
- H0neytr4p: 56

**Top Attacking IPs:**
- 188.244.26.232
- 213.212.36.174
- 187.237.97.188
- 86.54.42.238
- 89.110.102.210
- 213.149.166.133
- 178.17.53.66
- 172.86.95.98
- 198.12.68.114

**Top Targeted Ports/Protocols:**
- 445/TCP (SMB)
- 25 (SMTP)
- 22/TCP (SSH)
- 5060 (SIP)
- 1433 (MSSQL)

**Most Common CVEs:**
- CVE-2005-4050
- CVE-2019-11500
- CVE-2021-3449
- CVE-2002-0013, CVE-2002-0012
- CVE-2021-35394
- CVE-1999-0517

**Commands Attempted by Attackers:**
- `cd ~; chattr -ia .ssh; lockr -ia .ssh`
- `lockr -ia .ssh`
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..." >> .ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~`
- `cat /proc/cpuinfo | grep name | wc -l`
- `uname -a`
- `whoami`
- `rm -rf /data/local/tmp; mkdir -p /data/local/tmp; ...`

**Signatures Triggered:**
- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication
- ET DROP Dshield Block Listed Source group 1
- ET SCAN NMAP -sS window 1024
- ET VOIP MultiTech SIP UDP Overflow
- ET DROP Spamhaus DROP Listed Traffic Inbound group 41
- ET INFO Reserved Internal IP Traffic

**Users / Login Attempts (username/password):**
- 345gs5662d34/345gs5662d34
- test/zhbjETuyMffoL8F
- root/3245gs5662d34
- root/nPSpP4PBW0
- novinhost/novinhost.org
- root/LeitboGi0ro
- root/2glehe5t24th1issZs
- ansible/12345
- test/test123

**Files Uploaded/Downloaded:**
- wget.sh
- w.sh
- c.sh
- catgirls

**HTTP User-Agents:**
- None observed.

**SSH Clients:**
- None observed.

**SSH Servers:**
- None observed.

**Top Attacker AS Organizations:**
- None observed.

### Key Observations and Anomalies

- **High Volume of DoublePulsar Scans:** The Suricata honeypot detected a very high number of hits for the DoublePulsar backdoor signature, suggesting a coordinated campaign or a large botnet is actively scanning for vulnerable SMB services.
- **Repetitive SSH Commands:** The commands executed on the Cowrie honeypot are highly repetitive and focused on establishing persistent SSH access by adding a public key to `authorized_keys`. This is a common tactic for botnet propagation.
- **Targeted Services:** The most targeted services are SMB, SMTP, SSH, and SIP, which is consistent with common attack vectors for initial access and communication exploits.
- **Credential Stuffing:** A wide variety of usernames and passwords were attempted, indicating credential stuffing attacks. The pair `345gs5662d34/345gs5662d34` was the most frequently used.
- **Lack of HTTP-based attacks:** No HTTP user-agents were logged, which is anomalous given that web servers are a common target. This could indicate that the current wave of attacks is focused on other protocols.
