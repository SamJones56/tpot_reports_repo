Here is your Honeypot Attack Summary Report.

**Honeypot Attack Summary Report**

*   **Report Generation Time:** 2025-10-14T11:01:31Z
*   **Timeframe of Report:** 2025-10-14T10:20:01Z to 2025-10-14T11:00:01Z
*   **Files Used to Generate Report:**
    *   `agg_log_20251014T102001Z.json`
    *   `agg_log_20251014T104001Z.json`
    *   `agg_log_20251014T110001Z.json`

**Executive Summary**

This report summarizes 20,587 events collected from the T-Pot honeypot network over a 40-minute period on October 14, 2025. The majority of attacks were captured by the Cowrie, Suricata, and Ciscoasa honeypots. The most frequently targeted ports were 5060 (SIP) and 445 (SMB). A significant number of attacks originated from IP addresses `85.93.49.155` and `206.191.154.180`. Several CVEs were targeted, with `CVE-2005-4050` being the most common. A variety of commands were attempted by attackers, many of which were aimed at downloading and executing malicious scripts.

**Detailed Analysis**

*   **Attacks by Honeypot:**
    *   Cowrie: 5173
    *   Honeytrap: 3794
    *   Sentrypeer: 3055
    *   Ciscoasa: 3226
    *   Suricata: 3076
    *   Dionaea: 1884
    *   Tanner: 86
    *   Mailoney: 114
    *   H0neytr4p: 52
    *   Adbhoney: 19
    *   ConPot: 17
    *   Honeyaml: 20
    *   ElasticPot: 11
    *   Ipphoney: 2
    *   Redishoneypot: 34
    *   Heralding: 19
    *   Dicompot: 3
    *   ssh-rsa: 2

*   **Top Attacking IPs:**
    *   85.93.49.155: 1488
    *   206.191.154.180: 1376
    *   134.199.200.145: 1002
    *   36.229.206.51: 1015
    *   185.243.5.146: 1087
    *   157.230.169.149: 1121
    *   185.243.5.148: 798
    *   45.236.188.4: 510
    *   88.210.63.16: 418
    *   172.86.95.98: 388
    *   172.86.95.115: 387
    *   62.141.43.183: 324

*   **Top Targeted Ports/Protocols:**
    *   5060: 3055
    *   445: 1820
    *   22: 916
    *   TCP/445: 1486
    *   5903: 189
    *   8333: 118
    *   25: 114
    *   23: 69
    *   80: 94

*   **Most Common CVEs:**
    *   CVE-2005-4050: 25
    *   CVE-2002-0013 CVE-2002-0012: 9
    *   CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 6
    *   CVE-2019-11500 CVE-2019-11500: 3
    *   CVE-2021-3449 CVE-2021-3449: 3
    *   CVE-2024-4577 CVE-2024-4577: 2
    *   CVE-2024-4577 CVE-2002-0953: 2
    *   CVE-2021-41773 CVE-2021-41773 CVE-2021-41773 CVE-2021-41773: 1
    *   CVE-2021-42013 CVE-2021-42013: 1

*   **Commands Attempted by Attackers:**
    *   `cd ~; chattr -ia .ssh; lockr -ia .ssh`: 15
    *   `lockr -ia .ssh`: 15
    *   `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ... mdrfckr">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~`: 15
    *   `uname -a`: 8
    *   `cd /data/local/tmp/; rm *; busybox wget ...`: 2
    *   `system`: 2
    *   `shell`: 2
    *   `q`: 2
    *   `uname -s -v -n -r -m`: 2
    *   ... and numerous other system reconnaissance and malware download commands.

*   **Signatures Triggered:**
    *   ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication: 1483
    *   ET DROP Dshield Block Listed Source group 1: 446
    *   ET SCAN MS Terminal Server Traffic on Non-standard Port: 226
    *   ET SCAN NMAP -sS window 1024: 164
    *   ET HUNTING RDP Authentication Bypass Attempt: 104

*   **Users / Login Attempts:**
    *   345gs5662d34/345gs5662d34: 14
    *   ubnt/7777777: 6
    *   ubnt/ubnt2013: 6
    *   blank/P@ssw0rd: 6
    *   root/bsnp2ra: 4
    *   ... many other attempts with common and default credentials.

*   **Files Uploaded/Downloaded:**
    *   sh: 98
    *   wget.sh;: 4
    *   arm.urbotnetisass;: 2
    *   arm5.urbotnetisass;: 2
    *   arm6.urbotnetisass;: 2
    *   arm7.urbotnetisass;: 2
    *   x86_32.urbotnetisass;: 2
    *   mips.urbotnetisass;: 2
    *   mipsel.urbotnetisass;: 2

*   **HTTP User-Agents:**
    *   No data available in the logs.

*   **SSH Clients and Servers:**
    *   No data available in the logs.

*   **Top Attacker AS Organizations:**
    *   No data available in the logs.

**Key Observations and Anomalies**

*   The high number of events targeting port 5060 suggests a focus on VoIP-related services.
*   The DoublePulsar backdoor signature was triggered a large number of times, indicating attempts to exploit the EternalBlue vulnerability.
*   The commands attempted by attackers show a clear pattern of reconnaissance, followed by attempts to download and execute malware from remote servers.
*   The presence of commands related to `urbotnetisass` suggests a specific botnet is actively targeting the honeypot.
*   The lack of data for HTTP User-Agents, SSH clients/servers, and AS organizations may indicate that the attacks are primarily focused on lower-level protocols, or that this information was not captured by the honeypots that were targeted.

This concludes the Honeypot Attack Summary Report. Continued monitoring is advised.
