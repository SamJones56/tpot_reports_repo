Honeypot Attack Summary Report

**Report Information**

*   **Report ID**: T-POT-20250929T000121Z
*   **Report Date**: 2025-09-29T00-01-21Z
*   **Time Range**: 2025-09-28T23:20:01Z to 2025-09-29T00:00:02Z
*   **Data Source**: T-Pot Honeypot Network

**Executive Summary**

This report summarizes 15,146 security events captured by the T-Pot honeypot network between 2025-09-28T23:20:01Z and 2025-09-29T00:00:02Z. The data indicates a high volume of automated attacks, with a significant number of events originating from a small number of IP addresses.

The most prominent attack vectors include brute-force attempts against SSH (Cowrie) and scanning activity captured by Honeytrap and Suricata. A notable concentration of attacks was directed at TCP port 445 (SMB), with a high volume of traffic from the top attacking IP addresses.

Several vulnerabilities were targeted, with a focus on older CVEs. A significant number of brute-force attempts were observed, with a wide variety of usernames and passwords being tested. The commands executed on the honeypots suggest that attackers are attempting to install malware and add SSH keys for persistent access.

**Detailed Analysis**

**Attacks by Honeypot**

A total of 15,146 events were recorded across 16 different honeypots. The top 5 most active honeypots were:

*   **Cowrie**: 5,506 events. This honeypot, which emulates an SSH server, captured the highest number of events, indicating a large volume of brute-force login attempts and command execution.
*   **Honeytrap**: 4,035 events. This honeypot, which is designed to capture and analyze network traffic, recorded a significant number of connection attempts across a wide range of ports.
*   **Suricata**: 2,921 events. As an Intrusion Detection System (IDS), Suricata logged numerous alerts for suspicious network traffic, including port scans and exploit attempts.
*   **Ciscoasa**: 1,476 events. This honeypot, emulating a Cisco ASA firewall, detected a large number of connection attempts, likely from automated scanners.
*   **Mailoney**: 831 events. This honeypot, which emulates an open mail relay, captured a significant number of events related to spam and email abuse.

The remaining 11 honeypots accounted for 377 events in total, indicating a lower but still present level of scanning and attack activity against other services.

**Top Attacking IP Addresses**

A small number of IP addresses were responsible for a large percentage of the total attack volume. The top 5 attacking IP addresses were:

*   `38.172.172.53`: 1,402 events
*   `134.122.46.149`: 1,355 events
*   `103.146.202.84`: 1,256 events
*   `119.8.78.107`: 1,246 events
*   `162.244.80.233`: 1,107 events

These five IP addresses alone accounted for over 42% of the total recorded events, suggesting automated and targeted scanning campaigns.

**Top Destination Ports**

The most frequently targeted destination ports provide insight into the services that attackers are most interested in exploiting. The top 5 ports were:

*   `TCP/445`: 1,398 events
*   `22`: 1,004 events
*   `25`: 831 events
*   `5060`: 135 events
*   `8333`: 105 events

The high volume of traffic to TCP port 445 (SMB) suggests widespread scanning for vulnerabilities such as EternalBlue. Port 22 (SSH) and port 25 (SMTP) were also heavily targeted, which aligns with the high number of events captured by the Cowrie and Mailoney honeypots, respectively.

**CVEs Exploited**

The honeypots recorded attempts to exploit several vulnerabilities. The following CVEs were identified:

*   `CVE-2002-0013`, `CVE-2002-0012`
*   `CVE-2019-11500`
*   `CVE-2024-3721`
*   `CVE-1999-0517`
*   `CVE-2005-4050`
*   `CVE-2021-44228`

The continued presence of older CVEs, such as those from 1999 and 2002, indicates that attackers are still scanning for and attempting to exploit legacy vulnerabilities that may exist in unpatched systems.

**Credentials Used**

A wide variety of usernames and passwords were used in brute-force attacks, primarily against the Cowrie (SSH) honeypot. Some of the most frequently used credentials included:

*   `root/LeitboGi0ro`
*   `root/Passw0rd`
*   `345gs5662d34/345gs5662d34`
*   `root/123qwezxc`
*   `test/zhbjETuyMffoL8F`

The use of common and default credentials such as `root`, `test`, `guest`, and `admin` remains a popular tactic for attackers.

**Commands Executed**

Upon gaining access to the honeypots, attackers executed a series of commands to gather information about the system and to install malware. The most common commands observed were:

*   System information gathering: `uname -a`, `whoami`, `cat /proc/cpuinfo`
*   Disabling security features: `cd ~; chattr -ia .ssh; lockr -ia .ssh`
*   Adding SSH keys for persistence: `echo "ssh-rsa ..." >> .ssh/authorized_keys`
*   Downloading and executing malware: `cd /data/local/tmp/; rm *; busybox wget ...`

These commands demonstrate a clear pattern of activity: once access is gained, the attacker attempts to secure their foothold, disable security measures, and then download and execute additional payloads.

**Notes and Limitations**

The data in this report is based on a distributed network of honeypots and represents a sample of malicious traffic on the internet. It is not a comprehensive view of all threats, but rather a snapshot of the activity seen by the T-Pot network during the specified time period. The IP addresses listed as sources of attacks may be compromised systems or proxies and may not be the true origin of the attacks. The data is presented as recorded by the honeypots and has not been independently verified.
