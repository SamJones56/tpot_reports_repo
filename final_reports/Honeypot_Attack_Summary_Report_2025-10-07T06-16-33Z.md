## Interesting Attacker IPs

Based on the analysis and the OSINT investigation, several IP addresses stand out as particularly interesting:

*   **172.86.95.98:** This IP is fascinating because of its conflicting profile. While it was a top attacker against our honeypots, the OSINT investigation revealed it's managed by **FranTech Solutions** and is publicly listed on the website of **UM-Labs**, a cybersecurity company. Despite its association with a security firm, it is also present on multiple malicious IP blocklists. This suggests it could be a security research tool, another honeypot, or a compromised server belonging to a legitimate tech company, making its activity highly anomalous.

*   **103.179.56.29:** This IP, traced to an Indonesian hosting provider (**PT Cloud Hosting Indonesia**), is noteworthy because it was specifically listed on a blocklist associated with the **MIRAI botnet**. This provides a direct link between the generic scanning activity we observed and a well-known, large-scale threat that targets IoT devices.

*   **86.54.42.238:** This IP from Moldova was one of the top two most aggressive attackers. What makes it interesting is its reverse DNS hostname, **"RDP-mwKEJLli"**, which strongly suggests it is a server configured for Remote Desktop Protocol. This, combined with its known malicious activity, points to it being a compromised server or a piece of infrastructure specifically set up for RDP-related attacks.

*   **176.65.141.117:** As the single most frequent attacker, its sheer volume is what makes it interesting. The OSINT data links it to a provider in Germany named **Optibounce, LLC,** and it appears on numerous spam and threat blocklists. This IP is a prime example of a persistent, high-volume "bad neighbor" on the internet, likely part of a dedicated spam or brute-forcing operation.
