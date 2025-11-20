This OSINT report is based on the analysis of honeypot data from the following files: `Honeypot_Attack_Summary_Report_2025-09-28T14-37-09Z.md`, `Honeypot_Attack_Summary_Report_2025-09-28T21-01-51Z.md`, `Honeypot_Attack_Summary_Report_2025-09-28T22-03-04Z.md`, `Honeypot_Attack_Summary_Report_2025-09-28T23-02-04Z.md`, `Honeypot_Attack_Summary_Report_2025-09-29T00-01-47Z.md`, `Honeypot_Attack_Summary_Report_2025-09-29T01-01-37Z.md`, `Honeypot_Attack_Summary_Report_2025-09-29T02-02-07Z.md`, `Honeypot_Attack_Summary_Report_2025-09-29T04-01-53Z.md`, `Honeypot_Attack_Summary_Report_2025-09-29T05-01-54Z.md`, `Honeypot_Attack_Summary_Report_2025-09-29T06-01-50Z.md`, `Honeypot_Attack_Summary_Report_2025-09-29T07-01-45Z.md`, `Honeypot_Attack_Summary_Report_2025-09-29T08-01-48Z.md`, `Honeypot_Attack_Summary_Report_2025-09-29T09-02-42Z.md`, `Honeypot_Attack_Summary_Report_2025-09-29T10-02-22Z.md`, `Honeypot_Attack_Summary_Report_2025-09-29T11-01-58Z.md`, `Honeypot_Attack_Summary_Report_2025-09-29T12-02-14Z.md`, `Honeypot_Attack_Summary_Report_2025-09-29T13-02-20Z.md`, `Honeypot_Attack_Summary_Report_2025-09-29T14-02-04Z.md`, `Honeypot_Attack_Summary_Report_2025-09-29T14:58:05Z.md`, `Honeypot_Attack_Summary_Report_2025-09-29T15:02:30Z.md`, `Honeypot_Attack_Summary_Report_2025-09-29T15:42:56Z.md`, `Honeypot_Attack_Summary_Report_2025-09-29T16:02:15Z.md`, `Honeypot_Attack_Summary_Report_2025-09-29T17:20:43Z.md`, `Honeypot_Attack_Summary_Report_2025-09-29T18:43:06Z.md`, `Honeypot_Attack_Summary_Report_2025-09-29T19:02:19Z.md`, `Honeypot_Attack_Summary_Report_2025-09-29T20:01:56Z.md`, `Honeypot_Attack_Summary_Report_2025-09-29T21:01:52Z.md`, `Honeypot_Attack_Summary_Report_2025-09-29T22:01:52Z.md`, `Honeypot_Attack_Summary_Report_2025-09-30T00:01:58Z.md`, `Honeypot_Attack_Summary_Report_2025-09-30T01:02:03Z.md`, `Honeypot_Attack_Summary_Report_2025-09-30T02:02:12Z.md`, `Honeypot_Attack_Summary_Report_2025-09-30T03:02:05Z.md`, `Honeypot_Attack_summary_report_2025-09-30T04:02:01Z.md`, and `Honeypot_Attack_Summary_Report_2025-09-30T05:01:53Z.md` and `Honeypot_Attack_Summary_Report_2025-09-30T06:02:00Z.md`.

# OSINT Investigation Report: Honeypot Network Analysis

**Report Generation Time:** 2025-10-26

**Executive Summary:**

This report presents an Open Source Intelligence (OSINT) investigation into the malicious activities recorded by a distributed honeypot network. The analysis of the collected data reveals a multifaceted threat landscape characterized by both opportunistic, large-scale scanning and targeted malware campaigns. Two dominant attack vectors were identified: the widespread exploitation of the EternalBlue vulnerability to deliver the DoublePulsar backdoor, and a coordinated campaign to propagate the `urbotnetisass` malware, a variant of the Mirai botnet, targeting Internet of Things (IoT) devices. The investigation highlights the continued threat posed by legacy vulnerabilities and the growing sophistication of IoT-focused botnets.

**Key Findings:**

**1. Mirai Botnet Campaign: The "urbotnetisass" Malware**

A significant portion of the observed attacks were part of a campaign to distribute the `urbotnetisass` malware. This malware has been identified as a variant of the Mirai botnet, which is known for its ability to infect a wide range of IoT devices and incorporate them into a network for launching Distributed Denial-of-Service (DDoS) attacks.

*   **Command and Control (C2) Server:** The investigation traced the source of the malware to the IP address `94.154.35.154`. This IP, associated with AS214943 Railnet LLC, serves as a C2 server, hosting and distributing multiple variants of the `urbotnetisass` payload compiled for different processor architectures (ARM, MIPS, etc.).
*   **Infection Vector:** The primary infection vector for this malware is the exploitation of weak or default credentials on IoT devices. Once compromised, the devices are instructed to download and execute the `urbotnetisass` binary, thereby joining the botnet.
*   **Targeted Vulnerabilities:** The campaign also leverages specific vulnerabilities to gain access to devices. The presence of attacks targeting `CVE-2023-26801`, a critical command injection vulnerability in LB-LINK wireless routers, is a strong indicator of the tactics used by the botnet operators to expand their network.

**2. EternalBlue and DoublePulsar: The Lingering Threat**

The honeypot data shows a high volume of traffic targeting port 445 (SMB), with a significant number of alerts for the DoublePulsar backdoor. This indicates a continued and widespread effort by attackers to exploit the EternalBlue vulnerability (CVE-2017-0144).

*   **Top Attacking IP:** The IP address `182.10.97.127`, registered to PT Telekomunikasi Selular (Telkomsel) in Indonesia, was the most prolific attacker. While no specific malicious activity is publicly attributed to this IP, its behavior is consistent with that of a compromised system or a node in a botnet dedicated to scanning for the EternalBlue vulnerability.
*   **Attack Pattern:** The attacks follow a classic pattern: scanning for open SMB ports, exploiting the vulnerability to gain remote code execution, and then implanting the DoublePulsar backdoor to maintain persistent access and deliver secondary payloads.

**3. Broad-Spectrum Vulnerability Scanning**

Beyond the two main campaigns, the honeypots recorded a wide variety of probes for other vulnerabilities, including:

*   `CVE-2002-0013`, `CVE-2002-0012`, `CVE-1999-0517`: Older, well-known vulnerabilities, indicating that attackers are still attempting to exploit legacy systems.
*   `CVE-2023-31983`, `CVE-2024-33112`: More recent vulnerabilities, demonstrating that attackers are actively incorporating new exploits into their scanning tools.

This broad scanning activity suggests the use of automated tools designed to find any vulnerable system, regardless of the specific software or service it runs.

**4. Anomalous Login Attempts**

The analysis of login attempts revealed the use of both common and unusual usernames and passwords. The username `thayne` was observed with multiple password variations. While the OSINT investigation did not link this username to a specific threat actor, its presence suggests the use of custom or less common wordlists in brute-force attacks.

**Recommendations:**

Based on the findings of this investigation, the following security measures are recommended:

*   **Patch and Harden Systems:** Prioritize the patching of all systems vulnerable to EternalBlue (MS17-010). Disable SMBv1 where possible.
*   **Secure IoT Devices:** Change default usernames and passwords on all IoT devices. Regularly check for and apply firmware updates. Isolate IoT devices on a separate network segment to limit their exposure.
*   **Network Monitoring:** Monitor for and block traffic to and from the identified IoCs. Implement firewall rules to restrict inbound traffic to only necessary ports.
*   **Intrusion Detection/Prevention:** Utilize an IDS/IPS to detect and block known exploits, including those for EternalBlue and other CVEs mentioned in this report.

**Indicators of Compromise (IoCs):**

*   **IP Address (C2 Server):** `94.154.35.154`
*   **Malware:** `urbotnetisass` (Mirai variant)
*   **Vulnerability:** `CVE-2023-26801` (LB-LINK Routers), `CVE-2017-0144` (EternalBlue)
*   **Malware Download URLs:**
    *   `http://94.154.35.154/arm.urbotnetisass`
    *   `http://94.154.35.154/arm5.urbotnetisass`
    *   `http://94.154.35.154/arm6.urbotnetisass`
    *   `http://94.154.35.154/arm7.urbotnetisass`
    *   `http://94.154.35.154/x86_32.urbotnetisass`
    *   `http://94.154.35.154/mips.urbotnetisass`
    *   `http://94.154.35.154/mipsel.urbotnetisass`

**Conclusion:**

The analysis of the honeypot data provides a clear picture of the current threat landscape. Attackers are leveraging both old and new vulnerabilities to compromise a wide range of systems, from traditional servers to IoT devices. The continued prevalence of threats like EternalBlue underscores the importance of basic security hygiene, while the rise of IoT botnets like the one distributing `urbotnetisass` highlights the need for a more security-conscious approach to the deployment of connected devices. It is imperative that organizations and individuals remain vigilant and proactive in their security efforts to defend against these persistent and evolving threats.