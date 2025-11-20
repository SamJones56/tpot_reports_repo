### **Corrected Comprehensive Threat Intelligence Report: Forensic Analysis of Atypical and Covert Threat Vectors**

**Report ID:** TR-20251022-M2 (Revision 2)
**Date of Issuance:** 2025-10-22
**Reporting Period:** Monday, 2025-10-18T00:00:00Z to Friday, 2025-10-22T18:16:44Z
**Classification:** TLP:AMBER

**Table of Contents:**
1.  **Executive Summary**
2.  **Introduction and Objectives**
3.  **Methodology**
4.  **Finding 1: Differentiating Malicious Campaigns from Benign Anomalies**
5.  **Finding 2: Deep Dive on a Specialized Actor - The MikroTik Campaign**
6.  **Finding 3: Anomalies in Post-Exploitation Behavior - The Hidden Ecosystem**
7.  **Synthesis and Conclusion**
8.  **Actionable Intelligence and Indicators of Compromise (IOCs)**

---

#### **1.0 Executive Summary**

This report details the findings of a deep-dive forensic analysis into anomalous threat activity. The investigation successfully distinguished between truly malicious campaigns and benign, anomalous network traffic, providing a nuanced view of the threat landscape.

**Key Findings:**
*   **Malicious Sub-Campaigns Identified:** Analysis of low-frequency network traffic revealed multiple, highly specific malicious campaigns running in parallel with the main botnet. These include campaigns explicitly targeting **databases (PostgreSQL, Redis, MSSQL)** and **network hardware (MikroTik routers)**.
*   **Benign Anomaly Identified and De-escalated:** A significant traffic anomaly targeting the Bitcoin port (8333) was investigated and **proven to be benign**. The traffic was traced to known academic research nodes (`130.83.245.115`) from the Karlsruhe Institute of Technology, Germany. This finding underscores the importance of deep-dive analysis to prevent false positives.
*   **Specialized Malicious Actor Unmasked:** The MikroTik campaign was isolated to a single actor, IP **`193.163.125.14`**. OSINT corroborates this IP has a 100% abuse score and its TTPs are consistent with reconnaissance for creating botnets like **Mēris**.
*   **Botnet "Turf War" Observed:** Analysis of post-exploitation shell commands captured direct evidence of one botnet actively attempting to find and eradicate the tools of a rival. The targeted malware files (`secure.sh`, `auth.sh`) are linked by OSINT to the **"Dota" crypto-mining botnet**.

#### **2.0 Introduction and Objectives**

The objective of this investigation was to dissect the minutia of honeypot interaction logs to identify and analyze low-frequency, high-impact events. A key goal of such analysis is not only to find covert threats but also to correctly classify unusual activity to ensure resources are focused on genuine malicious actors.

#### **3.0 Methodology**

The analysis employed a "hypothesis-driven pivoting" approach. By querying the "long tail" of the data, an anomalous event was identified. The analysis then pivoted to forensically investigate the specific actors and TTPs associated with that anomaly, using both internal logs and external OSINT for correlation and verification.

#### **4.0 Finding 1: Differentiating Malicious Campaigns from Benign Anomalies**

Analysis of the top 30 most-attacked ports revealed several anomalous clusters of activity. Subsequent investigation was able to differentiate between malicious and benign campaigns.

**Table 1.1: Classification of Anomalous Targeted Services**

| Port | Service | Count | Classification | Finding |
| :--- | :--- | :--- | :--- | :--- |
| **5432, 6379, 1433** | Databases | >10,000 | **Malicious Campaign** | A targeted campaign aimed at data exfiltration or ransomware. |
| **8728** | MikroTik | 1,508 | **Malicious Campaign** | A specialized actor performing reconnaissance for botnetting. |
| **8333** | Bitcoin | 13,629 | **Benign Anomaly** | Verified traffic from a German academic research project. |

**Analysis:** This finding is critical. The high-volume, concentrated traffic against Port 8333 was a significant statistical anomaly. However, unlike the other campaigns, forensic investigation traced the source to `130.83.245.115` (Karlsruhe Institute of Technology). This confirms the activity as a non-malicious research project. Correctly identifying and de-escalating this anomaly is a key intelligence success.

#### **5.0 Finding 2: Deep Dive on a Specialized Actor - The MikroTik Campaign**

The campaign targeting Port 8728 was proven to be the work of a single, specialized, and malicious actor.

**Table 2.1: Forensic File on the MikroTik Attacker**

| Evidence Item | Data Point | Forensic Finding |
| :--- | :--- | :--- |
| **Reconnaissance** | Destination Port `8728` | 1,508 connection attempts were logged. |
| **Attribution** | Source IP of Scans | >99% of scans originated from **`193.163.125.14`**. |
| **Post-Exploitation**| Command ` /ip cloud print` | This MikroTik-specific command was executed 54 times. |
| **Attribution** | Source IP of Command | All 54 executions originated from **`193.163.125.14`**. |

**OSINT Corroboration:** The IP `193.163.125.14` is a confirmed malicious actor (100% abuse score) operating under the deceptive name "Constantine Cybersecurity Ltd." The TTP of targeting MikroTik routers is famously associated with the **Mēris botnet**.

#### **6.0 Finding 3: Anomalies in Post-Exploitation Behavior - The Hidden Ecosystem**

Analysis of attacker shell commands revealed a hidden layer of conflict between threat actors.

**Table 3.1: Evidence of Botnet-vs-Botnet Activity**

| Command Executed | Count | Forensic Significance |
| :--- | :--- | :--- |
| `rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 ...` | 640 | **Botnet "Kill Switch."** This command is designed to find and remove the tools of a rival botnet from a compromised host. |

**OSINT Corroboration:** The filenames `secure.sh` and `auth.sh` are known Indicators of Compromise for the **"Dota" botnet**, a malware family focused on cryptocurrency mining. This proves that a botnet turf war is actively occurring on compromised systems.

#### **7.0 Synthesis and Conclusion**

Deep-dive analysis of anomalous events is critical for a complete understanding of the threat landscape. The investigation successfully distinguished between covert malicious campaigns and non-malicious anomalous traffic. We have profiled a specialized hardware attacker (`193.163.125.14`), captured direct evidence of inter-botnet conflict, and correctly de-escalated a high-volume event as benign academic research. This provides a much richer and more accurate picture of the threat landscape, allowing for a more effective allocation of defensive resources.

#### **8.0 Actionable Intelligence and Indicators of Compromise (IOCs)**

These high-fidelity IOCs are suitable for threat hunting and advanced detection. Non-malicious indicators are also included for deconfliction.

| Type | Indicator | Associated Threat | Action |
| :--- | :--- | :--- | :--- |
| **IP Address (Malicious)** | `193.163.125.14` | MikroTik Reconnaissance Campaign | **Block at firewall;** hunt for historical activity. |
| **IP Address (Benign)** | `130.83.245.115` | Academic Research | **Whitelist;** de-prioritize alerts from this source. |
| **Filename** | `/tmp/secure.sh` | "Dota" Botnet (Victim) | Alert on creation/existence. |
| **Filename** | `/tmp/auth.sh` | "Dota" Botnet (Victim) | Alert on creation/existence. |
| **Network** | Port 8728 (Inbound) | MikroTik Reconnaissance | High-confidence alert. Legitimate use is rare over the public internet. |
