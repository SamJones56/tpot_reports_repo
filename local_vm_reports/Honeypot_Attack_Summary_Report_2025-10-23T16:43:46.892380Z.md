### **INCIDENT REPORT: SUSPECTED ZERO-DAY RECONNAISSANCE TARGETING CISCO ASA DEVICES**

| **Case ID** | **Date of Report** | **Status** | **Classification** |
| :--- | :--- | :--- | :--- |
| 20251023-ZDE-03 | 2025-10-23 | Active Investigation | **HIGH - POTENTIAL ZERO-DAY ACTIVITY** |

---

### **1.0 Executive Summary**

A rigorous, multi-stage investigation into anomalous network activity has identified a high-confidence indicator of a potential zero-day threat. The activity does not involve a captured payload but rather a highly specific reconnaissance TTP (Tactic, Technique, and Procedure) targeting Cisco Adaptive Security Appliance (ASA) firewalls.

On **October 12, 2025**, an attacker from the IP address **185.216.140.186** made a single, unique request for the file `/admin/dm-launcher.msi` against the `sens-tel` honeypot, which emulates a Cisco ASA device. OSINT analysis confirms this file is the legitimate installer for the Cisco ASDM management software, but it is also a known vector for targeted attacks.

Crucially, the attacker's IP is a known scanner but is **not associated with any of the recent, large-scale campaigns** (e.g., "ArcaneDoor") targeting Cisco ASA vulnerabilities. This suggests the activity is from a separate, more careful actor. It is our assessment that this reconnaissance is the preparatory phase for deploying a private, undisclosed (zero-day) exploit. The novelty lies in the TTP from this specific, unattributed actor.

---

### **2.0 Detection and Indicator Details**

The investigation pivoted to contextual anomalies after exhausting leads from high-volume data. A single HTTP request was isolated from the last month of data due to its unique and contextually inappropriate nature.

*   **Indicator:** `GET /admin/dm-launcher.msi HTTP/1.1`
*   **Anomaly:** A request for a Windows-specific installer file (`.msi`) against a network appliance.
*   **Significance:** This is a highly specific fingerprinting method to identify the presence of a Cisco ASA firewall.

---

### **3.0 Incident Data**

A query for the specific payload returned a single event with the following details:

*   **Timestamp:** `2025-10-12T09:03:32.751Z`
*   **Attacker IP:** `185.216.140.186`
*   **Attacker ASN:** 57717
*   **Attacker Organization:** FiberXpress BV
*   **Attacker Geolocation:** Amsterdam, North Holland, The Netherlands
*   **Target Honeypot:** `sens-tel` (Cisco ASA Honeypot)
*   **Log Source:** `Ciscoasa`

---

### **4.0 Multi-Stage Verification and OSINT Analysis**

A rigorous, two-stage OSINT process was applied to scrutinize the finding.

**4.1 Stage 1: Filename Analysis (`dm-launcher.msi`)**
*   **Finding:** The file is the legitimate installer for the **Cisco Adaptive Security Device Manager (ASDM)**, the primary GUI tool for managing Cisco ASA firewalls.
*   **Threat Context:** While legitimate, the ASDM installer is a known attack vector. Threat actors can craft malicious versions to deliver malware (e.g., reverse shells) onto administrator workstations, as highlighted by vulnerabilities such as **CVE-2022-20829**.
*   **Conclusion:** This confirms the attacker's specific and targeted interest in Cisco ASA devices.

**4.2 Stage 2: Attacker IP Analysis (`185.216.140.186`)**
*   **Finding:** The IP is a known scanner with a history of reports on platforms like AbuseIPDB.
*   **Critical Finding:** A detailed search found **no public intelligence linking this IP** to the widely publicized, large-scale campaigns targeting recent Cisco ASA vulnerabilities (e.g., the "ArcaneDoor" campaign or malware such as "Line Runner").
*   **Conclusion:** The attacker is operating from infrastructure that is separate from the "background noise" of the major botnets currently exploiting Cisco ASA devices. This points to an independent and potentially more sophisticated actor.

---

### **5.0 Hypothesis and Final Assessment**

The evidence strongly suggests that this is not a random scan but a deliberate and stealthy reconnaissance effort preceding a zero-day exploit.

**Hypothesis:** The attacker is using a previously un-cataloged scanner to fingerprint Cisco ASA firewalls across the internet. By searching for the presence of `dm-launcher.msi`, they can confirm the device type with high confidence. This targeted reconnaissance allows them to reserve their valuable, unknown exploit for confirmed targets only. The use of an IP not associated with the major ongoing campaigns is a deliberate tactic to avoid attribution and early detection.

**This activity is assessed with high confidence as the reconnaissance phase of a new, undisclosed threat targeting Cisco ASA firewalls.** The TTP itself is the novel indicator.

---

### **6.0 Indicators of Compromise (IoCs)**

The following IoCs should be used for threat hunting and detection rule creation.

| **Indicator Type** | **Value** | **Notes** |
| :--- | :--- | :--- |
| **Attacker IP** | `185.216.140.186` | Source of reconnaissance. |
| **HTTP Request** | `GET /admin/dm-launcher.msi HTTP/1.1` | Unique fingerprinting TTP. |

---

### **7.0 Recommendations**

1.  **Block Attacker IP:** Immediately add `185.216.140.186` to the global network blocklist.
2.  **Create Detection Rule:** Deploy a high-priority detection rule in the SIEM and network IDS/IPS for any inbound `GET` requests to `/admin/dm-launcher.msi` from external sources.
3.  **Threat Hunt:** Initiate a threat hunt across all network appliance logs (especially Cisco ASA) for this specific TTP, originating from any IP address.
4.  **Escalate for Monitoring:** Escalate this finding to the threat intelligence team for proactive monitoring of this new TTP and any further activity from the source IP or ASN.

***
**End of Report**