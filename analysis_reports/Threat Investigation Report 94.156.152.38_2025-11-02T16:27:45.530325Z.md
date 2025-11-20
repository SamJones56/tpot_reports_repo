### **Threat Investigation Report: 94.156.152.38**

**Report Generation Time:** 2025-11-02T16:25:07.553541Z
**Timeframe of Investigation:** 2025-09-28T00:00:00.000Z - 2025-10-28T23:59:59.999Z

---

### **1. Executive Summary**

This report provides a comprehensive analysis of the malicious activities originating from the IP address **94.156.152.38**. During the investigation period, this IP was responsible for over **1,800** logged events against our global honeypot network. The activities included widespread port scanning, command injection, and the delivery of malicious payloads. External threat intelligence corroborates these findings, identifying the IP as a known attacker associated with malware distribution and pre-ransomware activities like RDP probes. The evidence strongly suggests this actor is a persistent threat to internet-facing services.

---

### **2. Attacker Profile**

*   **IP Address:** `94.156.152.38`
*   **Geolocation:** Bulgaria
*   **Autonomous System (ASN):** AS214209
*   **Service Provider:** Internet Magnate (Pty) Ltd
*   **Reputation:** **Malicious**. Both internal logs (`ip_rep: "known attacker"`) and external threat intelligence confirm its hostile nature. Reports from Malwarebytes and MalwareWorld link this IP to port scanning, RDP probes, and malware distribution.

---

### **3. Observed Malicious Activities**

Analysis of the **1,800+** events logged from this IP reveals a multi-faceted attack strategy targeting our entire honeypot network (`sens-ny`, `sens-tel`, `sens-tai`, `sens-dub`).

**a. Broad-Spectrum Scanning:**
The attacker systematically scanned a wide range of TCP and UDP ports to identify open services. Notable targets included:
*   **Common Ports:** `22` (SSH), `80` (HTTP), `88` (Kerberos)
*   **Web Proxies/Services:** `8080`
*   **Uncommon Ports:** `9034`, `52869`, and various ephemeral ports.

This activity, logged by our `P0f` and `Suricata` sensors, indicates an automated and indiscriminate search for vulnerable systems.

**b. Exploitation and Command Injection:**
On **2025-10-16**, the attacker attempted to exploit a command injection vulnerability in LB-Link routers (**CVE-2023-26801**). The Suricata alert `ET EXPLOIT LB-Link Command Injection Attempt` was triggered when the attacker sent a POST request to `/goform/set_LimitClient_cfg` on the `sens-tel` honeypot. The payload attempted to download and execute a shell script named `sora.sh` from another malicious IP (`151.242.30.16`).

**c. Payload Delivery (Prometei Botnet):**
As detailed in the previous investigation, this IP address was the source for delivering ELF binaries and shell scripts associated with the Prometei botnet. This includes the download of `x86`, `bot`, `wget.sh`, and `sigma.sh`, confirming the IP's role in malware distribution.

**d. Operating System Fingerprinting:**
The `P0f` logs indicate the attacker used tools associated with various operating systems, including **Linux 2.2.x-3.x** and **Windows NT kernel 5.x**, suggesting the use of a diverse toolkit or a multi-platform attack framework. The use of the `Go-http-client/1.1` user agent was also noted, which is common in automated attack tools.

---

### **4. Indicators of Compromise (IOCs)**

*   **Primary IP:** `94.156.152.38`
*   **Secondary IP (Payload Server):** `151.242.30.16`
*   **Malicious Files:** `sora.sh`, `x86`, `bot`, `wget.sh`, `w.sh`, `sigma.sh`
*   **CVE Exploited:** `CVE-2023-26801`
*   **Suricata Signatures:**
    *   `ET EXPLOIT LB-Link Command Injection Attempt (CVE-2023-26801)`
    *   `ET INFO Executable and linking format (ELF) file download`
    *   `ET INFO Go-http-client User-Agent Observed Inbound`
*   **Targeted URL Path:** `/goform/set_LimitClient_cfg`

---

### **5. Conclusion**

The IP address **94.156.152.38** is a highly active and malicious node on the internet. Our internal logs, combined with public threat intelligence, paint a clear picture of an attacker engaged in systematic scanning, exploitation of known vulnerabilities, and the distribution of the Prometei malware. The sheer volume and breadth of the attacks indicate that this is likely an automated system or botnet infrastructure. All indicators associated with this IP should be considered hostile and blocked.
