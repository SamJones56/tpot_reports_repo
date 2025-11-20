A full analysis of the T-Pot honeypot data is now complete, and the following summary report has been produced:

**Report Title:** Hourly Honeypot Attack Summary

**Report Information:**

*   **Timestamp (UTC):** 2025-09-28T23-01-19Z
*   **Data Sources:**
    *   `agg_log_20250928T222001Z.json`
    *   `agg_log_20250928T224001Z.json`
    *   `agg_log_20250928T230001Z.json`
*   **Reporting Period:** An aggregation of three two-minute log snippets.

**Executive Summary:**

This report summarizes a total of 23,271 malicious events captured by the T-Pot honeypot network. The attacks originated from a wide range of IP addresses and targeted various services and vulnerabilities. The most targeted service was `Honeytrap`, a versatile honeypot designed to mimic a wide range of services. A significant portion of the attacks were SSH bruteforce attempts and automated vulnerability scanning. The most active attacking IP was `162.244.80.233`.

**Detailed Analysis:**

**Attacks by Honeypot:**

The following table shows the distribution of attacks across the different honeypot services:

| Honeypot    | Event Count |
| :---------- | :---------- |
| Honeytrap   | 15987       |
| Cowrie      | 3784        |
| Suricata    | 1981        |
| Ciscoasa    | 1031        |
| Dionaea     | 108         |
| Sentrypeer  | 146         |
| Adbhoney    | 55          |
| Mailoney    | 28          |
| Tanner      | 19          |
| H0neytr4p   | 16          |
| ElasticPot  | 13          |
| ConPot      | 92          |
| Dicompot    | 4           |
| Redishoneypot | 3         |
| Honeyaml    | 2           |
| Ipphoney    | 2           |

**Top 20 Attacking IP Addresses:**

| IP Address        | Event Count |
| :---------------- | :---------- |
| 162.244.80.233    | 15259       |
| 91.237.163.112    | 324         |
| 111.32.153.180    | 430         |
| 103.172.237.182   | 296         |
| 185.156.73.167    | 259         |
| 185.156.73.166    | 256         |
| 92.63.197.55      | 248         |
| 92.63.197.59      | 233         |
| 20.80.248.60      | 214         |
| 205.185.126.121   | 226         |
| 178.62.17.84      | 164         |
| 181.218.9.86      | 149         |
| 122.169.47.13     | 138         |
| 181.212.81.227    | 133         |
| 175.27.225.89     | 126         |
| 106.12.134.176    | 113         |
| 84.247.134.72     | 186         |
| 103.189.208.13    | 181         |
| 95.58.255.251     | 124         |
| 115.190.126.244   | 108         |

**Top 20 Destination Ports:**

| Port   | Protocol | Event Count |
| :----- | :------- | :---------- |
| 22     | TCP      | 441         |
| 5060   | UDP      | 146         |
| 8333   | TCP      | 59          |
| 1025   | TCP      | 87          |
| 23     | TCP      | 46          |
| 1090   | TCP      | 41          |
| 1100   | TCP      | 41          |
| 8888   | TCP      | 39          |
| 1521   | TCP      | 36          |
| 8000   | TCP      | 35          |
| 6567   | TCP      | 34          |
| 6666   | TCP      | 34          |
| 6668   | TCP      | 34          |
| 9001   | TCP      | 34          |
| 9090   | TCP      | 34          |
| 8001   | TCP      | 34          |
| 9002   | TCP      | 47          |
| 9999   | TCP      | 33          |
| 8008   | TCP      | 33          |
| 1583   | TCP      | 33          |

**CVEs Exploited:**

*   CVE-2022-27255
*   CVE-2021-3449
*   CVE-2019-11500
*   CVE-2005-4050
*   CVE-2002-0013
*   CVE-2002-0012
*   CVE-1999-0517
*   CVE-2021-35394
*   CVE-2008-2639

**Top 20 Credentials Used in Attacks:**

| Username/Password         | Count |
| :------------------------ | :---- |
| 345gs5662d34/345gs5662d34 | 26    |
| root/3245gs5662d34        | 12    |
| root/nPSpP4PBW0           | 8     |
| test/zhbjETuyMffoL8F      | 5     |
| root/Linux@123            | 4     |
| root/www.qq.com           | 3     |
| root/@Aa123456            | 3     |
| xyx/xyx123                | 3     |
| minikube/123              | 3     |
| ftpuser2/ftpuser2123      | 3     |
| root/Passw0rd             | 5     |
| root/LeitboGi0ro          | 2     |
| test/2024                 | 2     |
| root/Root2024!            | 2     |
| root/administrator        | 2     |
| tomcat/123                | 2     |
| jayesh/jayesh123          | 2     |
| matrix/matrix             | 2     |
| ubnt/ubnt1                | 2     |
| stone/stone               | 4     |

**Top 20 Commands Executed by Attackers:**

| Command                                                                                                                                                                                                                                                                                                                                                                                                                    | Count |
| :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | :---- |
| `cd ~; chattr -ia .ssh; lockr -ia .ssh`                                                                                                                                                                                                                                                                                                                                                                                     | 28    |
| `lockr -ia .ssh`                                                                                                                                                                                                                                                                                                                                                                                                           | 28    |
| `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~` | 28    |
| `cat /proc/cpuinfo | grep name | wc -l`                                                                                                                                                                                                                                                                                                                                                                                     | 29    |
| `cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'`                                                                                                                                                                                                                                                                                                                                                | 29    |
| `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`                                                                                                                                                                                                                                                                                                                                                                    | 29    |
| `ls -lh $(which ls)`                                                                                                                                                                                                                                                                                                                                                                                                       | 29    |
| `which ls`                                                                                                                                                                                                                                                                                                                                                                                                                 | 29    |
| `crontab -l`                                                                                                                                                                                                                                                                                                                                                                                                               | 29    |
| `w`                                                                                                                                                                                                                                                                                                                                                                                                                        | 29    |
| `uname -m`                                                                                                                                                                                                                                                                                                                                                                                                                 | 29    |
| `cat /proc/cpuinfo | grep model | grep name | wc -l`                                                                                                                                                                                                                                                                                                                                                                         | 29    |
| `top`                                                                                                                                                                                                                                                                                                                                                                                                                      | 29    |
| `uname`                                                                                                                                                                                                                                                                                                                                                                                                                    | 29    |
| `uname -a`                                                                                                                                                                                                                                                                                                                                                                                                                 | 30    |
| `whoami`                                                                                                                                                                                                                                                                                                                                                                                                                   | 30    |
| `lscpu | grep Model`                                                                                                                                                                                                                                                                                                                                                                                                       | 30    |
| `df -h | head -n 2 | awk 'FNR == 2 {print $2;}'`                                                                                                                                                                                                                                                                                                                                                                               | 30    |
| `Enter new UNIX password: `                                                                                                                                                                                                                                                                                                                                                                                                | 15    |
| `Enter new UNIX password:`                                                                                                                                                                                                                                                                                                                                                                                                 | 15    |

**Notes and Limitations:**

*   The data in this report is based on a limited time frame and may not be representative of long-term trends.
*   The IP addresses listed are the immediate source of the attack and may be part of a larger botnet or compromised system.
*   The commands listed are those that were attempted by the attackers and may not have been successfully executed.
*   The CVEs listed are based on signatures from Suricata and may not represent actual successful exploitation.

This report is intended for informational purposes and should be used to improve the security posture of the organization. Further analysis of the raw logs is recommended for a more in-depth understanding of the threats.

**End of Report**