# 📝 TA577 Network-Based Malware Investigation Report

---

## Findings

**Time:**  
2023-12-15 16:01:58 UTC

**Host:**  
10.12.15.101

**IOC Domains:**  
- jinjadiocese[.]com  
- keebling[.]com  
- baumbachers[.]com  
- ionister[.]com  

**IOC IPs:**  
- 68.66.226.89  
- 66.42.96.18  
- 45.77.85.150  
- 207.246.75.243  
- 57.128.83.129  
- 57.128.164.11  
- 57.128.109.221  
- 57.128.108.132  
- 51.83.253.102  
- 45.76.98.136  
- 172.232.173.141  
- 154.211.12.126  
- 141.95.108.252  

**Possible Malware Family:**  
TA577-associated activity (commonly used to deliver secondary malware such as Pikabot)

**Zip Filename:**  
GURVU.zip

**Zip File SHA256:**  
F24888DA47BAE0149AB5C0D887D32FC155CB42AC8138D22699AE12CE1DCA6BD1

---

## Investigation

On **2023-12-15 at 16:01:58 UTC**, the host **10.12.15.101** initiated HTTP communication with the domain **jinjadiocese[.]com**, which has been reported in the wild as malicious. Analysis of HTTP traffic shows multiple suspicious GET requests containing randomized URI parameters, consistent with traffic broker infrastructure.

At **16:02:04 UTC**, the host downloaded a ZIP archive named **GURVU.zip**. Approximately **three minutes later**, beginning at **16:05:18 UTC**, the host initiated multiple outbound **TLS-encrypted connections** to a variety of external IP addresses.

TLS analysis revealed that several external IPs were contacted **exactly 15 times**, and further inspection of TLS Client Hello packets showed **consistent ~22-minute intervals** between connections to the same IP address. This regular and repetitive pattern is indicative of **automated beaconing behavior** rather than legitimate user activity.

The infrastructure contacted during this activity aligns with **TA577 delivery frameworks**, which are commonly used to distribute secondary malware families such as **Pikabot**.

Based on the PCAP provided, there is **high confidence** that the host **10.12.15.101** was compromised and engaged in **command-and-control (C2) communication**. However, due to reliance on a single PCAP, it is **not possible to determine whether the activity persisted beyond the capture window**.

---

## WHO, WHAT, WHEN, WHERE, WHY, HOW

**WHO:**  
Host: 10.12.15.101

**WHAT:**  
Download of a malicious ZIP file followed by encrypted beaconing activity

**WHEN:**  
Activity began on 2023-12-15 at 16:01:58 UTC  
Based on the PCAP, ongoing activity beyond the capture window cannot be confirmed

**WHERE:**  
Outbound network traffic from the internal host to multiple external attacker-controlled IP addresses

**WHY:**  
To establish and maintain encrypted command-and-control communication following initial compromise

**HOW:**  
The user clicked a malicious link delivered via email, accessed a compromised website, downloaded a ZIP archive, and the contents were likely executed, resulting in automated encrypted outbound communication

---

## Recommendations

1. **Immediately isolate** the affected host and conduct a forensic investigation to determine the full scope of compromise. If forensic analysis is not feasible, reimage the system to ensure complete removal of any residual artifacts.

2. **Search the environment** for the identified domains, IP addresses, and file hash to identify any additional affected hosts. Any systems associated with these indicators should be isolated immediately.

3. **Block the identified IOC domains and IP addresses** at network security controls (firewalls, proxies, EDR). While attacker infrastructure can change, blocking known indicators can help prevent further compromise and reduce risk.

---
