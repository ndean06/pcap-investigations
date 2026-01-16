# 🛡️ TA577 Network-Based Malware Investigation (PCAP Analysis)

## 📌 Overview
Network-only investigation of suspected **TA577** activity following a phishing email link click.  
All findings were derived **solely from a PCAP**, without SIEM or endpoint telemetry.

---

## Scope
- **Data:** Packet Capture (PCAP)
- **Tools:** Tshark, VirusTotal, whois.domaintools
- **Protocols:** HTTP, DNS, TLS

---

## High-Level Timeline

| Time (UTC) | Event |
|-----------|------|
| 16:01:58 | Malicious domain accessed |
| 16:02:04 | ZIP file downloaded |
| 16:05+ | Encrypted beaconing begins |

---

## Key Findings
- Phishing-based initial access via malicious domain
- ZIP archive downloaded shortly after access
- Outbound TLS connections initiated minutes later
- Repeated TLS connections at ~22-minute intervals
- Behavior consistent with **command-and-control beaconing**

---

## Beaconing Evidence

![TLS Beaconing Timing Evidence](screenshots/10-ip-time-pattern.png)  
*TLS Client Hello timing showing periodic outbound connections.*

---

## MITRE ATT&CK
- **T1566.002** – Phishing: Link  
- **T1204** – User Execution  
- **T1071.001** – Application Layer Protocol (Web)  
- **T1573** – Encrypted Channel  
- **T1105** – Beaconing  

---

## Recommendations
- Isolate affected host
- Hunt for related IOCs
- Block malicious infrastructure
- Review email security controls

---

## 📂 Repository Contents
- **[Full Analyst Walkthrough](./walkthrough.md)**  
- **walkthrough.md** – Full analyst investigation with screenshots
- **evidence/** – DNS, HTTP, TLS artifacts and IOCs
- **pcaps/** – Original capture file

---

## Skills Demonstrated
PCAP analysis · Beaconing detection · IOC extraction · MITRE ATT&CK mapping

