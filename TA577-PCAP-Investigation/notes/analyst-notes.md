Scenario
A client reported that their computer has been acting strangely after clicking on a link from an email. Unfortunately, we do not have the email, but the client indicated that they clicked the link on December 15th, 2023, shortly after 4:00 PM UTC. Thankfully, have PCAPs, and tasked you to investigate what happened.

Assume we have no access to their SIEM to query data.

Only focus on this PCAP, no need to perform malware analysis.

IOC
Suspicious domains identified:
jinjadiocese.com
keebling.com
paumbachers.com

Multiple .dat pseudo-domains:
0.9091680638418338.dat
0.15903095867113098.dat
0.23982530077710623.dat

| Domain                 | Resolved IP                              |
| ---------------------- | ---------------------------------------- |
| `jinjadiocese.com`     | `68.66.226.89`                           |
| `ionister.com`         | `66.42.96.18`                            |
| `keebling.com`         | `45.77.85.150`                           |
| `paumbachers.com`      | `207.246.75.243`                         |
| `*.dat` pseudo-domains | No A record (used as redirect artifacts) |

0. capinfos TA577.pcap

1. Hierarchy Statistics

tshark -r TA577.pcap -q -z io,phs

2. Top talkers
tshark -r TA577.pcap -q -z conv,ip
 
================================================================================

3. DNS Analysis
List all DNS queries
tshark -r TA577.pcap -Y dns -T fields -e frame.time -e ip.src -e dns.qry.name

3.1 Pivot DNS → IP resolutions
tshark -r TA577.pcap -Y "dns.flags.response == 1" -T fields -e dns.qry.name -e dns.a

jinjadiocese.com        68.66.226.89
0.9091680638418338.dat
ionister.com    66.42.96.18
0.23982530077710623.dat
0.15903095867113098.dat
keebling.com    45.77.85.150
baumbachers.com 207.246.75.243


4. DNS → IP Pivot 
Map domains to IP addresses
tshark -r TA577.pcap -Y "dns.flags.response == 1" -T fields -e frame.time -e dns.qry.name -e dns.a


Step 5. HTTP Analysis

5.1 List all HTTP requests
tshark -r TA577.pcap -Y http -T fields -e frame.time -e ip.src -e http.host -e http.request.uri
Dec 15, 2023 16:01:58.062241000 UTC     10.12.15.101    jinjadiocese.com        /wgm3/?60937581
Dec 15, 2023 16:01:58.471505000 UTC     68.66.226.89
Dec 15, 2023 16:01:58.519477000 UTC     10.12.15.101    jinjadiocese.com        /favicon.ico
Dec 15, 2023 16:01:58.881582000 UTC     68.66.226.89
Dec 15, 2023 16:02:02.697268000 UTC     10.12.15.101    jinjadiocese.com        /wgm3//?zKGIWQwzp=1702656118
Dec 15, 2023 16:02:04.737299000 UTC     68.66.226.89

5.2 Filter to known suspicious domains
tshark -r TA577.pcap -Y 'http.host contains "jinjadiocese" or http.host contains "keebling" or http.host contains "paumbachers" or http.host contains "ionister"' -T fields -e frame.time -e http.host -e http.request.uri
Dec 15, 2023 16:01:58.062241000 UTC     jinjadiocese.com        /wgm3/?60937581
Dec 15, 2023 16:01:58.519477000 UTC     jinjadiocese.com        /favicon.ico
Dec 15, 2023 16:02:02.697268000 UTC     jinjadiocese.com        /wgm3//?zKGIWQwzp=1702656118

5.3 Show HTTP response codes
tshark -r TA577.pcap -Y http -T fields -e frame.time -e http.host -e http.response.code


HTTP Analysis Confirms 
Click → HTTP Activity (Initial Access)
Victim IP: 10.12.15.101
Malicious domain: jinjadiocese.com
First HTTP GET: Dec 15, 2023 16:01:58 UTC 
Suspicious URIs:
/wgm3/?60937581
/wgm3//?zKGIWQwzp=1702656118

Step 6 TLS Analysis — Encrypted Follow-On Traffic

6.1 Identify TLS sessions after the HTTP activity Lists all TLS Sessions (really noisy)
tshark -r TA577.pcap -Y tls -T fields -e frame.time -e ip.src -e ip.dst -e tls.handshake.type
Dec 15, 2023 16:05:18.820423000 UTC     10.12.15.101    66.42.96.18     1
Dec 15, 2023 16:05:18.851521000 UTC     10.12.15.101    45.77.85.150    1
Dec 15, 2023 16:05:18.918795000 UTC     10.12.15.101    207.246.75.243  1
Dec 15, 2023 16:05:19.142648000 UTC     66.42.96.18     10.12.15.101    2
Dec 15, 2023 16:05:19.142661000 UTC     66.42.96.18     10.12.15.101
Dec 15, 2023 16:05:19.174270000 UTC     45.77.85.150    10.12.15.101    2
Dec 15, 2023 16:05:19.174277000 UTC     45.77.85.150    10.12.15.101
Dec 15, 2023 16:05:19.210361000 UTC     207.246.75.243  10.12.15.101    2
Dec 15, 2023 16:05:19.210366000 UTC     207.246.75.243  10.12.15.101

6.2 Focus on TLS traffic from the victim host
tshark -r TA577.pcap -Y 'tls and ip.src == 10.12.15.101' -T fields -e frame.time -e ip.dst
Dec 15, 2023 16:05:18.820423000 UTC     66.42.96.18
Dec 15, 2023 16:05:18.851521000 UTC     45.77.85.150
Dec 15, 2023 16:05:18.918795000 UTC     207.246.75.243
Dec 15, 2023 16:05:20.657295000 UTC     45.77.85.150
Dec 15, 2023 16:05:20.657452000 UTC     45.77.85.150
Dec 15, 2023 16:05:20.942635000 UTC     66.42.96.18
Dec 15, 2023 16:05:20.942745000 UTC     66.42.96.18
Dec 15, 2023 16:05:21.131662000 UTC     207.246.75.243
Dec 15, 2023 16:05:21.131774000 UTC     207.246.75.243
Dec 15, 2023 16:05:23.633628000 UTC     45.77.85.150
Dec 15, 2023 16:05:23.763236000 UTC     207.246.75.243
Dec 15, 2023 16:05:23.898429000 UTC     66.42.96.18


TLS Findings Meaning
1) Immediate “multi-host TLS burst” after the click

At 16:05:18 UTC, 10.12.15.101 initiates TLS handshakes to the same IPs you resolved from DNS:

66.42.96.18 (ionister.com)
45.77.85.150 (keebling.com)
207.246.75.243 (paumbachers.com)

tshark -r TA577.pcap -Y tls -T fields -e frame.time -e ip.src -e ip.dst -e tls.handshake.type
Dec 15, 2023 16:05:18.820423000 UTC     10.12.15.101    66.42.96.18     1
Dec 15, 2023 16:05:18.851521000 UTC     10.12.15.101    45.77.85.150    1
Dec 15, 2023 16:05:18.918795000 UTC     10.12.15.101    207.246.75.243  1


2) Long-running repeated TLS sessions (beacon-like pattern)

workstation repeatedly initiating TLS to rotating external IPs every few minutes (16:07, 16:09, 16:12, 16:14… all the way past 17:09).

tshark -r TA577.pcap -Y 'tls and ip.src == 10.12.15.101' -T fields -e frame.time -e ip.dst

Dec 15, 2023 16:07:48.781155000 UTC     172.232.173.141
Dec 15, 2023 16:07:49.220600000 UTC     172.232.173.141
Dec 15, 2023 16:07:49.569457000 UTC     172.232.173.141
Dec 15, 2023 16:07:49.569627000 UTC     172.232.173.141
Dec 15, 2023 16:07:49.569637000 UTC     172.232.173.141
Dec 15, 2023 16:09:58.365770000 UTC     45.76.98.136
Dec 15, 2023 16:09:58.900389000 UTC     45.76.98.136
Dec 15, 2023 16:09:59.443818000 UTC     45.76.98.136
Dec 15, 2023 16:09:59.443981000 UTC     45.76.98.136
Dec 15, 2023 16:09:59.443993000 UTC     45.76.98.136
Dec 15, 2023 16:12:08.571733000 UTC     51.83.253.102
Dec 15, 2023 16:12:09.068058000 UTC     51.83.253.102
Dec 15, 2023 16:12:09.490031000 UTC     51.83.253.102
Dec 15, 2023 16:12:09.490106000 UTC     51.83.253.102
Dec 15, 2023 16:12:09.490116000 UTC     51.83.253.102
Dec 15, 2023 16:14:18.924627000 UTC     57.128.109.221
Dec 15, 2023 16:14:19.424213000 UTC     57.128.109.221
Dec 15, 2023 16:14:19.846536000 UTC     57.128.109.221
Dec 15, 2023 16:14:19.846698000 UTC     57.128.109.221
Dec 15, 2023 16:14:19.847175000 UTC     57.128.109.221
Dec 15, 2023 16:16:28.256445000 UTC     141.95.108.252
Dec 15, 2023 16:16:28.761014000 UTC     141.95.108.252
Dec 15, 2023 16:16:29.177312000 UTC     141.95.108.252
Dec 15, 2023 16:16:29.177495000 UTC     141.95.108.252
Dec 15, 2023 16:16:29.177522000 UTC     141.95.108.252

Step 7 Extract the “Top C2 IPs”
tshark -r TA577.pcap -Y 'tls and ip.src==10.12.15.101' -T fields -e ip.dst | sort | uniq -c | sort -nr
     15 57.128.83.129
     15 57.128.164.11
     15 57.128.109.221
     15 57.128.108.132
     15 51.83.253.102
     15 45.76.98.136
     15 172.232.173.141
     15 154.211.12.126
     15 141.95.108.252
      4 66.42.96.18
      4 45.77.85.150
      4 207.246.75.243

Step 8 Get SNI (Domain Names) from TLS
tshark -r TA577.pcap -Y 'tls.handshake.extensions_server_name and ip.src==10.12.15.101' -T fields -e frame.time -e ip.dst -e tls.handshake.extensions_server_name
Dec 15, 2023 16:05:18.820423000 UTC     66.42.96.18     ionister.com
Dec 15, 2023 16:05:18.851521000 UTC     45.77.85.150    keebling.com
Dec 15, 2023 16:05:18.918795000 UTC     207.246.75.243  baumbachers.com

Step 9 Build Final Timeline

16:01:57 DNS query for jinjadiocese.com

16:01:58 HTTP GET to jinjadiocese.com/wgm3/?... (200 OK)

16:02:02 Additional HTTP GET to /wgm3//?zKGI... (200 OK)

16:05:18 TLS burst to 66.42.96.18, 45.77.85.150, 207.246.75.243

16:05:39 → 17:09+ Repeated TLS connections to multiple external IPs (beacon-like)


Phase 1 — Immediate post-click burst (staging/redirect infra)

These 3 IPs were hit right after the HTTP activity (~16:05:18 UTC) and match your DNS-resolved domains:

66.42.96.18 (ionister.com) — 4

45.77.85.150 (keebling.com) — 4

207.246.75.243 (paumbachers.com) — 4

Phase 2 — Repeated TLS “beacon-like” behavior (likely C2)

Nine IPs contacted 15 times each (very uniform), over a long period:

57.128.83.129 — 15
57.128.164.11 — 15
57.128.109.221 — 15
57.128.108.132 — 15
51.83.253.102 — 15
45.76.98.136 — 15
172.232.173.141 — 15
154.211.12.126 — 15
141.95.108.252 — 15

