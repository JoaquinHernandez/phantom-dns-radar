# phantom-dns-radar# 📡 Phantom-DNS: DGA, Tunneling & Fast-Flux Threat Radar

A lightweight network threat hunting engine designed to analyze DNS telemetry, detect algorithmic **Domain Generation Algorithms (DGA)**, identify **DNS Tunneling exfiltration channels**, and flag **Fast-Flux** IP rotation networks.

---

## ✨ Features
- **DGA Mathematical Modeling**: Uses Shannon entropy and linguistic vowel/consonant distribution ratios to separate human-registered domains from malware C2 generation loops.
- **Covert Tunneling Inspection**: Identifies base64/hex data exfiltration embedded in DNS query subdomains.
- **Fast-Flux Pool Auditing**: Detects multi-A-record resolution clustering used by threat actors to evade IP blocking.
- **MITRE ATT&CK Mapping**: Correlates findings directly to technique IDs (`T1568.001`, `T1568.002`, `T1071.004`).
- **Zero Third-Party Dependencies**: Pure Python standard library implementation.

---

## 🚀 Quick Start
```bash
python3 phantom_dns.py
