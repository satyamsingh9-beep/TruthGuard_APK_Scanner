# 🛡️ TruthGuard: AI-Assisted Android Application Security & Forensic Analysis Platform

> Built for **Bihar Cyber Hackathon 2026** | Problem Statement: **PS-02**  
> Developed by: **Team TruthGuard**

---
## 👥 The Team
- **Chandan Kumar** – Lead Architect & Forensic Core Engine (`app.py`, Static Triage)
- **[Teammate 1 Name]** – Documentation, Threat Matrix & Research
- **[Teammate 2 Name]** – Presentation, QA Testing & Evaluation
## 📌 Problem Overview
Modern Android malware and predatory apps often bypass standard perimeter defenses by requesting excessive device permissions and establishing malicious background network endpoints. Forensic analysis usually requires cumbersome command-line tools. 

**TruthGuard** delivers a unified, automated, and explainable static analysis platform that parses APK binaries, computes heuristic threat scores, identifies potential Indicators of Compromise (IoCs), and produces verifiable forensic JSON reports.

---

## 🚀 Key Features
- **Binary & Plain-XML Manifest Parsing:** Resilient decompilation and parsing of package metadata, Target SDK, and registered permissions.
- **Dynamic Heuristic Risk Scoring:** Weighted threat score (0–100) categorizing applications into *Low Risk*, *Moderate Risk*, and *Critical Risk*.
- **Explainable AI/Heuristic Insights:** Transparent explanations detailing specific threat vectors (e.g., SMS interception risks, unauthorized audio surveillance, background location tracking).
- **Network IoC Extraction:** Automated scanning of hardcoded endpoints, remote IPs, and command-and-control (C2) domains.
- **One-Click Forensic Export:** Generates standardized JSON audit reports for cyber investigators and law enforcement.

---

## 🛠️ Tech Stack & Architecture
- **Language:** Python 3.10+
- **Parsing Engine:** Androguard (Binary APK analysis) & Fallback XML Parsing
- **Frontend Dashboard:** Streamlit
- **Forensic Pipeline:** Heuristic threat evaluation engine + Regex pattern extraction

---

## ⚙️ Installation & Local Setup

### 1. Clone the Repository
```bash
git clone [https://github.com/satyamsingh9-beep/TruthGuard_APK_Scanner.git](https://github.com/satyamsingh9-beep/TruthGuard_APK_Scanner.git)
cd TruthGuard_APK_Scanner
