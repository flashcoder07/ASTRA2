# ⬡ ASTRA — Autonomous Security Threat Response Agent

**ASTRA** is an AI-driven Intrusion Detection and Prevention System (IDPS) that secures networks by moving beyond traditional rules-based security. Rather than relying on static signatures, ASTRA uses machine learning to analyze real-time network traffic, identify sophisticated cyber threats (DDoS, brute-force attempts, stealthy port scans), and mitigate them autonomously.

## 🚀 Key Features

*   **Real-Time Traffic Analysis:** Directly sniffs network packets and extracts ML-ready features.
*   **Multi-Tier Response Engine:** Dynamically calibrates countermeasures:
    *   **Tier 1:** Monitor (ALLOW)
    *   **Tier 2:** Throttle Traffic
    *   **Tier 3:** Block IP Address
    *   **Tier 4:** Isolate Host completely (via Windows Firewall)
*   **Explainable AI (XAI):** Utilizing **SHAP** (SHapley Additive exPlanations), ASTRA provides transparent context on exactly *why* traffic was classified as a threat (e.g., `fin_count unusually HIGH`).
*   **Active Learning Feedback Loop:** A modern, real-time SOC web dashboard allows security analysts to label false positives or confirm threats, which ASTRA uses to periodically retrain its own models.
*   **Automated Incident Reports:** Automatically generates structured, SOC-ready incident reports mapping out attack vectors and automated mitigations.

## 🏗️ Architecture Stack

*   **Backend:** Python 3, Flask, Flask-SocketIO
*   **Network Processing:** Scapy
*   **Machine Learning:** Scikit-Learn (Models explicitly trained on network datasets like CICIoT2023)
*   **Explainability:** SHAP
*   **Frontend Dashboard:** HTML5, Vanilla JavaScript, Custom CSS (Glassmorphism/Dark UI)
*   **OS Integration:** Windows `netsh` for firewall orchestration

## 💻 Installation

1.  **Open PowerShell as Administrator** and navigate to the project directory:
    ```powershell
    cd C:\Cyber\ASTRA
    ```

2.  **Create and activate a Virtual Environment:**
    ```powershell
    python -m venv venv
    .\venv\Scripts\Activate.ps1
    ```

3.  **Install dependencies:**
    ```powershell
    pip install -r requirements.txt
    ```

4.  **Install Npcap (Windows):**
    ASTRA requires [Npcap](https://npcap.com/#download) to sniff live network packets. Ensure it is installed in "WinPcap API-compatible mode".

## 🎮 Usage

### 1. Start the ASTRA Server
> **⚠️ Important:** You must run PowerShell as **Administrator** so ASTRA has the necessary elevation to alter Windows Firewall rules for threatening IPs.

```powershell
python app.py
```

### 2. Open the SOC Dashboard
Navigate your web browser to:
```
http://localhost:5000
```

### 3. Simulating Traffic
ASTRA includes built-in tools to simulate attacks to test the ML engine. Open a **second terminal** and try:

**Run the Attack Simulator (`attack_demo.py`):**
```powershell
python attack_demo.py --attack ddos     # Simulate a DDoS attack (Tier 4)
python attack_demo.py --attack tiers    # Cycle through all threat tiers successively
```

**Mobile Device Simulation (`client_sender.py`):**
Run this script via Termux or another device on the same LAN to ingest traffic over HTTP directly into the engine, proving real-time inference over standard network loads.

## 🧠 Active Learning

ASTRA learns from you. On the live dashboard, every threat card has **Confirm Threat** and **False Positive** buttons. Once sufficient feedback is collected, the system automatically executes `retrainer.py` to seamlessly adjust the models and minimize future false alarms, continuously adapting to your organization's unique traffic baseline.

---
*Built for proactive, intelligent network defense.*