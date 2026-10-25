# CyberShield: Firewall and Intrusion Detection System (IDS)

An academic, locally running security prototype built in Python with **Streamlit**, **Plotly**, and **SQLite**.

> [!NOTE]
> **Academic Prototype Notice:** This application simulates network traffic locally in an embedded database. It does NOT capture live network packets, invoke raw sockets, require administrator privileges, or modify the host operating system's firewall.

---

## 🌟 Key Features

### 1. Security Operations Dashboard
- Live telemetry cards: Total Events, Allowed Events, Blocked Events, Suspicious Events, and Active Alerts.
- Plotly visual analytics: Event volume over time, protocol distribution (TCP/UDP/ICMP), and severity breakdown.
- Telemetry derived strictly from persistent SQLite storage (no hardcoded metrics).

### 2. Network Traffic Monitor
- Real-time event stream table with filters for Source IP, Protocol, Firewall Decision, and Classification.
- On-demand scenario generation:
  - Generate 25 or 100 events
  - Simulate Port Scan attacks
  - Simulate Repeated Connection bursts
  - Simulate Blocked IP / Port probes
  - Simulate Normal Web and DNS traffic

### 3. Stateful Firewall Rule Management
- Manage priority-ordered access control rules matching `(Source IP, Destination Port, Protocol)`.
- Configure actions: `ALLOW` or `BLOCK`.
- Real-time rule toggle (Enable / Disable) and rule deletion.
- Integrated **Rule Tester** to evaluate simulated packets against current policies.
- Default fallback policy: `ALLOW` for unmatched events.

### 4. Deterministic Heuristic Intrusion Detection System (IDS)
- **Port Scan Detection:** Identifies reconnaissance when a single source host probes $\ge 10$ distinct destination ports within a 60-second window.
- **Repeated Connection Attempts:** Identifies volume-based attacks when $\ge 20$ requests originate from the same host within 60 seconds.
- Configurable thresholds and sliding time windows.
- Intelligent deduplication window preventing duplicate alerts for ongoing incidents.

### 5. Security Incidents & Alerts
- Detailed alert log showing Alert ID, Timestamp, Originating IP, Detection Type, Severity (LOW / MEDIUM / HIGH), and detailed reasoning.
- Expandable list of related simulated event IDs.
- In-place incident acknowledgement tracking.

### 6. Event Logs & CSV Export
- Searchable audit log with multi-criteria filtering.
- One-click CSV export of filtered records directly from the database.

### 7. Benchmark & Scenario Evaluation
- Empirical benchmarking of 5 ground-truth scenarios:
  1. Normal mixed web & DNS traffic
  2. Traffic matching an ALLOW rule
  3. Traffic matching a BLOCK rule
  4. Port scan reconnaissance
  5. Repeated connection bursts
- Rigorous metrics:
  - Firewall Decision Accuracy
  - IDS Detection Rate (Sensitivity / Recall): $\text{TP} / (\text{TP} + \text{FN})$
  - False-Positive Rate: $\text{FP} / (\text{FP} + \text{TN})$
  - Confusion Matrix (TP, FP, TN, FN)
  - Latency / Average processing time per event

---

## 🚀 Windows Quick Start

### Prerequisites
- Windows 10 / 11
- Python 3.10 or higher installed with `python` added to PATH.

### Option A: One-Click Launcher (`run.bat`)
Double-click `run.bat` in the project root folder. The script will:
1. Verify Python availability.
2. Automatically create the `.venv` virtual environment if not present.
3. Install required packages from `requirements.txt`.
4. Launch the Streamlit dashboard in your default browser at `http://localhost:8501`.

### Option B: Manual Setup via PowerShell / CMD
```powershell
# 1. Clone or open the project folder
cd C:\Users\ROHIT\Desktop\IDS

# 2. Create and activate virtual environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run the application
streamlit run app.py
```

---

## 🧪 Running Automated Tests

Run the full pytest suite:
```powershell
.\.venv\Scripts\python.exe -m pytest -v
```

All 16 test cases verify:
- Database creation, migrations, and CRUD operations.
- Firewall rule priority, default ALLOW behavior, and disabled rule exclusion.
- IDS port scan heuristics, repeated connection floods, and deduplication.
- Evaluation metric calculations.

---

## 📂 Project Architecture

```
IDS/
├── app.py                   # Main Streamlit web application & UI navigation
├── database.py              # SQLite persistence, schema, and transactions
├── engine.py                # Pipeline coordinating Traffic -> Firewall -> IDS -> DB
├── firewall.py              # Rule matching and packet filtering engine
├── intrusion_detection.py   # Heuristic detection engine & alert creation
├── traffic_generator.py     # Deterministic synthetic traffic generator
├── evaluation.py            # Ground-truth scenario evaluation & metrics
├── requirements.txt         # Minimal third-party dependencies
├── run.bat                  # Automated Windows startup batch script
├── pytest.ini               # Pytest configuration
├── security_logs.db         # Local SQLite database (created automatically)
├── docs/
│   ├── README.md            # Docs index
│   └── architecture.md      # Detailed technical architecture specification
└── tests/
    ├── test_database.py     # Database persistence tests
    ├── test_firewall.py     # Firewall evaluation tests
    └── test_intrusion_detection.py # IDS heuristic tests
```

---

## ⚠️ Known Limitations
- **Simulation Only:** Does not bind to physical network adapters or utilize libpcap/winpcap.
- **Single-Host Prototype:** Designed for local evaluation and academic demonstration.
- **Rule-Based:** Detection relies on deterministic time-window heuristics without machine learning models.
