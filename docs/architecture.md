# CyberShield Architecture & System Specification

## 1. System Overview
**CyberShield** is an academic prototype of a host-based Firewall and Intrusion Detection System (IDS). It evaluates synthetic, simulated network events in an embedded SQLite database using deterministic rule sets without capturing physical network packets or altering the host operating system's firewall.

## 2. Component Architecture

```
                    +-----------------------------+
                    |  Traffic Generator          |
                    |  (traffic_generator.py)     |
                    +--------------+--------------+
                                   | (Synthetic Events)
                                   v
                    +-----------------------------+
                    |  Firewall Engine            |
                    |  (firewall.py)              |
                    +--------------+--------------+
                                   | (Evaluated Events)
                                   v
                    +-----------------------------+
                    |  Intrusion Detection (IDS)  |
                    |  (intrusion_detection.py)   |
                    +--------------+--------------+
                                   | (Events + Alerts)
                                   v
                    +-----------------------------+
                    |  SQLite Database            |
                    |  (database.py)              |
                    +--------------+--------------+
                                   | (Stored Telemetry)
                                   v
                    +-----------------------------+
                    |  Streamlit Dashboard UI     |
                    |  (app.py)                   |
                    +-----------------------------+
```

### Module Responsibilities:
- **`app.py`**: Streamlit-based UI handling dark-themed navigation, interactive controls, Plotly charting, and data presentation across 7 pages.
- **`database.py`**: Thread-safe SQLite management using parameterized queries, transactions, and automated schema migrations.
- **`traffic_generator.py`**: Deterministic synthetic event generator producing realistic normal web (HTTP/HTTPS), DNS queries, ICMP ping, port scan probes, repeated connection floods, and traffic to blocked ports/IPs.
- **`firewall.py`**: Sequential priority-based packet evaluation. Matches `(Source IP, Destination Port, Protocol)` tuples against enabled rules. Employs default ALLOW policy for unmatched traffic.
- **`intrusion_detection.py`**: Rule-based heuristic IDS identifying:
  - **Port Scans:** `>= 10` distinct ports probed within a 60-second window.
  - **Repeated Connections:** `>= 20` connection attempts from a single source host within 60 seconds.
  - Stateful incident deduplication to prevent alert flooding.
- **`evaluation.py`**: Empirical scenario benchmarking against ground-truth labels measuring firewall decision accuracy, detection rate (recall), false-positive rate, and throughput latency.
- **`run.bat`**: Single-click Windows deployment and launch script.

## 3. Database Schema

### `traffic_events`
- `event_id` (TEXT PK): Unique identifier (`evt-...`).
- `timestamp` (TEXT): ISO8601 formatted datetime.
- `source_ip` (TEXT): Originating IPv4 address.
- `destination_ip` (TEXT): Destination IPv4 address.
- `source_port` (INTEGER): Ephemeral source port.
- `destination_port` (INTEGER): Target service port.
- `protocol` (TEXT): TCP, UDP, or ICMP.
- `event_type` (TEXT): Description tagged with `[SIMULATED]`.
- `firewall_decision` (TEXT): `ALLOW` or `BLOCK`.
- `matched_rule_id` (INTEGER): Foreign ID of rule applied.
- `matched_rule_name` (TEXT): Name of rule applied.
- `traffic_classification` (TEXT): `Normal` or `Suspicious`.
- `connection_outcome` (TEXT): `Established`, `Denied`, or `Echo Reply`.
- `is_simulated` (INTEGER): Flagged as `1`.
- `scenario_tag` (TEXT): Ground-truth category tag.

### `firewall_rules`
- `rule_id` (INTEGER PK AUTOINCREMENT)
- `rule_name` (TEXT)
- `source_ip` (TEXT): Specific IP or `ANY`.
- `destination_port` (TEXT): Specific port or `ANY`.
- `protocol` (TEXT): `TCP`, `UDP`, `ICMP`, or `ANY`.
- `action` (TEXT): `ALLOW` or `BLOCK`.
- `enabled` (INTEGER): `1` (Active) or `0` (Disabled).
- `priority` (INTEGER): Evaluation order (lower = higher priority).
- `created_at` (TEXT)

### `security_alerts`
- `alert_id` (TEXT PK): Unique alert reference (`alt-...`).
- `timestamp` (TEXT)
- `source_ip` (TEXT)
- `detection_type` (TEXT): `Port Scan` or `Repeated Connections`.
- `severity` (TEXT): `LOW`, `MEDIUM`, or `HIGH`.
- `detection_reason` (TEXT): Plain-text technical explanation.
- `related_event_ids` (TEXT): Comma-separated list of event IDs in incident window.
- `is_acknowledged` (INTEGER): `0` (New) or `1` (Investigated).
- `acknowledged_at` (TEXT)

### `test_runs`
- `run_id` (TEXT PK)
- `timestamp` (TEXT)
- `scenario_name` (TEXT)
- `total_events` (INTEGER)
- `firewall_accuracy` (REAL)
- `detection_rate` (REAL)
- `false_positive_rate` (REAL)
- `avg_processing_time_ms` (REAL)
- `details` (TEXT)
