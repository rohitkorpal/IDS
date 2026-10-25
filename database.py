"""
Database module for Firewall and Intrusion Detection System (IDS).
Handles SQLite operations, table schemas, parameterized queries, and transactions.
"""

import sqlite3
import os
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime

DEFAULT_DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "security_logs.db")


def get_connection(db_path: str = DEFAULT_DB_PATH) -> sqlite3.Connection:
    """Create a connection to the SQLite database with row factory enabled."""
    conn = sqlite3.connect(db_path, timeout=10.0, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(db_path: str = DEFAULT_DB_PATH) -> None:
    """Initialize database and create all required tables automatically."""
    conn = get_connection(db_path)
    try:
        with conn:
            cursor = conn.cursor()

            # 1. Traffic events table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS traffic_events (
                    event_id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    source_ip TEXT NOT NULL,
                    destination_ip TEXT NOT NULL,
                    source_port INTEGER NOT NULL,
                    destination_port INTEGER NOT NULL,
                    protocol TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    firewall_decision TEXT NOT NULL,
                    matched_rule_id INTEGER,
                    matched_rule_name TEXT,
                    traffic_classification TEXT NOT NULL,
                    connection_outcome TEXT NOT NULL,
                    is_simulated INTEGER DEFAULT 1,
                    scenario_tag TEXT
                )
            """)

            # Index for performance in IDS detection & dashboard queries
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_src_time ON traffic_events(source_ip, timestamp)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_time ON traffic_events(timestamp)")

            # 2. Firewall rules table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS firewall_rules (
                    rule_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    rule_name TEXT NOT NULL,
                    source_ip TEXT NOT NULL,
                    destination_port TEXT NOT NULL,
                    protocol TEXT NOT NULL,
                    action TEXT NOT NULL,
                    enabled INTEGER DEFAULT 1,
                    priority INTEGER DEFAULT 10,
                    created_at TEXT NOT NULL
                )
            """)

            # 3. Security alerts table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS security_alerts (
                    alert_id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    source_ip TEXT NOT NULL,
                    detection_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    detection_reason TEXT NOT NULL,
                    related_event_ids TEXT NOT NULL,
                    is_acknowledged INTEGER DEFAULT 0,
                    acknowledged_at TEXT
                )
            """)

            cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_time ON security_alerts(timestamp)")

            # 4. Test runs table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS test_runs (
                    run_id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    scenario_name TEXT NOT NULL,
                    total_events INTEGER NOT NULL,
                    firewall_accuracy REAL NOT NULL,
                    detection_rate REAL NOT NULL,
                    false_positive_rate REAL NOT NULL,
                    avg_processing_time_ms REAL NOT NULL,
                    details TEXT
                )
            """)

            # Seed default firewall rules if table is empty
            cursor.execute("SELECT COUNT(*) FROM firewall_rules")
            if cursor.fetchone()[0] == 0:
                default_rules = [
                    ("Block Known Malicious IP", "198.51.100.25", "ANY", "ANY", "BLOCK", 1, 1),
                    ("Block Suspicious Subnet", "203.0.113.15", "ANY", "ANY", "BLOCK", 1, 2),
                    ("Block Inbound Telnet (Port 23)", "ANY", "23", "TCP", "BLOCK", 1, 3),
                    ("Block Inbound SMB (Port 445)", "ANY", "445", "TCP", "BLOCK", 1, 4),
                    ("Allow Web HTTPS", "ANY", "443", "TCP", "ALLOW", 1, 5),
                    ("Allow Web HTTP", "ANY", "80", "TCP", "ALLOW", 1, 6),
                    ("Allow DNS Queries", "ANY", "53", "UDP", "ALLOW", 1, 7),
                ]
                now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                for name, src_ip, dport, proto, action, enabled, prio in default_rules:
                    cursor.execute("""
                        INSERT INTO firewall_rules (rule_name, source_ip, destination_port, protocol, action, enabled, priority, created_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """, (name, src_ip, dport, proto, action, enabled, prio, now_str))

    finally:
        conn.close()


# -------------------------------------------------------------
# Traffic Events Operations
# -------------------------------------------------------------

def insert_traffic_events(events: List[Dict[str, Any]], db_path: str = DEFAULT_DB_PATH) -> None:
    """Insert multiple traffic event records within a transaction."""
    if not events:
        return
    conn = get_connection(db_path)
    try:
        with conn:
            cursor = conn.cursor()
            for evt in events:
                cursor.execute("""
                    INSERT INTO traffic_events (
                        event_id, timestamp, source_ip, destination_ip,
                        source_port, destination_port, protocol, event_type,
                        firewall_decision, matched_rule_id, matched_rule_name,
                        traffic_classification, connection_outcome, is_simulated, scenario_tag
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    evt["event_id"],
                    evt["timestamp"],
                    evt["source_ip"],
                    evt["destination_ip"],
                    int(evt["source_port"]),
                    int(evt["destination_port"]),
                    evt["protocol"].upper(),
                    evt["event_type"],
                    evt["firewall_decision"].upper(),
                    evt.get("matched_rule_id"),
                    evt.get("matched_rule_name"),
                    evt["traffic_classification"],
                    evt["connection_outcome"],
                    int(evt.get("is_simulated", 1)),
                    evt.get("scenario_tag")
                ))
    finally:
        conn.close()


def get_traffic_events(
    limit: Optional[int] = 500,
    offset: int = 0,
    source_ip: Optional[str] = None,
    protocol: Optional[str] = None,
    decision: Optional[str] = None,
    classification: Optional[str] = None,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    db_path: str = DEFAULT_DB_PATH
) -> List[Dict[str, Any]]:
    """Retrieve filtered traffic events ordered by timestamp descending."""
    conn = get_connection(db_path)
    try:
        query = "SELECT * FROM traffic_events WHERE 1=1"
        params: List[Any] = []

        if source_ip and source_ip.strip():
            query += " AND source_ip LIKE ?"
            params.append(f"%{source_ip.strip()}%")
        if protocol and protocol != "ALL":
            query += " AND protocol = ?"
            params.append(protocol.upper())
        if decision and decision != "ALL":
            query += " AND firewall_decision = ?"
            params.append(decision.upper())
        if classification and classification != "ALL":
            query += " AND traffic_classification = ?"
            params.append(classification)
        if start_time:
            query += " AND timestamp >= ?"
            params.append(start_time)
        if end_time:
            query += " AND timestamp <= ?"
            params.append(end_time)

        query += " ORDER BY timestamp DESC, rowid DESC"
        if limit is not None:
            query += " LIMIT ? OFFSET ?"
            params.extend([limit, offset])

        cursor = conn.cursor()
        cursor.execute(query, params)
        rows = cursor.fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()


def get_traffic_stats(db_path: str = DEFAULT_DB_PATH) -> Dict[str, Any]:
    """Retrieve summary counts for the dashboard directly from stored records."""
    conn = get_connection(db_path)
    try:
        cursor = conn.cursor()

        cursor.execute("SELECT COUNT(*) FROM traffic_events")
        total_events = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM traffic_events WHERE firewall_decision = 'ALLOW'")
        allowed_events = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM traffic_events WHERE firewall_decision = 'BLOCK'")
        blocked_events = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM traffic_events WHERE traffic_classification = 'Suspicious'")
        suspicious_events = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM security_alerts")
        total_alerts = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM security_alerts WHERE is_acknowledged = 0")
        unacknowledged_alerts = cursor.fetchone()[0]

        return {
            "total_events": total_events,
            "allowed_events": allowed_events,
            "blocked_events": blocked_events,
            "suspicious_events": suspicious_events,
            "total_alerts": total_alerts,
            "unacknowledged_alerts": unacknowledged_alerts
        }
    finally:
        conn.close()


# -------------------------------------------------------------
# Firewall Rules Operations
# -------------------------------------------------------------

def get_firewall_rules(db_path: str = DEFAULT_DB_PATH, only_enabled: bool = False) -> List[Dict[str, Any]]:
    """Retrieve all firewall rules ordered by priority ascending."""
    conn = get_connection(db_path)
    try:
        cursor = conn.cursor()
        query = "SELECT * FROM firewall_rules"
        if only_enabled:
            query += " WHERE enabled = 1"
        query += " ORDER BY priority ASC, rule_id ASC"
        cursor.execute(query)
        rows = cursor.fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()


def add_firewall_rule(
    rule_name: str,
    source_ip: str,
    destination_port: str,
    protocol: str,
    action: str,
    enabled: int = 1,
    priority: int = 10,
    db_path: str = DEFAULT_DB_PATH
) -> int:
    """Add a new firewall rule and return its generated ID."""
    conn = get_connection(db_path)
    try:
        with conn:
            cursor = conn.cursor()
            now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            cursor.execute("""
                INSERT INTO firewall_rules (rule_name, source_ip, destination_port, protocol, action, enabled, priority, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                rule_name.strip(),
                source_ip.strip(),
                str(destination_port).strip(),
                protocol.strip().upper(),
                action.strip().upper(),
                enabled,
                priority,
                now_str
            ))
            return cursor.lastrowid
    finally:
        conn.close()


def update_rule_status(rule_id: int, enabled: int, db_path: str = DEFAULT_DB_PATH) -> bool:
    """Enable or disable a firewall rule."""
    conn = get_connection(db_path)
    try:
        with conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE firewall_rules SET enabled = ? WHERE rule_id = ?", (enabled, rule_id))
            return cursor.rowcount > 0
    finally:
        conn.close()


def delete_firewall_rule(rule_id: int, db_path: str = DEFAULT_DB_PATH) -> bool:
    """Delete a firewall rule by ID."""
    conn = get_connection(db_path)
    try:
        with conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM firewall_rules WHERE rule_id = ?", (rule_id,))
            return cursor.rowcount > 0
    finally:
        conn.close()


# -------------------------------------------------------------
# Security Alerts Operations
# -------------------------------------------------------------

def insert_security_alerts(alerts: List[Dict[str, Any]], db_path: str = DEFAULT_DB_PATH) -> None:
    """Insert security alert records."""
    if not alerts:
        return
    conn = get_connection(db_path)
    try:
        with conn:
            cursor = conn.cursor()
            for alt in alerts:
                cursor.execute("""
                    INSERT OR IGNORE INTO security_alerts (
                        alert_id, timestamp, source_ip, detection_type,
                        severity, detection_reason, related_event_ids, is_acknowledged, acknowledged_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    alt["alert_id"],
                    alt["timestamp"],
                    alt["source_ip"],
                    alt["detection_type"],
                    alt["severity"].upper(),
                    alt["detection_reason"],
                    alt["related_event_ids"],
                    int(alt.get("is_acknowledged", 0)),
                    alt.get("acknowledged_at")
                ))
    finally:
        conn.close()


def get_security_alerts(
    severity: Optional[str] = None,
    status: Optional[str] = None,
    limit: Optional[int] = 200,
    db_path: str = DEFAULT_DB_PATH
) -> List[Dict[str, Any]]:
    """Retrieve security alerts filtered by severity or acknowledgement status."""
    conn = get_connection(db_path)
    try:
        query = "SELECT * FROM security_alerts WHERE 1=1"
        params: List[Any] = []

        if severity and severity != "ALL":
            query += " AND severity = ?"
            params.append(severity.upper())
        if status == "ACKNOWLEDGED":
            query += " AND is_acknowledged = 1"
        elif status == "UNACKNOWLEDGED":
            query += " AND is_acknowledged = 0"

        query += " ORDER BY timestamp DESC, rowid DESC"
        if limit is not None:
            query += " LIMIT ?"
            params.append(limit)

        cursor = conn.cursor()
        cursor.execute(query, params)
        rows = cursor.fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()


def acknowledge_alert(alert_id: str, db_path: str = DEFAULT_DB_PATH) -> bool:
    """Mark an alert as acknowledged with the current timestamp."""
    conn = get_connection(db_path)
    try:
        with conn:
            cursor = conn.cursor()
            now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            cursor.execute("""
                UPDATE security_alerts
                SET is_acknowledged = 1, acknowledged_at = ?
                WHERE alert_id = ?
            """, (now_str, alert_id))
            return cursor.rowcount > 0
    finally:
        conn.close()


# -------------------------------------------------------------
# Test Runs & Maintenance
# -------------------------------------------------------------

def save_test_run(run_data: Dict[str, Any], db_path: str = DEFAULT_DB_PATH) -> None:
    """Save an evaluation run's metrics for evaluation history."""
    conn = get_connection(db_path)
    try:
        with conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO test_runs (
                    run_id, timestamp, scenario_name, total_events,
                    firewall_accuracy, detection_rate, false_positive_rate,
                    avg_processing_time_ms, details
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                run_data["run_id"],
                run_data["timestamp"],
                run_data["scenario_name"],
                run_data["total_events"],
                run_data["firewall_accuracy"],
                run_data["detection_rate"],
                run_data["false_positive_rate"],
                run_data["avg_processing_time_ms"],
                run_data.get("details", "")
            ))
    finally:
        conn.close()


def get_test_runs(limit: int = 20, db_path: str = DEFAULT_DB_PATH) -> List[Dict[str, Any]]:
    """Retrieve recent test evaluation runs."""
    conn = get_connection(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM test_runs ORDER BY timestamp DESC LIMIT ?", (limit,))
        rows = cursor.fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()


def clear_simulation_data(clear_rules: bool = False, db_path: str = DEFAULT_DB_PATH) -> None:
    """Clear simulated traffic events, alerts, and evaluation test runs."""
    conn = get_connection(db_path)
    try:
        with conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM traffic_events")
            cursor.execute("DELETE FROM security_alerts")
            cursor.execute("DELETE FROM test_runs")
            if clear_rules:
                cursor.execute("DELETE FROM firewall_rules")
    finally:
        conn.close()
