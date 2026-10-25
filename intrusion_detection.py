"""
Intrusion Detection System (IDS) Engine.
Deterministic heuristic rule-based detection for:
1. Port Scan: >= N distinct destination ports from same source IP within time window.
2. Repeated Connection Attempts: >= N events from same source IP within time window.
"""

import uuid
from datetime import datetime, timedelta
from typing import List, Dict, Any, Tuple, Optional

DEFAULT_IDS_CONFIG = {
    "port_scan_threshold": 10,       # Distinct ports
    "port_scan_window_sec": 60,      # Seconds
    "repeated_conn_threshold": 20,   # Event count
    "repeated_conn_window_sec": 60,  # Seconds
    "dedup_window_sec": 60           # Avoid repeat alert for same source IP & type
}


def parse_timestamp(ts_str: str) -> datetime:
    """Parse timestamp string supporting ISO and common formats."""
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S.%f"):
        try:
            return datetime.strptime(ts_str, fmt)
        except (ValueError, TypeError):
            continue
    return datetime.now()


def analyze_traffic_stream(
    new_events: List[Dict[str, Any]],
    historical_events: Optional[List[Dict[str, Any]]] = None,
    recent_alerts: Optional[List[Dict[str, Any]]] = None,
    config: Optional[Dict[str, Any]] = None
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Analyze a batch of newly generated events against recent history.
    Detects Port Scans and Repeated Connection Attempts.
    
    Returns:
    - updated_events: List of new events with updated 'traffic_classification' ('Normal' or 'Suspicious')
    - generated_alerts: List of newly generated security alert records
    """
    cfg = dict(DEFAULT_IDS_CONFIG)
    if config:
        cfg.update(config)

    all_events = list(historical_events or []) + list(new_events)
    # Parse event times
    event_records = []
    for evt in all_events:
        dt = parse_timestamp(evt.get("timestamp", ""))
        event_records.append((dt, evt))

    # Sort all events by timestamp ascending
    event_records.sort(key=lambda x: x[0])

    # Build index of recent alerts for deduplication
    # Key: (source_ip, detection_type) -> most recent alert datetime
    alert_history: Dict[Tuple[str, str], datetime] = {}
    if recent_alerts:
        for alt in recent_alerts:
            key = (str(alt.get("source_ip", "")).strip(), str(alt.get("detection_type", "")).strip())
            alt_dt = parse_timestamp(alt.get("timestamp", ""))
            if key not in alert_history or alt_dt > alert_history[key]:
                alert_history[key] = alt_dt

    generated_alerts: List[Dict[str, Any]] = []
    suspicious_event_ids = set()

    # Group events by source IP
    events_by_ip: Dict[str, List[Tuple[datetime, Dict[str, Any]]]] = {}
    for dt, evt in event_records:
        ip = str(evt.get("source_ip", "")).strip()
        events_by_ip.setdefault(ip, []).append((dt, evt))

    # Evaluate each source IP's recent activity
    for ip, ip_evts in events_by_ip.items():
        if not ip_evts:
            continue

        latest_dt = ip_evts[-1][0]

        # -------------------------------------------------------------
        # Detection Rule 1: Port Scan Detection
        # -------------------------------------------------------------
        ps_window_start = latest_dt - timedelta(seconds=cfg["port_scan_window_sec"])
        ps_window_evts = [
            (dt, e) for dt, e in ip_evts
            if dt >= ps_window_start and int(e.get("destination_port", 0)) > 0
        ]
        distinct_ports = {int(e.get("destination_port")) for _, e in ps_window_evts}

        if len(distinct_ports) >= cfg["port_scan_threshold"]:
            # Check deduplication
            last_alert_time = alert_history.get((ip, "Port Scan"))
            should_alert = True
            if last_alert_time:
                if (latest_dt - last_alert_time).total_seconds() < cfg["dedup_window_sec"]:
                    should_alert = False

            if should_alert:
                port_count = len(distinct_ports)
                severity = "HIGH" if port_count >= cfg["port_scan_threshold"] * 1.8 else "MEDIUM"
                related_ids = [e["event_id"] for _, e in ps_window_evts[-30:]]  # up to last 30 IDs
                now_str = latest_dt.strftime("%Y-%m-%d %H:%M:%S")

                alert_id = f"alt-ps-{uuid.uuid4().hex[:8]}"
                reason = (
                    f"Heuristic Port Scan detected from {ip}: probed {port_count} distinct ports "
                    f"(threshold: {cfg['port_scan_threshold']}) within {cfg['port_scan_window_sec']}s window."
                )

                alert = {
                    "alert_id": alert_id,
                    "timestamp": now_str,
                    "source_ip": ip,
                    "detection_type": "Port Scan",
                    "severity": severity,
                    "detection_reason": reason,
                    "related_event_ids": ",".join(related_ids),
                    "is_acknowledged": 0,
                    "acknowledged_at": None
                }
                generated_alerts.append(alert)
                alert_history[(ip, "Port Scan")] = latest_dt

            # Mark all events in this incident as suspicious
            for _, e in ps_window_evts:
                suspicious_event_ids.add(e["event_id"])

        # -------------------------------------------------------------
        # Detection Rule 2: Repeated Connection Attempts Detection
        # -------------------------------------------------------------
        rc_window_start = latest_dt - timedelta(seconds=cfg["repeated_conn_window_sec"])
        rc_window_evts = [
            (dt, e) for dt, e in ip_evts
            if dt >= rc_window_start
        ]

        if len(rc_window_evts) >= cfg["repeated_conn_threshold"]:
            last_alert_time = alert_history.get((ip, "Repeated Connections"))
            should_alert = True
            if last_alert_time:
                if (latest_dt - last_alert_time).total_seconds() < cfg["dedup_window_sec"]:
                    should_alert = False

            if should_alert:
                conn_count = len(rc_window_evts)
                severity = "HIGH" if conn_count >= cfg["repeated_conn_threshold"] * 2 else "MEDIUM"
                related_ids = [e["event_id"] for _, e in rc_window_evts[-30:]]
                now_str = latest_dt.strftime("%Y-%m-%d %H:%M:%S")

                alert_id = f"alt-rc-{uuid.uuid4().hex[:8]}"
                reason = (
                    f"Excessive repeated connection attempts detected from {ip}: {conn_count} requests "
                    f"(threshold: {cfg['repeated_conn_threshold']}) within {cfg['repeated_conn_window_sec']}s window."
                )

                alert = {
                    "alert_id": alert_id,
                    "timestamp": now_str,
                    "source_ip": ip,
                    "detection_type": "Repeated Connections",
                    "severity": severity,
                    "detection_reason": reason,
                    "related_event_ids": ",".join(related_ids),
                    "is_acknowledged": 0,
                    "acknowledged_at": None
                }
                generated_alerts.append(alert)
                alert_history[(ip, "Repeated Connections")] = latest_dt

            # Mark all events in this incident as suspicious
            for _, e in rc_window_evts:
                suspicious_event_ids.add(e["event_id"])

    # Update new events' classification
    updated_events = []
    for evt in new_events:
        evt_copy = dict(evt)
        # If scenario explicitly labeled suspicious or IDS flagged it
        if (
            evt_copy.get("event_id") in suspicious_event_ids
            or evt_copy.get("traffic_classification") == "Suspicious"
        ):
            evt_copy["traffic_classification"] = "Suspicious"
        else:
            evt_copy["traffic_classification"] = "Normal"
        updated_events.append(evt_copy)

    return updated_events, generated_alerts
