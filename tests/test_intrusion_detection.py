"""
Unit tests for Intrusion Detection System (IDS) heuristics.
Verifies port scan detection, repeated connection detection, deduplication, and severity scoring.
"""

from datetime import datetime, timedelta
import intrusion_detection as ids
import traffic_generator as tg


def test_normal_traffic_no_alerts():
    events = tg.generate_normal_traffic(count=20)
    updated_events, alerts = ids.analyze_traffic_stream(new_events=events)
    assert len(alerts) == 0
    # None should be classified as Suspicious
    for e in updated_events:
        assert e["traffic_classification"] == "Normal"


def test_port_scan_detection():
    # Generate 15 distinct ports from single IP (threshold is 10)
    scanner_ip = "198.51.100.99"
    scan_events = tg.generate_port_scan_traffic(attacker_ip=scanner_ip, ports=list(range(1000, 1015)))
    updated_events, alerts = ids.analyze_traffic_stream(new_events=scan_events)

    assert len(alerts) == 1
    alert = alerts[0]
    assert alert["source_ip"] == scanner_ip
    assert alert["detection_type"] == "Port Scan"
    assert alert["severity"] in ["MEDIUM", "HIGH"]
    assert "Port Scan detected" in alert["detection_reason"]
    assert len(alert["related_event_ids"]) > 0

    # Ensure all scan events were marked as Suspicious
    for e in updated_events:
        assert e["traffic_classification"] == "Suspicious"


def test_repeated_connections_detection():
    # Generate 25 connections to port 80 from single IP (threshold is 20)
    flood_ip = "203.0.113.77"
    flood_events = tg.generate_repeated_connection_traffic(attacker_ip=flood_ip, count=25, target_port=80)
    updated_events, alerts = ids.analyze_traffic_stream(new_events=flood_events)

    assert len(alerts) == 1
    alert = alerts[0]
    assert alert["source_ip"] == flood_ip
    assert alert["detection_type"] == "Repeated Connections"
    assert "repeated connection attempts detected" in alert["detection_reason"]


def test_deduplication_prevents_alert_flooding():
    # If an alert was recently generated within the dedup window for the same IP and type,
    # another alert should not be created.
    scanner_ip = "198.51.100.88"
    scan_events = tg.generate_port_scan_traffic(attacker_ip=scanner_ip, ports=list(range(2000, 2015)))
    
    # Set high repeated connection threshold so we test port scan deduplication specifically
    cfg = dict(ids.DEFAULT_IDS_CONFIG)
    cfg["repeated_conn_threshold"] = 50

    # First batch triggers alert
    _, alerts_1 = ids.analyze_traffic_stream(new_events=scan_events, config=cfg)
    assert len(alerts_1) == 1
    assert alerts_1[0]["detection_type"] == "Port Scan"

    # Second batch immediately following with historical alert passed in
    _, alerts_2 = ids.analyze_traffic_stream(
        new_events=scan_events,
        historical_events=scan_events,
        recent_alerts=alerts_1,
        config=cfg
    )
    # Deduplication should prevent duplicate port scan alert
    # assert len(alerts_2) == 0
    assert len(alerts_2) == 0


def test_custom_configurable_thresholds():
    # Lower threshold to 3 distinct ports
    custom_cfg = dict(ids.DEFAULT_IDS_CONFIG)
    custom_cfg["port_scan_threshold"] = 3

    mini_scan = tg.generate_port_scan_traffic(attacker_ip="192.168.1.99", ports=[21, 22, 23])
    _, alerts = ids.analyze_traffic_stream(new_events=mini_scan, config=custom_cfg)
    assert len(alerts) == 1
