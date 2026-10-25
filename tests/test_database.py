"""
Unit tests for Database CRUD operations and SQLite persistence.
Verifies rules, events, alerts, and acknowledgement persistence.
"""

import os
import pytest
import database as db
import traffic_generator as tg


@pytest.fixture
def temp_db(tmp_path):
    test_db_path = str(tmp_path / "test_security.db")
    db.init_db(test_db_path)
    return test_db_path


def test_db_initialization(temp_db):
    assert os.path.exists(temp_db)
    # Default rules should be automatically seeded
    rules = db.get_firewall_rules(temp_db)
    assert len(rules) > 0


def test_firewall_rule_lifecycle(temp_db):
    # 1. Add rule
    new_id = db.add_firewall_rule(
        rule_name="Block Test IP",
        source_ip="10.10.10.10",
        destination_port="ANY",
        protocol="ANY",
        action="BLOCK",
        enabled=1,
        priority=1,
        db_path=temp_db
    )
    assert new_id > 0

    # 2. Verify retrieval
    rules = db.get_firewall_rules(temp_db)
    test_rule = next(r for r in rules if r["rule_id"] == new_id)
    assert test_rule["source_ip"] == "10.10.10.10"
    assert test_rule["action"] == "BLOCK"
    assert test_rule["enabled"] == 1

    # 3. Disable rule
    db.update_rule_status(new_id, 0, db_path=temp_db)
    rules_after_disable = db.get_firewall_rules(temp_db)
    disabled_rule = next(r for r in rules_after_disable if r["rule_id"] == new_id)
    assert disabled_rule["enabled"] == 0

    # 4. Delete rule
    db.delete_firewall_rule(new_id, db_path=temp_db)
    rules_after_del = db.get_firewall_rules(temp_db)
    assert not any(r["rule_id"] == new_id for r in rules_after_del)


def test_traffic_events_persistence_and_filtering(temp_db):
    events = tg.generate_normal_traffic(count=5)
    for e in events:
        e["firewall_decision"] = "ALLOW"
    db.insert_traffic_events(events, db_path=temp_db)

    # Fetch all
    stored = db.get_traffic_events(db_path=temp_db)
    assert len(stored) == 5

    # Filter by decision
    allowed = db.get_traffic_events(decision="ALLOW", db_path=temp_db)
    assert len(allowed) == 5

    blocked = db.get_traffic_events(decision="BLOCK", db_path=temp_db)
    assert len(blocked) == 0


def test_security_alerts_and_acknowledgement(temp_db):
    alert = {
        "alert_id": "alt-test-01",
        "timestamp": "2026-10-25 12:00:00",
        "source_ip": "198.51.100.99",
        "detection_type": "Port Scan",
        "severity": "HIGH",
        "detection_reason": "Test detection reason",
        "related_event_ids": "evt-1,evt-2",
        "is_acknowledged": 0,
        "acknowledged_at": None
    }
    db.insert_security_alerts([alert], db_path=temp_db)

    # Verify retrieval
    alerts = db.get_security_alerts(db_path=temp_db)
    assert len(alerts) == 1
    assert alerts[0]["is_acknowledged"] == 0

    # Acknowledge alert
    success = db.acknowledge_alert("alt-test-01", db_path=temp_db)
    assert success is True

    # Verify updated status
    updated_alerts = db.get_security_alerts(db_path=temp_db)
    assert updated_alerts[0]["is_acknowledged"] == 1
    assert updated_alerts[0]["acknowledged_at"] is not None


def test_clear_simulation_data_preserves_rules(temp_db):
    # Insert event and alert
    events = tg.generate_normal_traffic(count=3)
    for e in events:
        e["firewall_decision"] = "ALLOW"
    db.insert_traffic_events(events, db_path=temp_db)

    initial_rules_count = len(db.get_firewall_rules(temp_db))
    assert initial_rules_count > 0

    # Clear simulation data with clear_rules=False
    db.clear_simulation_data(clear_rules=False, db_path=temp_db)

    # Events should be 0, rules should remain intact
    events_after = db.get_traffic_events(db_path=temp_db)
    assert len(events_after) == 0

    rules_after = db.get_firewall_rules(temp_db)
    assert len(rules_after) == initial_rules_count
