"""
Unit tests for Firewall rule engine.
Tests rule matching, priority ordering, default ALLOW behavior, and disabled rules.
"""

import pytest
import firewall


@pytest.fixture
def sample_rules():
    return [
        {
            "rule_id": 1,
            "rule_name": "Block Malicious Host",
            "source_ip": "198.51.100.25",
            "destination_port": "ANY",
            "protocol": "ANY",
            "action": "BLOCK",
            "enabled": 1,
            "priority": 1
        },
        {
            "rule_id": 2,
            "rule_name": "Block Telnet Port",
            "source_ip": "ANY",
            "destination_port": "23",
            "protocol": "TCP",
            "action": "BLOCK",
            "enabled": 1,
            "priority": 2
        },
        {
            "rule_id": 3,
            "rule_name": "Allow Web HTTPS",
            "source_ip": "ANY",
            "destination_port": "443",
            "protocol": "TCP",
            "action": "ALLOW",
            "enabled": 1,
            "priority": 3
        },
        {
            "rule_id": 4,
            "rule_name": "Disabled Block Rule",
            "source_ip": "ANY",
            "destination_port": "80",
            "protocol": "TCP",
            "action": "BLOCK",
            "enabled": 0,  # Disabled
            "priority": 4
        }
    ]


def test_default_allow_when_no_rules_match(sample_rules):
    event = {
        "source_ip": "10.0.0.1",
        "destination_port": 8080,
        "protocol": "TCP"
    }
    result = firewall.evaluate_event(event, sample_rules)
    assert result["firewall_decision"] == "ALLOW"
    assert result["matched_rule_id"] is None
    assert result["connection_outcome"] == "Established"


def test_block_by_ip_rule(sample_rules):
    event = {
        "source_ip": "198.51.100.25",
        "destination_port": 80,
        "protocol": "TCP"
    }
    result = firewall.evaluate_event(event, sample_rules)
    assert result["firewall_decision"] == "BLOCK"
    assert result["matched_rule_id"] == 1
    assert result["connection_outcome"] == "Denied"


def test_block_by_port_rule(sample_rules):
    event = {
        "source_ip": "10.0.0.5",
        "destination_port": 23,
        "protocol": "TCP"
    }
    result = firewall.evaluate_event(event, sample_rules)
    assert result["firewall_decision"] == "BLOCK"
    assert result["matched_rule_id"] == 2


def test_allow_by_port_and_protocol(sample_rules):
    event = {
        "source_ip": "10.0.0.5",
        "destination_port": 443,
        "protocol": "TCP"
    }
    result = firewall.evaluate_event(event, sample_rules)
    assert result["firewall_decision"] == "ALLOW"
    assert result["matched_rule_id"] == 3


def test_disabled_rule_is_ignored(sample_rules):
    # Rule 4 blocks port 80, but it is disabled.
    # Therefore, event should fall through to default ALLOW.
    event = {
        "source_ip": "10.0.0.5",
        "destination_port": 80,
        "protocol": "TCP"
    }
    result = firewall.evaluate_event(event, sample_rules)
    assert result["firewall_decision"] == "ALLOW"
    assert result["matched_rule_id"] is None


def test_priority_ordering():
    # If two rules match, the one with lower priority number should win
    rules = [
        {
            "rule_id": 10,
            "rule_name": "Low Priority Block",
            "source_ip": "ANY",
            "destination_port": "80",
            "protocol": "TCP",
            "action": "BLOCK",
            "enabled": 1,
            "priority": 50
        },
        {
            "rule_id": 11,
            "rule_name": "High Priority Allow",
            "source_ip": "ANY",
            "destination_port": "80",
            "protocol": "TCP",
            "action": "ALLOW",
            "enabled": 1,
            "priority": 5
        }
    ]
    event = {"source_ip": "192.168.1.1", "destination_port": 80, "protocol": "TCP"}
    result = firewall.evaluate_event(event, rules)
    assert result["firewall_decision"] == "ALLOW"
    assert result["matched_rule_id"] == 11
