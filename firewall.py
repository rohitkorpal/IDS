"""
Firewall Engine for simulated packet filtering.
Evaluates synthetic network events against configurable firewall rules in priority order.
"""

from typing import Dict, Any, List, Optional, Tuple


def match_rule(event: Dict[str, Any], rule: Dict[str, Any]) -> bool:
    """
    Check if a single firewall rule matches the given traffic event.
    Returns True if Source IP, Destination Port, and Protocol all match.
    """
    # 1. Match Source IP
    rule_src = str(rule.get("source_ip", "")).strip().upper()
    event_src = str(event.get("source_ip", "")).strip().upper()
    if rule_src != "ANY" and rule_src != event_src:
        return False

    # 2. Match Destination Port
    rule_dport = str(rule.get("destination_port", "")).strip().upper()
    event_dport = str(event.get("destination_port", "")).strip().upper()
    if rule_dport != "ANY" and rule_dport != event_dport:
        return False

    # 3. Match Protocol
    rule_proto = str(rule.get("protocol", "")).strip().upper()
    event_proto = str(event.get("protocol", "")).strip().upper()
    if rule_proto != "ANY" and rule_proto != event_proto:
        return False

    return True


def evaluate_event(
    event: Dict[str, Any],
    rules: List[Dict[str, Any]],
    default_action: str = "ALLOW"
) -> Dict[str, Any]:
    """
    Evaluate an event against enabled rules in priority order.
    Returns updated event with:
    - firewall_decision ('ALLOW' or 'BLOCK')
    - matched_rule_id (int or None)
    - matched_rule_name (str or None)
    - connection_outcome ('Established', 'Denied', etc.)
    """
    # Sort enabled rules by priority ascending, then rule_id ascending
    enabled_rules = [r for r in rules if bool(r.get("enabled", 1))]
    sorted_rules = sorted(
        enabled_rules,
        key=lambda r: (int(r.get("priority", 10)), int(r.get("rule_id", 0)))
    )

    matched_rule: Optional[Dict[str, Any]] = None
    for rule in sorted_rules:
        if match_rule(event, rule):
            matched_rule = rule
            break

    if matched_rule:
        decision = str(matched_rule.get("action", "ALLOW")).upper()
        rule_id = matched_rule.get("rule_id")
        rule_name = matched_rule.get("rule_name")
    else:
        decision = default_action.upper()
        rule_id = None
        rule_name = "Default Policy (Allow)"

    # Determine connection outcome based on decision
    if decision == "BLOCK":
        outcome = "Denied"
    else:
        proto = str(event.get("protocol", "")).upper()
        outcome = "Echo Reply" if proto == "ICMP" else "Established"

    evaluated = dict(event)
    evaluated["firewall_decision"] = decision
    evaluated["matched_rule_id"] = rule_id
    evaluated["matched_rule_name"] = rule_name
    evaluated["connection_outcome"] = outcome

    return evaluated


def test_rule_against_event(rule: Dict[str, Any], event: Dict[str, Any]) -> Tuple[bool, str]:
    """
    Test helper for UI rule testing: returns (is_match, explanation).
    """
    matched = match_rule(event, rule)
    if matched:
        return True, f"Match! Action '{rule.get('action', 'ALLOW')}' would be applied."
    
    # Detail reason why it didn't match
    reasons = []
    rule_src = str(rule.get("source_ip", "")).strip().upper()
    event_src = str(event.get("source_ip", "")).strip().upper()
    if rule_src != "ANY" and rule_src != event_src:
        reasons.append(f"Source IP ({event_src} != {rule_src})")

    rule_dport = str(rule.get("destination_port", "")).strip().upper()
    event_dport = str(event.get("destination_port", "")).strip().upper()
    if rule_dport != "ANY" and rule_dport != event_dport:
        reasons.append(f"Destination Port ({event_dport} != {rule_dport})")

    rule_proto = str(rule.get("protocol", "")).strip().upper()
    event_proto = str(event.get("protocol", "")).strip().upper()
    if rule_proto != "ANY" and rule_proto != event_proto:
        reasons.append(f"Protocol ({event_proto} != {rule_proto})")

    return False, f"Did not match on: {', '.join(reasons)}"
