"""
Evaluation Module for Firewall & IDS.
Executes predefined benchmark scenarios with ground-truth labels, measuring:
- Firewall decision accuracy
- IDS Detection Rate: TP / (TP + FN)
- IDS False-Positive Rate: FP / (FP + TN)
- Average event processing time (ms)
"""

import time
import uuid
from datetime import datetime
from typing import Dict, Any, List, Tuple

from firewall import evaluate_event
from intrusion_detection import analyze_traffic_stream
import traffic_generator as tg


def run_scenario(
    scenario_type: str,
    rules: List[Dict[str, Any]],
    ids_config: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Run a predefined benchmark scenario against the current rules and IDS config.
    Returns metrics, ground-truth comparisons, and resulting events/alerts.
    """
    start_bench = time.perf_counter()
    
    # 1. Generate scenario test events with known ground truth
    events_with_ground_truth: List[Tuple[Dict[str, Any], str, str]] = []
    # Tuples: (event_dict, expected_firewall_decision, expected_ids_label)

    if scenario_type == "normal_traffic":
        scenario_title = "Normal Mixed Web & DNS Traffic"
        raw_events = tg.generate_normal_traffic(count=30)
        for e in raw_events:
            events_with_ground_truth.append((e, "ALLOW", "Normal"))

    elif scenario_type == "matching_allow_rule":
        scenario_title = "Traffic Matching ALLOW Rule (HTTPS / DNS)"
        raw_events = []
        for _ in range(15):
            raw_events.append(tg.generate_normal_web_event())
        for _ in range(15):
            raw_events.append(tg.generate_dns_event())
        for e in raw_events:
            events_with_ground_truth.append((e, "ALLOW", "Normal"))

    elif scenario_type == "matching_block_rule":
        scenario_title = "Traffic Matching BLOCK Rule (Restricted Ports/IPs)"
        raw_events = []
        raw_events.extend(tg.generate_blocked_ip_traffic(count=15))
        raw_events.extend(tg.generate_blocked_port_traffic(count=15))
        for e in raw_events:
            events_with_ground_truth.append((e, "BLOCK", "Suspicious"))

    elif scenario_type == "port_scan":
        scenario_title = "Port Scan Detection Benchmark"
        # 16 distinct ports from attacker + 10 background normal events
        scan_events = tg.generate_port_scan_traffic()
        normal_events = tg.generate_normal_traffic(count=10)
        for e in scan_events:
            events_with_ground_truth.append((e, "EVALUATE", "Suspicious"))
        for e in normal_events:
            events_with_ground_truth.append((e, "ALLOW", "Normal"))

    elif scenario_type == "repeated_connection":
        scenario_title = "Repeated Connection Attempts Benchmark"
        # 25 repeated connections + 10 background normal events
        flood_events = tg.generate_repeated_connection_traffic(count=25)
        normal_events = tg.generate_normal_traffic(count=10)
        for e in flood_events:
            events_with_ground_truth.append((e, "EVALUATE", "Suspicious"))
        for e in normal_events:
            events_with_ground_truth.append((e, "ALLOW", "Normal"))

    else:
        raise ValueError(f"Unknown scenario type: {scenario_type}")

    total_events = len(events_with_ground_truth)
    if total_events == 0:
        return {}

    # 2. Process each event through the firewall
    processed_events = []
    correct_firewall_decisions = 0
    evaluable_firewall_count = 0

    eval_start_time = time.perf_counter()
    for raw_event, expected_fw, _ in events_with_ground_truth:
        evaluated = evaluate_event(raw_event, rules)
        processed_events.append(evaluated)

        if expected_fw != "EVALUATE":
            evaluable_firewall_count += 1
            if evaluated["firewall_decision"] == expected_fw:
                correct_firewall_decisions += 1

    # 3. Process events through IDS
    updated_events, alerts = analyze_traffic_stream(
        new_events=processed_events,
        historical_events=[],
        recent_alerts=[],
        config=ids_config
    )
    total_eval_time = time.perf_counter() - eval_start_time
    avg_processing_ms = (total_eval_time / total_events) * 1000.0

    # 4. Calculate IDS Metrics against Ground Truth
    # TP: Ground Truth = Suspicious, Detected = Suspicious
    # FP: Ground Truth = Normal, Detected = Suspicious
    # TN: Ground Truth = Normal, Detected = Normal
    # FN: Ground Truth = Suspicious, Detected = Normal
    tp = 0
    fp = 0
    tn = 0
    fn = 0

    for idx, (original, _, expected_ids) in enumerate(events_with_ground_truth):
        actual_classification = updated_events[idx]["traffic_classification"]
        if expected_ids == "Suspicious":
            if actual_classification == "Suspicious":
                tp += 1
            else:
                fn += 1
        else:  # expected_ids == "Normal"
            if actual_classification == "Suspicious":
                fp += 1
            else:
                tn += 1

    # Safe denominator calculations
    detection_rate = (tp / (tp + fn)) if (tp + fn) > 0 else 1.0
    false_positive_rate = (fp / (fp + tn)) if (fp + tn) > 0 else 0.0

    if evaluable_firewall_count > 0:
        firewall_accuracy = correct_firewall_decisions / evaluable_firewall_count
    else:
        firewall_accuracy = 1.0

    run_id = f"run-{uuid.uuid4().hex[:8]}"
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    results = {
        "run_id": run_id,
        "timestamp": now_str,
        "scenario_key": scenario_type,
        "scenario_name": scenario_title,
        "total_events": total_events,
        "evaluable_firewall_count": evaluable_firewall_count,
        "correct_firewall_decisions": correct_firewall_decisions,
        "firewall_accuracy": round(firewall_accuracy * 100, 2),
        "alerts_generated": len(alerts),
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "detection_rate": round(detection_rate * 100, 2),
        "false_positive_rate": round(false_positive_rate * 100, 2),
        "avg_processing_time_ms": round(avg_processing_ms, 3),
        "events": updated_events,
        "alerts": alerts
    }

    return results
