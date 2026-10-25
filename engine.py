"""
Central pipeline engine coordinating Traffic Generation -> Firewall -> IDS -> SQLite Storage.
"""

from typing import List, Dict, Any, Optional
import database as db
import firewall
import intrusion_detection as ids


def process_and_store_traffic(
    raw_events: List[Dict[str, Any]],
    db_path: str = db.DEFAULT_DB_PATH,
    ids_config: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Executes the standard end-to-end data pipeline:
    1. Evaluate events through active firewall rules.
    2. Pass evaluated events to the IDS engine.
    3. Persist events and any generated security alerts to SQLite.
    4. Return execution summary.
    """
    if not raw_events:
        return {"processed": 0, "alerts": 0}

    # 1. Fetch enabled firewall rules
    rules = db.get_firewall_rules(db_path=db_path, only_enabled=True)

    # 2. Evaluate each event with firewall
    evaluated_events = [firewall.evaluate_event(evt, rules) for evt in raw_events]

    # 3. Fetch recent events (last 500) and recent alerts for stateful IDS correlation
    historical_events = db.get_traffic_events(limit=500, db_path=db_path)
    recent_alerts = db.get_security_alerts(limit=50, db_path=db_path)

    # 4. IDS analysis
    updated_events, new_alerts = ids.analyze_traffic_stream(
        new_events=evaluated_events,
        historical_events=historical_events,
        recent_alerts=recent_alerts,
        config=ids_config
    )

    # 5. Persist to SQLite
    db.insert_traffic_events(updated_events, db_path=db_path)
    db.insert_security_alerts(new_alerts, db_path=db_path)

    return {
        "processed": len(updated_events),
        "alerts": len(new_alerts),
        "events": updated_events,
        "new_alerts": new_alerts
    }
