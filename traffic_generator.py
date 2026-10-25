"""
Traffic Generator for Firewall and Intrusion Detection System (IDS).
Generates deterministic synthetic/simulated network traffic locally without network packets.
All generated events are explicitly flagged as SIMULATED.
"""

import random
import uuid
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional

# Realistic IP pools
INTERNAL_HOSTS = ["192.168.1.10", "192.168.1.20", "192.168.1.50", "10.0.0.15", "10.0.0.22"]
PUBLIC_SERVERS = ["104.21.45.10", "172.67.182.20", "142.250.190.46", "151.101.65.140", "1.1.1.1", "8.8.8.8"]
SUSPICIOUS_IPS = ["198.51.100.25", "203.0.113.15", "185.220.101.5", "45.146.164.110"]
SCANNER_IP = "198.51.100.77"
FLOOD_IP = "203.0.113.88"

COMMON_WEB_PORTS = [80, 443, 8080]
COMMON_DNS_PORTS = [53]
COMMON_ADMIN_PORTS = [22, 23, 3389, 445]
COMMON_SCAN_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 1433, 1521, 3306, 3389, 5432, 8080, 8443]


def _create_event(
    source_ip: str,
    destination_ip: str,
    source_port: int,
    destination_port: int,
    protocol: str,
    event_type: str,
    classification: str = "Normal",
    scenario_tag: Optional[str] = None,
    timestamp: Optional[datetime] = None
) -> Dict[str, Any]:
    """Factory helper to construct a standardized simulated event record."""
    ts = timestamp or datetime.now()
    return {
        "event_id": f"evt-{uuid.uuid4().hex[:10]}",
        "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "source_port": int(source_port),
        "destination_port": int(destination_port),
        "protocol": protocol.upper(),
        "event_type": f"[SIMULATED] {event_type}",
        "firewall_decision": "PENDING",  # Populated by firewall engine
        "matched_rule_id": None,
        "matched_rule_name": None,
        "traffic_classification": classification,
        "connection_outcome": "Pending",
        "is_simulated": 1,
        "scenario_tag": scenario_tag
    }


def generate_normal_web_event(base_time: Optional[datetime] = None) -> Dict[str, Any]:
    """Generate a single legitimate HTTP or HTTPS request event."""
    src = random.choice(INTERNAL_HOSTS)
    dst = random.choice(PUBLIC_SERVERS)
    sport = random.randint(49152, 65535)
    dport = random.choice([80, 443])
    etype = "Web HTTPS" if dport == 443 else "Web HTTP"
    return _create_event(
        source_ip=src,
        destination_ip=dst,
        source_port=sport,
        destination_port=dport,
        protocol="TCP",
        event_type=etype,
        classification="Normal",
        scenario_tag="normal_web",
        timestamp=base_time
    )


def generate_dns_event(base_time: Optional[datetime] = None) -> Dict[str, Any]:
    """Generate a single simulated DNS resolution event."""
    src = random.choice(INTERNAL_HOSTS)
    dst = random.choice(["1.1.1.1", "8.8.8.8", "9.9.9.9"])
    sport = random.randint(49152, 65535)
    return _create_event(
        source_ip=src,
        destination_ip=dst,
        source_port=sport,
        destination_port=53,
        protocol="UDP",
        event_type="DNS Query",
        classification="Normal",
        scenario_tag="normal_dns",
        timestamp=base_time
    )


def generate_normal_traffic(count: int = 25) -> List[Dict[str, Any]]:
    """Generate a sequence of entirely normal web, DNS, and ICMP traffic."""
    events = []
    base_time = datetime.now() - timedelta(seconds=count * 2)
    for i in range(count):
        evt_time = base_time + timedelta(seconds=i * 2 + random.uniform(0.1, 1.5))
        choice = random.random()
        if choice < 0.65:
            events.append(generate_normal_web_event(evt_time))
        elif choice < 0.90:
            events.append(generate_dns_event(evt_time))
        else:
            # ICMP Ping
            src = random.choice(INTERNAL_HOSTS)
            dst = random.choice(PUBLIC_SERVERS)
            events.append(_create_event(
                source_ip=src,
                destination_ip=dst,
                source_port=0,
                destination_port=0,
                protocol="ICMP",
                event_type="ICMP Echo Request",
                classification="Normal",
                scenario_tag="normal_icmp",
                timestamp=evt_time
            ))
    return events


def generate_port_scan_traffic(
    attacker_ip: str = SCANNER_IP,
    target_ip: str = "192.168.1.10",
    ports: Optional[List[int]] = None,
    base_time: Optional[datetime] = None
) -> List[Dict[str, Any]]:
    """
    Simulate a port scan scenario:
    The attacker tests multiple distinct destination ports within seconds.
    """
    scan_ports = ports or COMMON_SCAN_PORTS[:16]  # 16 distinct ports exceeds default threshold 10
    now = base_time or datetime.now()
    events = []
    
    # Space them closely (e.g. 0.5s to 1s apart) within a 30s window
    start_time = now - timedelta(seconds=len(scan_ports))
    for idx, dport in enumerate(scan_ports):
        evt_time = start_time + timedelta(seconds=idx * 0.8)
        events.append(_create_event(
            source_ip=attacker_ip,
            destination_ip=target_ip,
            source_port=random.randint(50000, 60000),
            destination_port=dport,
            protocol="TCP",
            event_type=f"TCP SYN Probe (Port {dport})",
            classification="Suspicious",
            scenario_tag="port_scan",
            timestamp=evt_time
        ))
    return events


def generate_repeated_connection_traffic(
    attacker_ip: str = FLOOD_IP,
    target_ip: str = "192.168.1.10",
    count: int = 25,
    target_port: int = 80,
    base_time: Optional[datetime] = None
) -> List[Dict[str, Any]]:
    """
    Simulate repeated connection attempts (e.g. brute force or connection flood):
    The same source IP initiates rapid connections to a single service.
    """
    now = base_time or datetime.now()
    events = []
    # 25 attempts within 20 seconds exceeds threshold of 20
    start_time = now - timedelta(seconds=25)
    for idx in range(count):
        evt_time = start_time + timedelta(seconds=idx * 0.7)
        events.append(_create_event(
            source_ip=attacker_ip,
            destination_ip=target_ip,
            source_port=random.randint(45000, 65000),
            destination_port=target_port,
            protocol="TCP",
            event_type="Rapid Connection Burst",
            classification="Suspicious",
            scenario_tag="repeated_connection",
            timestamp=evt_time
        ))
    return events


def generate_blocked_ip_traffic(count: int = 5) -> List[Dict[str, Any]]:
    """Generate events originating from known blocked IPs."""
    events = []
    now = datetime.now()
    for i in range(count):
        src = "198.51.100.25"
        dst = random.choice(INTERNAL_HOSTS)
        events.append(_create_event(
            source_ip=src,
            destination_ip=dst,
            source_port=random.randint(40000, 50000),
            destination_port=80,
            protocol="TCP",
            event_type="Inbound Request from Blocklisted Host",
            classification="Suspicious",
            scenario_tag="blocked_ip",
            timestamp=now - timedelta(seconds=(count - i) * 2)
        ))
    return events


def generate_blocked_port_traffic(count: int = 5) -> List[Dict[str, Any]]:
    """Generate events targeting blocked ports (Telnet 23, SMB 445)."""
    events = []
    now = datetime.now()
    for i in range(count):
        src = random.choice(SUSPICIOUS_IPS)
        dst = random.choice(INTERNAL_HOSTS)
        dport = 23 if i % 2 == 0 else 445
        events.append(_create_event(
            source_ip=src,
            destination_ip=dst,
            source_port=random.randint(40000, 50000),
            destination_port=dport,
            protocol="TCP",
            event_type=f"Inbound Probe to Restricted Port {dport}",
            classification="Suspicious",
            scenario_tag="blocked_port",
            timestamp=now - timedelta(seconds=(count - i) * 2)
        ))
    return events


def generate_batch(count: int = 25) -> List[Dict[str, Any]]:
    """
    Generate a realistic mixed batch of simulated traffic:
    Mostly normal traffic with occasional probes or blocked events.
    """
    events = []
    normal_count = int(count * 0.75)
    events.extend(generate_normal_traffic(normal_count))

    # Add a few suspicious/blocked events
    rem = count - normal_count
    if rem > 0:
        events.extend(generate_blocked_ip_traffic(max(1, rem // 2)))
        events.extend(generate_blocked_port_traffic(max(1, rem - (rem // 2))))

    # Shuffle slightly so they interleave realistically
    events.sort(key=lambda x: x["timestamp"])
    return events[:count]
