"""
Firewall and Intrusion Detection System (IDS) - Academic Prototype.
Built with Streamlit, Plotly, and SQLite.
"""

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
import os
import sys

# Core application modules
import database as db
import firewall
import intrusion_detection as ids
import traffic_generator as tg
import evaluation as ev
from engine import process_and_store_traffic

# -----------------------------------------------------------------------------
# App Configuration & Styling
# -----------------------------------------------------------------------------
st.set_page_config(
    page_title="CyberShield | Firewall & IDS Prototype",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# =============================================================================
# Light Minimalistic Theme CSS
# =============================================================================
# [OLD DARK THEME CODE PRESERVED AS PER RULE 1]
# CUSTOM_CSS = """
# <style>
#     /* Dark Cybersecurity Background and Base Typography */
#     .stApp {
#         background: radial-gradient(circle at 15% 15%, #0d1527 0%, #080c16 100%);
#         color: #e2e8f0;
#         font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
#     }
#     section[data-testid="stSidebar"] {
#         background-color: #0b1120 !important;
#         border-right: 1px solid #1e293b;
#     }
#     .metric-card {
#         background: linear-gradient(135deg, rgba(17, 24, 39, 0.9) 0%, rgba(30, 41, 59, 0.8) 100%);
#         border: 1px solid #1e293b;
#         border-left: 4px solid #00f2fe;
#         border-radius: 8px;
#         padding: 16px 20px;
#         box-shadow: 0 4px 14px rgba(0, 0, 0, 0.35);
#         margin-bottom: 12px;
#     }
#     .metric-card-danger { border-left-color: #ef4444 !important; }
#     .metric-card-success { border-left-color: #10b981 !important; }
#     .metric-card-warning { border-left-color: #f59e0b !important; }
#     .metric-label { font-size: 0.82rem; text-transform: uppercase; color: #94a3b8; font-weight: 600; }
#     .metric-val { font-size: 1.85rem; font-weight: 700; color: #f8fafc; }
#     .metric-sub { font-size: 0.78rem; color: #64748b; }
#     .sim-badge { background: rgba(14, 165, 233, 0.15); color: #38bdf8; border: 1px solid #0284c7; }
#     .badge-allow { background-color: rgba(16, 185, 129, 0.2); color: #34d399; }
#     .badge-block { background-color: rgba(239, 68, 68, 0.2); color: #f87171; }
#     .badge-suspicious { background-color: rgba(245, 158, 11, 0.2); color: #fbbf24; }
#     h1, h2, h3 { color: #f8fafc !important; }
#     .academic-disclaimer { background: rgba(30, 41, 59, 0.6); border: 1px solid #334155; }
# </style>
# """

CUSTOM_CSS = """
<style>
    /* Clean Light Minimalist Styling */
    .stApp {
        background-color: #f8fafc;
        color: #0f172a;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
    }
    
    /* Minimalist Light Sidebar */
    section[data-testid="stSidebar"] {
        background-color: #ffffff !important;
        border-right: 1px solid #e2e8f0;
    }

    /* Minimalist Metric Cards */
    .metric-card {
        background-color: #ffffff;
        border: 1px solid #e2e8f0;
        border-left: 4px solid #0284c7;
        border-radius: 8px;
        padding: 16px 20px;
        box-shadow: 0 1px 3px 0 rgba(0, 0, 0, 0.04);
        margin-bottom: 12px;
    }
    .metric-card-danger {
        border-left-color: #ef4444 !important;
    }
    .metric-card-success {
        border-left-color: #10b981 !important;
    }
    .metric-card-warning {
        border-left-color: #f59e0b !important;
    }
    .metric-label {
        font-size: 0.78rem;
        text-transform: uppercase;
        letter-spacing: 0.06em;
        color: #64748b;
        font-weight: 600;
        margin-bottom: 4px;
    }
    .metric-val {
        font-size: 1.85rem;
        font-weight: 700;
        color: #0f172a;
        line-height: 1.2;
    }
    .metric-sub {
        font-size: 0.78rem;
        color: #94a3b8;
        margin-top: 4px;
    }

    /* Minimalist Soft Badges */
    .sim-badge {
        display: inline-block;
        background-color: #f0f9ff;
        color: #0284c7;
        border: 1px solid #bae6fd;
        border-radius: 4px;
        padding: 2px 8px;
        font-size: 0.75rem;
        font-weight: 600;
        letter-spacing: 0.04em;
    }
    
    .badge-allow {
        background-color: #ecfdf5;
        color: #059669;
        border: 1px solid #a7f3d0;
        padding: 2px 8px;
        border-radius: 4px;
        font-weight: 600;
        font-size: 0.85rem;
    }
    .badge-block {
        background-color: #fef2f2;
        color: #dc2626;
        border: 1px solid #fecaca;
        padding: 2px 8px;
        border-radius: 4px;
        font-weight: 600;
        font-size: 0.85rem;
    }
    .badge-suspicious {
        background-color: #fffbeb;
        color: #d97706;
        border: 1px solid #fde68a;
        padding: 2px 8px;
        border-radius: 4px;
        font-weight: 600;
        font-size: 0.85rem;
    }
    
    /* Clean Minimal Headers */
    h1, h2, h3, h4 {
        color: #0f172a !important;
        font-weight: 600 !important;
    }
    
    /* Clean Buttons */
    .stButton>button {
        border-radius: 6px;
        font-weight: 500;
        border: 1px solid #cbd5e1;
        transition: all 0.15s ease-in-out;
    }
    .stButton>button:hover {
        border-color: #0284c7;
        color: #0284c7;
    }
    
    /* Minimalist Notice Banner */
    .academic-disclaimer {
        background-color: #ffffff;
        border: 1px solid #e2e8f0;
        border-left: 3px solid #0284c7;
        border-radius: 6px;
        padding: 10px 16px;
        font-size: 0.85rem;
        color: #475569;
        box-shadow: 0 1px 2px 0 rgba(0, 0, 0, 0.03);
        margin-bottom: 20px;
    }
</style>
"""
st.markdown(CUSTOM_CSS, unsafe_allow_html=True)

# Initialize Database on first startup
db.init_db()

# Initialize Session State
if "ids_config" not in st.session_state:
    st.session_state["ids_config"] = dict(ids.DEFAULT_IDS_CONFIG)
if "last_action_msg" not in st.session_state:
    st.session_state["last_action_msg"] = None

# Helper to format Plotly charts with a light minimalistic theme
# Previously named apply_dark_theme, preserved as alias for compatibility
def apply_dark_theme(fig):
    """
    # [OLD DARK THEME CODE PRESERVED AS PER RULE 1]
    # fig.update_layout(
    #     paper_bgcolor="rgba(17, 24, 39, 0.4)",
    #     plot_bgcolor="rgba(17, 24, 39, 0.4)",
    #     font=dict(color="#cbd5e1", family="Inter"),
    #     margin=dict(l=20, r=20, t=35, b=20),
    #     legend=dict(font=dict(color="#94a3b8"))
    # )
    # fig.update_xaxes(gridcolor="#1e293b", showline=True, linecolor="#334155")
    # fig.update_yaxes(gridcolor="#1e293b", showline=True, linecolor="#334155")
    """
    fig.update_layout(
        paper_bgcolor="#ffffff",
        plot_bgcolor="#ffffff",
        font=dict(color="#334155", family="sans-serif"),
        margin=dict(l=20, r=20, t=35, b=20),
        legend=dict(font=dict(color="#475569"))
    )
    fig.update_xaxes(gridcolor="#f1f5f9", showline=True, linecolor="#cbd5e1")
    fig.update_yaxes(gridcolor="#f1f5f9", showline=True, linecolor="#cbd5e1")
    return fig

apply_light_theme = apply_dark_theme


# -----------------------------------------------------------------------------
# Sidebar Navigation & Global Controls
# -----------------------------------------------------------------------------
st.sidebar.markdown("""
<div style="padding: 10px 0;">
    <h2 style="margin: 0; font-size: 1.35rem; color: #0284c7 !important;">🛡️ CyberShield IDS</h2>
    <div style="font-size: 0.78rem; color: #64748b; margin-top: 2px;">Firewall & Intrusion Detection System</div>
    <div style="margin-top: 8px;"><span class="sim-badge">ACADEMIC PROTOTYPE</span></div>
</div>
""", unsafe_allow_html=True)

nav_page = st.sidebar.radio(
    "Navigation",
    options=[
        "Dashboard",
        "Network Monitor",
        "Firewall Rules",
        "Intrusion Detection",
        "Security Alerts",
        "Event Logs",
        "Testing & Evaluation"
    ],
    index=0
)

st.sidebar.markdown("---")
st.sidebar.subheader("Quick Traffic Simulation")

col_sb1, col_sb2 = st.sidebar.columns(2)
with col_sb1:
    if st.button("⚡ +25 Events", use_container_width=True):
        events = tg.generate_batch(25)
        res = process_and_store_traffic(events, ids_config=st.session_state["ids_config"])
        st.session_state["last_action_msg"] = f"Generated 25 events ({res['alerts']} alerts triggered)."
        st.rerun()

with col_sb2:
    if st.button("🚀 +100 Events", use_container_width=True):
        events = tg.generate_batch(100)
        res = process_and_store_traffic(events, ids_config=st.session_state["ids_config"])
        st.session_state["last_action_msg"] = f"Generated 100 events ({res['alerts']} alerts triggered)."
        st.rerun()

st.sidebar.markdown("---")
st.sidebar.subheader("System Maintenance")

with st.sidebar.expander("Database Operations"):
    st.caption("Clear simulated traffic and alerts history. Firewall rules are kept intact.")
    confirm_clear = st.checkbox("Confirm data clearing")
    if st.button("🗑️ Clear Simulation Logs", type="secondary", disabled=not confirm_clear):
        db.clear_simulation_data(clear_rules=False)
        st.session_state["last_action_msg"] = "Simulation database logs cleared."
        st.rerun()

st.sidebar.caption("Status: Running locally on Windows • SQLite3")


# Global Academic Prototype Banner
st.markdown("""
<div class="academic-disclaimer">
    ℹ️ <strong>Simulated Prototype Notice:</strong> This software is a standalone academic demonstration. 
    It evaluates synthetic network events in a local SQLite database without capturing live packets or altering the host OS firewall.
</div>
""", unsafe_allow_html=True)

if st.session_state["last_action_msg"]:
    st.success(st.session_state["last_action_msg"])
    st.session_state["last_action_msg"] = None


# =============================================================================
# PAGE 1: SECURITY DASHBOARD
# =============================================================================
if nav_page == "Dashboard":
    col_title, col_btn = st.columns([4, 1])
    with col_title:
        st.title("Security Operations Dashboard")
        st.caption("Real-time telemetry and aggregated statistics from local security logs.")
    with col_btn:
        st.write("")
        if st.button("🔄 Refresh Data", use_container_width=True):
            st.rerun()

    # Metrics Row directly from SQLite
    stats = db.get_traffic_stats()

    m1, m2, m3, m4, m5 = st.columns(5)
    with m1:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-label">Total Simulated Events</div>
            <div class="metric-val">{stats['total_events']:,}</div>
            <div class="metric-sub">Recorded in SQLite</div>
        </div>
        """, unsafe_allow_html=True)

    with m2:
        st.markdown(f"""
        <div class="metric-card metric-card-success">
            <div class="metric-label">Allowed Events</div>
            <div class="metric-val">{stats['allowed_events']:,}</div>
            <div class="metric-sub">Passed firewall policy</div>
        </div>
        """, unsafe_allow_html=True)

    with m3:
        st.markdown(f"""
        <div class="metric-card metric-card-danger">
            <div class="metric-label">Blocked Events</div>
            <div class="metric-val">{stats['blocked_events']:,}</div>
            <div class="metric-sub">Filtered by firewall rules</div>
        </div>
        """, unsafe_allow_html=True)

    with m4:
        st.markdown(f"""
        <div class="metric-card metric-card-warning">
            <div class="metric-label">Suspicious Events</div>
            <div class="metric-val">{stats['suspicious_events']:,}</div>
            <div class="metric-sub">Flagged by IDS heuristics</div>
        </div>
        """, unsafe_allow_html=True)

    with m5:
        st.markdown(f"""
        <div class="metric-card metric-card-danger">
            <div class="metric-label">Active Alerts</div>
            <div class="metric-val">{stats['unacknowledged_alerts']} / {stats['total_alerts']}</div>
            <div class="metric-sub">Unacknowledged incidents</div>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    # Fetch recent traffic events for visual analytics
    events = db.get_traffic_events(limit=500)

    if not events:
        st.info("No network traffic events recorded yet. Click '+25 Events' or navigate to 'Network Monitor' to generate synthetic traffic.")
    else:
        df_events = pd.DataFrame(events)

        c1, c2, c3 = st.columns([2, 1, 1])

        with c1:
            st.subheader("Traffic Activity Over Time")
            # Group by 1-minute intervals or second intervals
            df_events["dt"] = pd.to_datetime(df_events["timestamp"])
            time_counts = df_events.set_index("dt").resample("1min")["event_id"].count().reset_index()
            time_counts.columns = ["Timestamp", "Events"]

            # [OLD DARK TEMPLATE PRESERVED AS PER RULE 1]
            # fig_time = px.line(time_counts, x="Timestamp", y="Events", title="Event Volume (Per Minute)", template="plotly_dark", color_discrete_sequence=["#00f2fe"])
            # fig_time.update_traces(mode="lines+markers", fill="tozeroy", fillcolor="rgba(0, 242, 254, 0.1)")
            fig_time = px.line(
                time_counts,
                x="Timestamp",
                y="Events",
                title="Event Volume (Per Minute)",
                template="plotly_white",
                color_discrete_sequence=["#0284c7"]
            )
            fig_time.update_traces(mode="lines+markers", fill="tozeroy", fillcolor="rgba(2, 132, 199, 0.08)")
            st.plotly_chart(apply_dark_theme(fig_time), use_container_width=True)

        with c2:
            st.subheader("Protocol Distribution")
            proto_counts = df_events["protocol"].value_counts().reset_index()
            proto_counts.columns = ["Protocol", "Count"]

            # [OLD DARK PALETTE PRESERVED AS PER RULE 1]
            # color_discrete_map={"TCP": "#38bdf8", "UDP": "#818cf8", "ICMP": "#34d399"}
            fig_proto = px.pie(
                proto_counts,
                names="Protocol",
                values="Count",
                hole=0.55,
                color_discrete_map={"TCP": "#0284c7", "UDP": "#6366f1", "ICMP": "#10b981"}
            )
            fig_proto.update_traces(textposition="inside", textinfo="percent+label")
            st.plotly_chart(apply_dark_theme(fig_proto), use_container_width=True)

        with c3:
            st.subheader("Severity Distribution")
            alerts = db.get_security_alerts(limit=500)
            if alerts:
                df_alerts = pd.DataFrame(alerts)
                sev_counts = df_alerts["severity"].value_counts().reset_index()
                sev_counts.columns = ["Severity", "Count"]
                color_map = {"HIGH": "#ef4444", "MEDIUM": "#f59e0b", "LOW": "#0284c7"}
                fig_sev = px.bar(
                    sev_counts,
                    x="Severity",
                    y="Count",
                    color="Severity",
                    color_discrete_map=color_map,
                    template="plotly_white",
                    title="Alert Severity"
                )
                st.plotly_chart(apply_dark_theme(fig_sev), use_container_width=True)
            else:
                st.caption("No alerts logged yet to chart.")

        # Recent Events Table
        st.subheader("Recent Simulated Network Events")
        display_df = df_events[[
            "event_id", "timestamp", "source_ip", "destination_ip",
            "destination_port", "protocol", "firewall_decision", "traffic_classification"
        ]].head(12)
        st.dataframe(display_df, use_container_width=True, hide_index=True)


# =============================================================================
# PAGE 2: NETWORK MONITOR
# =============================================================================
elif nav_page == "Network Monitor":
    st.title("Network Traffic Monitor")
    st.caption("Interactive telemetry stream of synthetic packets evaluated by the firewall and IDS engines.")

    # Generator Controls Section
    st.subheader("Generate Synthetic Scenarios")
    b1, b2, b3, b4, b5 = st.columns(5)
    
    with b1:
        if st.button("🌐 Normal Traffic (25)", use_container_width=True):
            events = tg.generate_normal_traffic(25)
            res = process_and_store_traffic(events, ids_config=st.session_state["ids_config"])
            st.session_state["last_action_msg"] = f"Processed {res['processed']} normal events."
            st.rerun()

    with b2:
        if st.button("🔍 Simulate Port Scan", use_container_width=True):
            events = tg.generate_port_scan_traffic()
            res = process_and_store_traffic(events, ids_config=st.session_state["ids_config"])
            st.session_state["last_action_msg"] = f"Simulated Port Scan ({res['alerts']} alert(s) triggered)."
            st.rerun()

    with b3:
        if st.button("🌊 Repeated Connections", use_container_width=True):
            events = tg.generate_repeated_connection_traffic(count=25)
            res = process_and_store_traffic(events, ids_config=st.session_state["ids_config"])
            st.session_state["last_action_msg"] = f"Simulated Repeated Connection Burst ({res['alerts']} alert(s) triggered)."
            st.rerun()

    with b4:
        if st.button("🚫 Blocked IP Probes", use_container_width=True):
            events = tg.generate_blocked_ip_traffic(count=10)
            res = process_and_store_traffic(events, ids_config=st.session_state["ids_config"])
            st.session_state["last_action_msg"] = f"Simulated 10 Blocked IP probes."
            st.rerun()

    with b5:
        if st.button("🔒 Blocked Port Probes", use_container_width=True):
            events = tg.generate_blocked_port_traffic(count=10)
            res = process_and_store_traffic(events, ids_config=st.session_state["ids_config"])
            st.session_state["last_action_msg"] = f"Simulated 10 Blocked Port requests."
            st.rerun()

    st.markdown("---")

    # Filter Bar
    st.subheader("Live Event Stream & Filter")
    f1, f2, f3, f4 = st.columns(4)
    with f1:
        src_filter = st.text_input("Filter by Source IP", placeholder="e.g. 198.51.100.25")
    with f2:
        proto_filter = st.selectbox("Protocol", ["ALL", "TCP", "UDP", "ICMP"])
    with f3:
        dec_filter = st.selectbox("Firewall Decision", ["ALL", "ALLOW", "BLOCK"])
    with f4:
        class_filter = st.selectbox("Classification", ["ALL", "Normal", "Suspicious"])

    filtered_events = db.get_traffic_events(
        limit=200,
        source_ip=src_filter,
        protocol=proto_filter,
        decision=dec_filter,
        classification=class_filter
    )

    if filtered_events:
        df_feed = pd.DataFrame(filtered_events)
        st.dataframe(
            df_feed[[
                "event_id", "timestamp", "source_ip", "destination_ip",
                "source_port", "destination_port", "protocol", "event_type",
                "firewall_decision", "matched_rule_name", "traffic_classification", "connection_outcome"
            ]],
            use_container_width=True,
            hide_index=True
        )
        st.caption(f"Showing {len(filtered_events)} matching records from SQLite.")
    else:
        st.info("No matching traffic records found in the database.")


# =============================================================================
# PAGE 3: FIREWALL RULES
# =============================================================================
elif nav_page == "Firewall Rules":
    st.title("Firewall Rule Management")
    st.caption("Configure simulated access control policies evaluated sequentially in priority order.")

    tab_rules, tab_add, tab_test = st.tabs(["📋 Active Rules", "➕ Add New Rule", "🧪 Rule Tester"])

    with tab_rules:
        rules = db.get_firewall_rules()
        if rules:
            for r in rules:
                with st.container():
                    col_info, col_toggle, col_del = st.columns([5, 1, 1])
                    with col_info:
                        action_badge = "🔴 BLOCK" if r["action"] == "BLOCK" else "🟢 ALLOW"
                        status_str = "Active" if r["enabled"] else "Disabled"
                        st.markdown(f"""
                        **#{r['priority']} — {r['rule_name']}** &nbsp; {action_badge} &nbsp; 
                        <span style="font-size:0.8rem; color:#94a3b8;">(ID: {r['rule_id']}) — Status: {status_str}</span><br>
                        `Src IP: {r['source_ip']}` &nbsp;|&nbsp; `Port: {r['destination_port']}` &nbsp;|&nbsp; `Proto: {r['protocol']}`
                        """, unsafe_allow_html=True)
                    
                    with col_toggle:
                        btn_label = "Disable" if r["enabled"] else "Enable"
                        if st.button(btn_label, key=f"tog_{r['rule_id']}"):
                            db.update_rule_status(r["rule_id"], 0 if r["enabled"] else 1)
                            st.rerun()

                    with col_del:
                        if st.button("Delete", key=f"del_{r['rule_id']}", type="secondary"):
                            db.delete_firewall_rule(r["rule_id"])
                            st.rerun()
                    st.divider()
        else:
            st.info("No firewall rules configured.")

    with tab_add:
        st.subheader("Define Access Control Rule")
        with st.form("new_rule_form"):
            c_name, c_prio = st.columns([3, 1])
            with c_name:
                rule_name = st.text_input("Rule Name", placeholder="e.g. Block Malicious Scanner")
            with c_prio:
                priority = st.number_input("Evaluation Priority (Lower = higher priority)", min_value=1, max_value=999, value=10)

            c_src, c_port, c_proto, c_act = st.columns(4)
            with c_src:
                source_ip = st.text_input("Source IP", value="ANY")
            with c_port:
                dest_port = st.text_input("Destination Port", value="ANY")
            with c_proto:
                protocol = st.selectbox("Protocol", ["ANY", "TCP", "UDP", "ICMP"])
            with c_act:
                action = st.selectbox("Action", ["BLOCK", "ALLOW"])

            submitted = st.form_submit_button("Save Rule", use_container_width=True)
            if submitted:
                if not rule_name.strip():
                    st.error("Please provide a descriptive rule name.")
                else:
                    new_id = db.add_firewall_rule(
                        rule_name=rule_name,
                        source_ip=source_ip,
                        destination_port=dest_port,
                        protocol=protocol,
                        action=action,
                        priority=priority
                    )
                    st.success(f"Rule #{new_id} added successfully!")
                    st.rerun()

    with tab_test:
        st.subheader("Simulate Event Matching")
        st.caption("Verify how an incoming synthetic packet will be evaluated by existing rules.")
        
        tc1, tc2, tc3 = st.columns(3)
        with tc1:
            test_src = st.text_input("Test Source IP", value="198.51.100.25")
        with tc2:
            test_dport = st.text_input("Test Destination Port", value="23")
        with tc3:
            test_proto = st.selectbox("Test Protocol", ["TCP", "UDP", "ICMP"], key="test_proto")

        if st.button("Evaluate Test Packet", use_container_width=True):
            test_evt = {
                "source_ip": test_src,
                "destination_port": test_dport,
                "protocol": test_proto
            }
            active_rules = db.get_firewall_rules(only_enabled=True)
            eval_result = firewall.evaluate_event(test_evt, active_rules)
            
            st.markdown("### Result:")
            res_col1, res_col2 = st.columns(2)
            with res_col1:
                dec = eval_result["firewall_decision"]
                badge_class = "badge-block" if dec == "BLOCK" else "badge-allow"
                st.markdown(f"**Decision:** <span class='{badge_class}'>{dec}</span>", unsafe_allow_html=True)
                st.markdown(f"**Connection Outcome:** `{eval_result['connection_outcome']}`")
            with res_col2:
                st.markdown(f"**Matched Rule ID:** `{eval_result['matched_rule_id'] or 'None (Default Policy)'}`")
                st.markdown(f"**Rule Name:** `{eval_result['matched_rule_name']}`")


# =============================================================================
# PAGE 4: INTRUSION DETECTION
# =============================================================================
elif nav_page == "Intrusion Detection":
    st.title("Intrusion Detection System (IDS)")
    st.caption("Deterministic heuristic anomaly detection engine operating on simulated telemetry streams.")

    st.subheader("Active Detection Heuristics")

    c_h1, c_h2 = st.columns(2)
    with c_h1:
        st.markdown("""
        <div class="metric-card">
            <div class="metric-label">Detection Rule 1</div>
            <h3 style="margin: 4px 0; color: #38bdf8 !important;">Port Scan Heuristic</h3>
            <p style="font-size: 0.85rem; color: #94a3b8; margin-top: 6px;">
                Identifies rapid reconnaissance by tracking connection attempts from the same source IP 
                to multiple distinct destination ports within a defined sliding time window.
            </p>
        </div>
        """, unsafe_allow_html=True)

    with c_h2:
        st.markdown("""
        <div class="metric-card">
            <div class="metric-label">Detection Rule 2</div>
            <h3 style="margin: 4px 0; color: #38bdf8 !important;">Repeated Connections</h3>
            <p style="font-size: 0.85rem; color: #94a3b8; margin-top: 6px;">
                Identifies volume-based attacks (DoS or aggressive brute force) by detecting rapid repeated 
                connection attempts from a single source host within a specified duration.
            </p>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)
    st.subheader("Configurable Heuristic Thresholds")

    with st.form("ids_config_form"):
        sc1, sc2 = st.columns(2)
        with sc1:
            st.markdown("#### Port Scan Parameters")
            ps_thresh = st.slider(
                "Distinct Port Threshold",
                min_value=3, max_value=50,
                value=int(st.session_state["ids_config"]["port_scan_threshold"])
            )
            ps_win = st.slider(
                "Port Scan Time Window (seconds)",
                min_value=10, max_value=300,
                value=int(st.session_state["ids_config"]["port_scan_window_sec"])
            )

        with sc2:
            st.markdown("#### Repeated Connections Parameters")
            rc_thresh = st.slider(
                "Connection Attempts Threshold",
                min_value=5, max_value=100,
                value=int(st.session_state["ids_config"]["repeated_conn_threshold"])
            )
            rc_win = st.slider(
                "Connection Time Window (seconds)",
                min_value=10, max_value=300,
                value=int(st.session_state["ids_config"]["repeated_conn_window_sec"])
            )

        saved = st.form_submit_button("Update IDS Configuration", use_container_width=True)
        if saved:
            st.session_state["ids_config"]["port_scan_threshold"] = ps_thresh
            st.session_state["ids_config"]["port_scan_window_sec"] = ps_win
            st.session_state["ids_config"]["repeated_conn_threshold"] = rc_thresh
            st.session_state["ids_config"]["repeated_conn_window_sec"] = rc_win
            st.success("IDS heuristic parameters updated successfully.")

    st.markdown("---")
    st.subheader("Recent Flagged Attack Sources")
    alerts = db.get_security_alerts(limit=50)
    if alerts:
        flagged_ips = {}
        for a in alerts:
            ip = a["source_ip"]
            flagged_ips[ip] = flagged_ips.get(ip, 0) + 1
        
        df_sources = pd.DataFrame([
            {"Source IP": ip, "Total Incidents": count}
            for ip, count in flagged_ips.items()
        ]).sort_values(by="Total Incidents", ascending=False)
        st.dataframe(df_sources, use_container_width=True, hide_index=True)
    else:
        st.caption("No attack sources currently flagged.")


# =============================================================================
# PAGE 5: SECURITY ALERTS
# =============================================================================
elif nav_page == "Security Alerts":
    st.title("Security Incidents & Alerts")
    st.caption("Investigate and acknowledge security events flagged by deterministic IDS heuristics.")

    af1, af2 = st.columns(2)
    with af1:
        sev_filter = st.selectbox("Filter by Severity", ["ALL", "HIGH", "MEDIUM", "LOW"])
    with af2:
        status_filter = st.selectbox("Filter by Status", ["ALL", "UNACKNOWLEDGED", "ACKNOWLEDGED"])

    alerts = db.get_security_alerts(severity=sev_filter, status=status_filter, limit=100)

    if alerts:
        for alt in alerts:
            with st.container():
                col_sev, col_body, col_ack = st.columns([1, 6, 2])
                with col_sev:
                    s = alt["severity"]
                    color = "#ef4444" if s == "HIGH" else ("#f59e0b" if s == "MEDIUM" else "#38bdf8")
                    st.markdown(f"""
                    <div style="border-left: 3px solid {color}; padding-left: 8px;">
                        <span style="font-weight:700; color:{color};">{s}</span><br>
                        <span style="font-size:0.75rem; color:#64748b;">{alt['alert_id']}</span>
                    </div>
                    """, unsafe_allow_html=True)

                with col_body:
                    st.markdown(f"**{alt['detection_type']}** from `{alt['source_ip']}` &nbsp; <span style='font-size:0.75rem; color:#94a3b8;'>({alt['timestamp']})</span>", unsafe_allow_html=True)
                    st.write(alt["detection_reason"])
                    with st.expander("Related Simulated Event IDs"):
                        st.code(alt["related_event_ids"])

                with col_ack:
                    if alt["is_acknowledged"]:
                        st.markdown(f"✅ <span style='color:#34d399; font-size:0.85rem;'>Acknowledged<br>{alt['acknowledged_at']}</span>", unsafe_allow_html=True)
                    else:
                        if st.button("Acknowledge", key=f"ack_{alt['alert_id']}"):
                            db.acknowledge_alert(alt["alert_id"])
                            st.rerun()

                st.divider()
    else:
        st.info("No security alerts matching the selected filters.")


# =============================================================================
# PAGE 6: EVENT LOGS
# =============================================================================
elif nav_page == "Event Logs":
    st.title("Audit & Event Logs")
    st.caption("Search, inspect, and export stored simulated traffic events.")

    # Filter Bar
    c_f1, c_f2, c_f3, c_f4 = st.columns(4)
    with c_f1:
        log_src = st.text_input("Source IP", placeholder="Search IP...")
    with c_f2:
        log_proto = st.selectbox("Protocol", ["ALL", "TCP", "UDP", "ICMP"], key="log_p")
    with c_f3:
        log_dec = st.selectbox("Decision", ["ALL", "ALLOW", "BLOCK"], key="log_d")
    with c_f4:
        log_class = st.selectbox("Classification", ["ALL", "Normal", "Suspicious"], key="log_c")

    events = db.get_traffic_events(
        limit=1000,
        source_ip=log_src,
        protocol=log_proto,
        decision=log_dec,
        classification=log_class
    )

    if events:
        df_logs = pd.DataFrame(events)

        # CSV Export functionality using actual stored SQLite data
        csv_data = df_logs.to_csv(index=False).encode('utf-8')
        st.download_button(
            label="📥 Export Filtered Logs to CSV",
            data=csv_data,
            file_name=f"ids_traffic_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv"
        )

        st.dataframe(
            df_logs[[
                "event_id", "timestamp", "source_ip", "destination_ip",
                "source_port", "destination_port", "protocol", "event_type",
                "firewall_decision", "matched_rule_name", "traffic_classification"
            ]],
            use_container_width=True,
            hide_index=True
        )
        st.caption(f"Displaying {len(events)} logged records.")
    else:
        st.info("No records found in database matching the search parameters.")


# =============================================================================
# PAGE 7: TESTING & EVALUATION
# =============================================================================
elif nav_page == "Testing & Evaluation":
    st.title("Benchmark & Scenario Evaluation")
    st.caption("Execute predefined ground-truth scenarios to empirically measure firewall decision accuracy and IDS detection rates.")

    scenarios = {
        "normal_traffic": "1. Normal Mixed Web & DNS Traffic",
        "matching_allow_rule": "2. Traffic Matching ALLOW Rule",
        "matching_block_rule": "3. Traffic Matching BLOCK Rule",
        "port_scan": "4. Port Scan Reconnaissance",
        "repeated_connection": "5. Repeated Connection Attempts"
    }

    c_sel, c_run = st.columns([3, 1])
    with c_sel:
        selected_scenario = st.selectbox(
            "Select Benchmark Scenario",
            options=list(scenarios.keys()),
            format_func=lambda x: scenarios[x]
        )
    with c_run:
        st.write("")
        run_btn = st.button("▶️ Run Scenario Benchmark", use_container_width=True)

    if run_btn:
        with st.spinner("Executing benchmark against active rules and heuristic thresholds..."):
            rules = db.get_firewall_rules(only_enabled=True)
            res = ev.run_scenario(
                scenario_type=selected_scenario,
                rules=rules,
                ids_config=st.session_state["ids_config"]
            )
            # Save run metrics to SQLite test_runs table
            db.save_test_run(res)
            st.session_state["last_eval_result"] = res

    if "last_eval_result" in st.session_state:
        res = st.session_state["last_eval_result"]
        st.subheader(f"Evaluation Results: {res['scenario_name']}")

        # Primary Metrics
        em1, em2, em3, em4 = st.columns(4)
        with em1:
            st.markdown(f"""
            <div class="metric-card metric-card-success">
                <div class="metric-label">Firewall Decision Accuracy</div>
                <div class="metric-val">{res['firewall_accuracy']}%</div>
                <div class="metric-sub">{res['correct_firewall_decisions']} / {res['evaluable_firewall_count']} correct decisions</div>
            </div>
            """, unsafe_allow_html=True)

        with em2:
            st.markdown(f"""
            <div class="metric-card">
                <div class="metric-label">IDS Detection Rate (Sensitivity)</div>
                <div class="metric-val">{res['detection_rate']}%</div>
                <div class="metric-sub">TP / (TP + FN)</div>
            </div>
            """, unsafe_allow_html=True)

        with em3:
            st.markdown(f"""
            <div class="metric-card metric-card-warning">
                <div class="metric-label">False-Positive Rate</div>
                <div class="metric-val">{res['false_positive_rate']}%</div>
                <div class="metric-sub">FP / (FP + TN)</div>
            </div>
            """, unsafe_allow_html=True)

        with em4:
            st.markdown(f"""
            <div class="metric-card">
                <div class="metric-label">Avg Processing Time</div>
                <div class="metric-val">{res['avg_processing_time_ms']} ms</div>
                <div class="metric-sub">{res['total_events']} events processed</div>
            </div>
            """, unsafe_allow_html=True)

        # Confusion Matrix breakdown
        st.markdown("#### IDS Confusion Matrix (Ground Truth vs. Detection)")
        cm_col1, cm_col2 = st.columns(2)
        with cm_col1:
            cm_data = pd.DataFrame([
                {"Label": "Ground Truth: Suspicious", "Detected as Suspicious (TP)": res['tp'], "Detected as Normal (FN)": res['fn']},
                {"Label": "Ground Truth: Normal", "Detected as Suspicious (FP)": res['fp'], "Detected as Normal (TN)": res['tn']}
            ])
            st.dataframe(cm_data, use_container_width=True, hide_index=True)

        with cm_col2:
            st.markdown(f"""
            **Metric Definitions & Ground Truth:**
            - **Detection Rate (Recall):** `{res['detection_rate']}%` = True Positives divided by all ground-truth suspicious events.
            - **False-Positive Rate:** `{res['false_positive_rate']}%` = Legitimate events incorrectly flagged as suspicious.
            - **Generated Alerts:** `{res['alerts_generated']}` incident record(s) created.
            """)

    # Historical Test Runs Table from SQLite
    st.markdown("---")
    st.subheader("Historical Benchmark Runs")
    history = db.get_test_runs(limit=10)
    if history:
        df_hist = pd.DataFrame(history)
        st.dataframe(
            df_hist[[
                "run_id", "timestamp", "scenario_name", "total_events",
                "firewall_accuracy", "detection_rate", "false_positive_rate", "avg_processing_time_ms"
            ]],
            use_container_width=True,
            hide_index=True
        )
    else:
        st.caption("No previous benchmark runs stored.")
