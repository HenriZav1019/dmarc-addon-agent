import streamlit as st
import pandas as pd
import json

from services.dns_checks import analyze_domain
from services.header_analyzer import analyze_headers
from services.history_store import (
    init_db,
    save_domain_scan,
    get_all_domain_scans,
    save_header_sender_mapping,
    get_all_sender_inventory,
    sender_exists
)
from services.dmarc_report_parser import parse_dmarc_aggregate_xml

st.set_page_config(
    page_title="DMARC Add-On Agent",
    layout="wide",
    initial_sidebar_state="expanded"
)

init_db()

# -----------------------------
# Clean Ops Console styling
# -----------------------------
st.markdown("""
<style>
    :root {
        --app-bg: var(--background-color);
        --card-bg: var(--secondary-background-color);
        --border-color: rgba(128, 128, 128, 0.22);
        --text-main: var(--text-color);
        --text-soft: rgba(127, 127, 127, 0.95);
        --pill-bg: rgba(100, 116, 139, 0.12);
        --pill-border: rgba(100, 116, 139, 0.28);
    }

    .stApp {
        background-color: var(--app-bg);
    }

    .app-title {
        font-size: 2rem;
        font-weight: 700;
        color: var(--text-main);
        margin-bottom: 0.2rem;
    }

    .app-subtitle {
        font-size: 0.95rem;
        color: var(--text-soft);
        margin-bottom: 1rem;
    }

    .section-header {
        font-size: 1.1rem;
        font-weight: 700;
        color: var(--text-main);
        margin-top: 0.8rem;
        margin-bottom: 0.4rem;
    }

    .soft-card {
        background: var(--card-bg);
        border: 1px solid var(--border-color);
        border-radius: 12px;
        padding: 0.95rem 1rem;
        margin-bottom: 1rem;
        box-shadow: none;
    }

    .small-note {
        color: var(--text-soft);
        font-size: 0.82rem;
        margin-top: 0.5rem;
    }

    .pill {
        display: inline-block;
        padding: 0.22rem 0.55rem;
        margin-right: 0.35rem;
        margin-bottom: 0.35rem;
        border-radius: 999px;
        background: var(--pill-bg);
        border: 1px solid var(--pill-border);
        color: var(--text-main);
        font-size: 0.82rem;
        font-weight: 600;
    }

    div[data-testid="stMetric"] {
        background: var(--card-bg);
        border: 1px solid var(--border-color);
        padding: 0.8rem;
        border-radius: 12px;
        box-shadow: none;
    }

    div[data-testid="stMetricLabel"] {
        color: var(--text-soft) !important;
    }

    div[data-testid="stMetricValue"] {
        color: var(--text-main) !important;
    }

    .stTabs [data-baseweb="tab-list"] {
        gap: 0.4rem;
    }

    .stTabs [data-baseweb="tab"] {
        background: var(--card-bg);
        border: 1px solid var(--border-color);
        border-radius: 10px 10px 0 0;
        color: var(--text-main);
        padding: 0.6rem 1rem;
    }

    .stTabs [aria-selected="true"] {
        background: var(--card-bg) !important;
        color: var(--text-main) !important;
        border-bottom-color: transparent !important;
    }

    .footer-text {
        color: var(--text-soft);
        font-size: 0.82rem;
        margin-top: 1rem;
    }
</style>
""", unsafe_allow_html=True)


# -----------------------------
# Helpers
# -----------------------------
def render_header():
    st.markdown('<div class="app-title">DMARC Add-On Agent</div>', unsafe_allow_html=True)
    st.markdown(
        '<div class="app-subtitle">Lightweight visibility and troubleshooting for DMARC, DKIM, SPF, sender mapping, and aggregate report analysis.</div>',
        unsafe_allow_html=True
    )


def section_header(text: str):
    st.markdown(f'<div class="section-header">{text}</div>', unsafe_allow_html=True)


def open_card():
    st.markdown('<div class="soft-card">', unsafe_allow_html=True)


def close_card():
    st.markdown('</div>', unsafe_allow_html=True)


def pill_list(items):
    if not items:
        st.write("- None")
        return

    html = "".join([f'<span class="pill">{str(item)}</span>' for item in items])
    st.markdown(html, unsafe_allow_html=True)


def show_status(label, data):
    status = data.get("status", "unknown")

    if status == "ok":
        st.success(f"{label}: OK")
    elif status == "warning":
        st.warning(f"{label}: Warning")
    else:
        st.error(f"{label}: Issue")

    if data.get("record"):
        st.code(data["record"])

    if data.get("details"):
        st.write(data["details"])


def show_header_result(label, value):
    value_lower = str(value).lower()

    if value_lower == "pass":
        st.success(f"{label}: PASS")
    elif value_lower in ["fail", "softfail", "permerror", "temperror"]:
        st.error(f"{label}: {value}")
    elif value_lower in ["none", "neutral", "unknown", ""]:
        st.warning(f"{label}: {value if value else 'unknown'}")
    else:
        st.info(f"{label}: {value}")


render_header()

tab1, tab2, tab3, tab4 = st.tabs([
    "🌐 Domain Analyzer",
    "📧 Header Analyzer",
    "🕘 History",
    "📥 DMARC Reports"
])

# =============================
# DOMAIN ANALYZER
# =============================
with tab1:
    section_header("Domain Analyzer")

    input_col1, input_col2 = st.columns([2, 1])

    with input_col1:
        domain = st.text_input(
            "Enter a domain",
            placeholder="example.com"
        )

    with input_col2:
        selectors_text = st.text_input(
            "Optional DKIM selectors (comma separated)",
            placeholder="Leave blank to auto-discover common selectors, or enter selector1,selector2,s1,s2"
        )

    if st.button("Analyze Domain", use_container_width=True):
        selectors = [s.strip() for s in selectors_text.split(",") if s.strip()]

        if not domain.strip():
            st.error("Please enter a domain.")
        else:
            result = analyze_domain(domain.strip(), selectors)
            save_domain_scan(domain.strip(), result)

            metric1, metric2, metric3, metric4 = st.columns(4)
            with metric1:
                st.metric("DMARC Status", result["dmarc"].get("status", "unknown"))
            with metric2:
                st.metric("SPF Status", result["spf"].get("status", "unknown"))
            with metric3:
                st.metric("DKIM Selectors Tested", len(result["dkim"]))
            with metric4:
                st.metric("Health Score", result["health"]["score"])

            left, right = st.columns(2)

            with left:
                section_header("🔐 DMARC")
                open_card()
                show_status("DMARC", result["dmarc"])
                close_card()

                section_header("📡 SPF")
                open_card()
                show_status("SPF", result["spf"])

                spf_analysis = result["spf"].get("spf_analysis", {})
                if spf_analysis:
                    spf_status = spf_analysis.get("status", "unknown")
                    spf_details = spf_analysis.get("details", "No SPF analysis available.")

                    if spf_status == "low":
                        st.success(spf_details)
                    elif spf_status == "warning":
                        st.warning(spf_details)
                    else:
                        st.error(spf_details)

                    st.write(f"**Includes:** {spf_analysis.get('include_count', 0)}")
                    st.write(f"**A mechanisms:** {spf_analysis.get('a_count', 0)}")
                    st.write(f"**MX mechanisms:** {spf_analysis.get('mx_count', 0)}")
                    st.write(f"**Exists mechanisms:** {spf_analysis.get('exists_count', 0)}")
                    st.write(f"**Redirect modifiers:** {spf_analysis.get('redirect_count', 0)}")
                    st.write(f"**Estimated DNS lookups:** {spf_analysis.get('lookup_count', 0)}")

                    with st.expander("Show SPF extracted sources"):
                        st.write(f"**IP4 entries:** {', '.join(spf_analysis.get('ip4_list', [])) or 'None'}")
                        st.write(f"**IP6 entries:** {', '.join(spf_analysis.get('ip6_list', [])) or 'None'}")
                        st.write(f"**Include domains:** {', '.join(spf_analysis.get('include_domains', [])) or 'None'}")
                        st.write(f"**A mechanisms:** {', '.join(spf_analysis.get('a_mechanisms', [])) or 'None'}")
                        st.write(f"**MX mechanisms:** {', '.join(spf_analysis.get('mx_mechanisms', [])) or 'None'}")
                        st.write(f"**Exists mechanisms:** {', '.join(spf_analysis.get('exists_mechanisms', [])) or 'None'}")
                        st.write(f"**Redirect target:** {spf_analysis.get('redirect_target') or 'None'}")
                        st.divider()
                        st.write("🔄 **Expanded SPF IPs (from includes):**")
                        st.write(f"**Expanded IP4:** {', '.join(spf_analysis.get('expanded_ip4', [])) or 'None'}")
                        st.write(f"**Expanded IP6:** {', '.join(spf_analysis.get('expanded_ip6', [])) or 'None'}")

                    st.write("**SPF optimization findings:**")
                    for item in spf_analysis.get("optimization_findings", []):
                        st.write(f"- {item}")

                    st.write("**SPF optimization recommendations:**")
                    for item in spf_analysis.get("optimization_recommendations", []):
                        st.write(f"- {item}")

                close_card()

            with right:
                section_header("🔑 DKIM")
                open_card()
                if result["dkim"]:
                    for d in result["dkim"]:
                        show_status(f"Selector: {d['selector']}", d)

                        key_info = d.get("key_info", {})
                        if key_info:
                            strength = key_info.get("strength", "unknown")
                            details = key_info.get("details", "No key details available.")
                            bits = key_info.get("key_length_bits")

                            if strength == "strong":
                                st.success(details)
                            elif strength in ["warning", "unknown"]:
                                st.warning(details)
                            else:
                                st.error(details)

                            if bits:
                                st.write(f"**Estimated key length:** {bits} bits")
                else:
                    st.info("No DKIM selectors were provided for testing.")
                close_card()

            section_header("🔎 DKIM Discovery Results")
            open_card()
            if result.get("auto_discovered"):
                st.write("Automatic common-selector discovery was used.")

            valid_selectors = result.get("valid_dkim_selectors", [])
            missing_selectors = result.get("missing_dkim_selectors", [])

            if valid_selectors:
                st.success(f"Valid DKIM selectors found: {', '.join(valid_selectors)}")
            else:
                st.warning("No valid DKIM selectors were found from the tested list.")

            if missing_selectors:
                with st.expander("Show selectors that did not match"):
                    for selector in missing_selectors:
                        st.write(f"- {selector}")
            close_card()

            section_header("🧩 Sender Mapping")
            open_card()
            sender_mapping = result.get("sender_mapping", {})

            st.write(f"**Domain:** {sender_mapping.get('domain', 'Not found')}")

            st.write("**SPF include domains:**")
            pill_list(sender_mapping.get("spf_include_domains", []))

            st.write("**SPF direct IP4 entries:**")
            pill_list(sender_mapping.get("spf_direct_ip4", []))

            st.write("**SPF expanded IP4 entries:**")
            pill_list(sender_mapping.get("spf_expanded_ip4", []))

            st.write("**Valid DKIM selectors:**")
            pill_list(sender_mapping.get("dkim_valid_selectors", []))

            st.write("**Needs review:**")
            review_items = sender_mapping.get("needs_review", [])
            if review_items:
                for item in review_items:
                    st.write(f"- {item}")
            else:
                st.write("- No obvious issues flagged")
            close_card()

            section_header("💚 Health Score")
            open_card()
            health = result["health"]

            if health["label"] == "Excellent":
                st.success(f"Overall Health: {health['label']} ({health['score']}/100)")
            elif health["label"] == "Good":
                st.success(f"Overall Health: {health['label']} ({health['score']}/100)")
            elif health["label"] == "Fair":
                st.warning(f"Overall Health: {health['label']} ({health['score']}/100)")
            else:
                st.error(f"Overall Health: {health['label']} ({health['score']}/100)")

            st.write("**Why this score?**")
            for item in health["reasons"]:
                st.write(f"- {item}")
            close_card()

            section_header("🧭 Policy Progression Recommendations")
            open_card()
            for item in result.get("policy_recommendations", []):
                st.write(f"- {item}")
            close_card()

            section_header("📊 Summary")
            open_card()
            for item in result["summary"]:
                st.write(f"- {item}")
            close_card()

            section_header("📤 Export Domain Analysis")
            open_card()
            domain_json = json.dumps(result, indent=2)
            st.download_button(
                label="Download Domain Analysis JSON",
                data=domain_json,
                file_name=f"{domain.strip()}_domain_analysis.json",
                mime="application/json"
            )
            close_card()

# =============================
# HEADER ANALYZER
# =============================
with tab2:
    section_header("Header Analyzer")

    raw_headers = st.text_area(
        "Paste raw email headers here",
        height=300,
        placeholder="Paste full raw email headers..."
    )

    if st.button("Analyze Headers", use_container_width=True):
        if not raw_headers.strip():
            st.error("Please paste email headers.")
        else:
            result = analyze_headers(raw_headers)
            sender_newness = save_header_sender_mapping(result.get("sender_mapping", {}))

            if result.get("error"):
                st.error(result["error"])
            else:
                m1, m2, m3 = st.columns(3)
                with m1:
                    st.metric("SPF Result", result["spf"]["result"])
                with m2:
                    st.metric("DKIM Result", result["dkim"]["result"])
                with m3:
                    st.metric("DMARC Result", result["dmarc"]["result"])

                section_header("Authentication Results")
                open_card()
                show_header_result("SPF", result["spf"]["result"])
                show_header_result("DKIM", result["dkim"]["result"])
                show_header_result("DMARC", result["dmarc"]["result"])
                close_card()

                info_col1, info_col2 = st.columns(2)

                with info_col1:
                    section_header("Message Details")
                    open_card()
                    st.write(f"**From Header:** {result['from_header'] or 'Not found'}")
                    st.write(f"**From Domain:** {result['from_domain'] or 'Not found'}")
                    st.write(f"**Organizational Domain:** {result['org_domain'] or 'Not found'}")
                    st.write(f"**Return-Path:** {result['return_path'] or 'Not found'}")
                    st.write(f"**Return-Path Domain:** {result['return_path_domain'] or 'Not found'}")
                    st.write(f"**Reply-To:** {result['reply_to'] or 'Not found'}")
                    st.write(f"**Reply-To Domain:** {result['reply_to_domain'] or 'Not found'}")
                    st.write(f"**Received Header Count:** {result['received_count']}")
                    close_card()

                with info_col2:
                    section_header("Technical Details")
                    open_card()
                    st.write(f"**SPF Domain:** {result['spf']['domain'] or 'Not found'}")
                    st.write(f"**SPF Aligned:** {'Yes' if result['spf']['aligned'] else 'No'}")
                    st.write(f"**DKIM Domain:** {result['dkim']['domain'] or 'Not found'}")
                    st.write(f"**DKIM Selector:** {result['dkim']['selector'] or 'Not found'}")
                    st.write(f"**DKIM Algorithm:** {result['dkim']['algorithm'] or 'Not found'}")
                    st.write(f"**DKIM Aligned:** {'Yes' if result['dkim']['aligned'] else 'No'}")
                    st.write(f"**DMARC Header From Domain:** {result['dmarc']['header_from_domain'] or 'Not found'}")
                    close_card()

                section_header("🧩 Sender Mapping")
                open_card()
                sender_mapping = result.get("sender_mapping", {})

                st.write("**Known vs New Sender Signals:**")
                if sender_newness:
                    new_count = 0
                    for sender_type, is_new in sender_newness.items():
                        if is_new:
                            new_count += 1
                            st.warning(f"{sender_type}: new sender observed")
                        else:
                            st.success(f"{sender_type}: known sender")

                    if new_count >= 2:
                        st.warning("Multiple sender components are new. Review whether this is an expected third-party sender.")
                else:
                    st.info("No sender observations were saved from this header.")

                st.write("🚨 **Suspicious / Risk Indicators:**")
                risk_flags = sender_mapping.get("risk_flags", [])
                if risk_flags:
                    for item in risk_flags:
                        st.error(f"- {item}")
                else:
                    st.success("No obvious suspicious sender patterns detected.")

                st.write("🕵️ **Unauthorized / Shadow Sender Signals:**")
                shadow_signals = sender_mapping.get("shadow_signals", [])
                possible_shadow_sender = sender_mapping.get("possible_shadow_sender", False)

                if possible_shadow_sender:
                    st.error("Possible shadow / unauthorized sender pattern detected.")
                elif shadow_signals:
                    st.warning("Some sender mismatch signals were detected.")
                else:
                    st.success("No obvious shadow sender pattern detected.")

                if shadow_signals:
                    for item in shadow_signals:
                        st.write(f"- {item}")

                st.write("**Observed domains:**")
                pill_list(sender_mapping.get("observed_domains", []))

                st.write(f"**Visible From domain:** {sender_mapping.get('from_domain') or 'Not found'}")
                st.write(f"**Return-Path domain:** {sender_mapping.get('return_path_domain') or 'Not found'}")
                st.write(f"**Reply-To domain:** {sender_mapping.get('reply_to_domain') or 'Not found'}")
                st.write(f"**DKIM domain:** {sender_mapping.get('dkim_domain') or 'Not found'}")
                st.write(f"**DKIM selector:** {sender_mapping.get('dkim_selector') or 'Not found'}")
                st.write(f"**SPF mailfrom domain:** {sender_mapping.get('spf_mailfrom_domain') or 'Not found'}")

                st.write("**SPF include domains:**")
                pill_list(sender_mapping.get("spf_include_domains", []))

                st.write("**SPF expanded IP4 entries:**")
                pill_list(sender_mapping.get("spf_expanded_ip4", []))

                st.write("**Needs review:**")
                review_items = sender_mapping.get("needs_review", [])
                if review_items:
                    for item in review_items:
                        st.write(f"- {item}")
                else:
                    st.write("- No obvious issues flagged")
                close_card()

                section_header("🌐 DNS Checks (Live)")
                open_card()
                dns = result.get("dns_checks", {})

                if dns.get("dmarc_from_domain"):
                    st.write("**DMARC (From Domain):**")
                    st.code(dns["dmarc_from_domain"].get("record", "Not found"))

                if dns.get("dmarc_org_domain"):
                    st.write("**DMARC (Organizational Domain Fallback):**")
                    st.code(dns["dmarc_org_domain"].get("record", "Not found"))

                if dns.get("spf_domain"):
                    st.write("**SPF (Envelope Domain):**")
                    st.code(dns["spf_domain"].get("record", "Not found"))

                    spf_analysis = dns["spf_domain"].get("spf_analysis", {})
                    if spf_analysis:
                        spf_status = spf_analysis.get("status", "unknown")
                        spf_details = spf_analysis.get("details", "No SPF analysis available.")

                        if spf_status == "low":
                            st.success(spf_details)
                        elif spf_status == "warning":
                            st.warning(spf_details)
                        else:
                            st.error(spf_details)

                        st.write(f"**Includes:** {spf_analysis.get('include_count', 0)}")
                        st.write(f"**A mechanisms:** {spf_analysis.get('a_count', 0)}")
                        st.write(f"**MX mechanisms:** {spf_analysis.get('mx_count', 0)}")
                        st.write(f"**Exists mechanisms:** {spf_analysis.get('exists_count', 0)}")
                        st.write(f"**Redirect modifiers:** {spf_analysis.get('redirect_count', 0)}")
                        st.write(f"**Estimated DNS lookups:** {spf_analysis.get('lookup_count', 0)}")

                        with st.expander("Show SPF extracted sources"):
                            st.write(f"**IP4 entries:** {', '.join(spf_analysis.get('ip4_list', [])) or 'None'}")
                            st.write(f"**IP6 entries:** {', '.join(spf_analysis.get('ip6_list', [])) or 'None'}")
                            st.write(f"**Include domains:** {', '.join(spf_analysis.get('include_domains', [])) or 'None'}")
                            st.write(f"**A mechanisms:** {', '.join(spf_analysis.get('a_mechanisms', [])) or 'None'}")
                            st.write(f"**MX mechanisms:** {', '.join(spf_analysis.get('mx_mechanisms', [])) or 'None'}")
                            st.write(f"**Exists mechanisms:** {', '.join(spf_analysis.get('exists_mechanisms', [])) or 'None'}")
                            st.write(f"**Redirect target:** {spf_analysis.get('redirect_target') or 'None'}")
                            st.divider()
                            st.write("🔄 **Expanded SPF IPs (from includes):**")
                            st.write(f"**Expanded IP4:** {', '.join(spf_analysis.get('expanded_ip4', [])) or 'None'}")
                            st.write(f"**Expanded IP6:** {', '.join(spf_analysis.get('expanded_ip6', [])) or 'None'}")

                        st.write("**SPF optimization findings:**")
                        for item in spf_analysis.get("optimization_findings", []):
                            st.write(f"- {item}")

                        st.write("**SPF optimization recommendations:**")
                        for item in spf_analysis.get("optimization_recommendations", []):
                            st.write(f"- {item}")

                if dns.get("dkim"):
                    st.write("**DKIM Selector Check:**")
                    st.code(dns["dkim"].get("record", "Not found"))

                    dkim_key_info = dns["dkim"].get("key_info", {})
                    if dkim_key_info:
                        strength = dkim_key_info.get("strength", "unknown")
                        details = dkim_key_info.get("details", "No key details available.")
                        bits = dkim_key_info.get("key_length_bits")

                        if strength == "strong":
                            st.success(details)
                        elif strength in ["warning", "unknown"]:
                            st.warning(details)
                        else:
                            st.error(details)

                        if bits:
                            st.write(f"**Estimated key length:** {bits} bits")

                with st.expander("Show Authentication-Results Headers"):
                    if result["authentication_results"]:
                        for item in result["authentication_results"]:
                            st.code(item)
                    else:
                        st.write("No Authentication-Results headers found.")

                with st.expander("Show List-Unsubscribe Headers"):
                    if result["list_unsubscribe"]:
                        for item in result["list_unsubscribe"]:
                            st.code(item)
                    else:
                        st.write("No List-Unsubscribe headers found.")
                close_card()

                section_header("Findings")
                open_card()
                for item in result["findings"]:
                    st.write(f"- {item}")
                close_card()

                section_header("Summary")
                open_card()
                for item in result["summary"]:
                    st.write(f"- {item}")
                close_card()

                section_header("Remediation")
                open_card()
                if result["remediation"]:
                    for item in result["remediation"]:
                        st.write(f"- {item}")
                else:
                    st.success("No obvious remediation items were detected.")
                close_card()

                section_header("📤 Export Header Analysis")
                open_card()
                header_json = json.dumps(result, indent=2)
                st.download_button(
                    label="Download Header Analysis JSON",
                    data=header_json,
                    file_name="header_analysis.json",
                    mime="application/json"
                )
                close_card()

# =============================
# HISTORY
# =============================
with tab3:
    section_header("Saved Domain Scan History")

    all_scans = get_all_domain_scans()

    if all_scans:
        df = pd.DataFrame(
            all_scans,
            columns=[
                "Scanned At",
                "Domain",
                "DMARC Status",
                "SPF Status",
                "Health Score",
                "Health Label",
                "Summary"
            ]
        )

        search_term = st.text_input(
            "Search by domain",
            placeholder="Type part of a domain name..."
        )

        if search_term.strip():
            filtered_df = df[df["Domain"].str.contains(search_term, case=False, na=False)].copy()
        else:
            filtered_df = df.copy()

        open_card()
        st.dataframe(filtered_df, use_container_width=True)
        st.write(f"**Matching scans:** {len(filtered_df)}")
        st.write(f"**Total saved scans:** {len(df)}")

        history_csv = filtered_df.to_csv(index=False)
        st.download_button(
            label="Download Scan History CSV",
            data=history_csv,
            file_name="domain_scan_history.csv",
            mime="text/csv"
        )
        close_card()

        if not filtered_df.empty:
            section_header("📈 Health Score Trend")
            open_card()
            filtered_df["Scanned At"] = pd.to_datetime(filtered_df["Scanned At"], errors="coerce")
            filtered_df = filtered_df.dropna(subset=["Scanned At"])
            filtered_df = filtered_df.sort_values("Scanned At")
            chart_df = filtered_df[["Scanned At", "Health Score"]].set_index("Scanned At")
            st.line_chart(chart_df)
            close_card()
        else:
            st.info("No matching scans to chart.")
    else:
        st.info("No saved domain scans yet.")

    section_header("📬 Sender Inventory")
    sender_rows = get_all_sender_inventory()

    if sender_rows:
        sender_df = pd.DataFrame(
            sender_rows,
            columns=[
                "Sender Value",
                "Sender Type",
                "First Seen",
                "Last Seen"
            ]
        )

        open_card()
        st.dataframe(sender_df, use_container_width=True)

        sender_csv = sender_df.to_csv(index=False)
        st.download_button(
            label="Download Sender Inventory CSV",
            data=sender_csv,
            file_name="sender_inventory.csv",
            mime="text/csv"
        )
        close_card()
    else:
        st.info("No sender inventory saved yet.")

# =============================
# DMARC REPORTS
# =============================
with tab4:
    section_header("Upload DMARC Aggregate XML Report")

    uploaded_file = st.file_uploader(
        "Choose a DMARC aggregate XML file",
        type=["xml"]
    )

    if uploaded_file is not None:
        file_bytes = uploaded_file.read()
        parsed_report = parse_dmarc_aggregate_xml(file_bytes)

        if parsed_report.get("error"):
            st.error(parsed_report["error"])
        else:
            metadata = parsed_report["metadata"]
            policy = parsed_report["policy"]
            summary = parsed_report["summary"]
            records = parsed_report["records"]
            findings = parsed_report["findings"]

            correlated_sender_inventory = []

            for record in records:
                header_from = record.get("header_from", "")
                envelope_from = record.get("envelope_from", "")
                dkim_domain = record.get("dkim_domain", "")

                header_from_known = sender_exists(header_from, "from_domain") if header_from else False
                envelope_from_known = sender_exists(envelope_from, "spf_mailfrom_domain") if envelope_from else False
                dkim_domain_known = sender_exists(dkim_domain, "dkim_domain") if dkim_domain else False

                correlated_sender_inventory.append({
                    "source_ip": record.get("source_ip", ""),
                    "count": record.get("count", 0),
                    "header_from": header_from,
                    "header_from_status": "known" if header_from_known else "new",
                    "envelope_from": envelope_from,
                    "envelope_from_status": "known" if envelope_from_known else "new",
                    "dkim_domain": dkim_domain,
                    "dkim_domain_status": "known" if dkim_domain_known else "new",
                })

            m1, m2, m3, m4 = st.columns(4)
            with m1:
                st.metric("Total Records", summary["total_records"])
            with m2:
                st.metric("Total Messages", summary["total_messages"])
            with m3:
                st.metric("SPF Non-Pass", summary["failed_spf_count"])
            with m4:
                st.metric("DKIM Non-Pass", summary["failed_dkim_count"])

            meta1, meta2 = st.columns(2)
            with meta1:
                section_header("Report Metadata")
                open_card()
                st.write(f"**Organization:** {metadata['org_name'] or 'Not found'}")
                st.write(f"**Email:** {metadata['email'] or 'Not found'}")
                st.write(f"**Report ID:** {metadata['report_id'] or 'Not found'}")
                st.write(f"**Date Begin:** {metadata['date_begin'] or 'Not found'}")
                st.write(f"**Date End:** {metadata['date_end'] or 'Not found'}")
                close_card()

            with meta2:
                section_header("Published Policy")
                open_card()
                st.write(f"**Domain:** {policy['domain'] or 'Not found'}")
                st.write(f"**Policy (p):** {policy['p'] or 'Not found'}")
                st.write(f"**Subdomain Policy (sp):** {policy['sp'] or 'Not found'}")
                st.write(f"**DKIM Alignment (adkim):** {policy['adkim'] or 'Not found'}")
                st.write(f"**SPF Alignment (aspf):** {policy['aspf'] or 'Not found'}")
                st.write(f"**Policy Percentage (pct):** {policy['pct'] or 'Not found'}")
                close_card()

            section_header("Priority Findings")
            open_card()
            for item in findings:
                st.write(f"- {item}")

            st.divider()
            st.write("**Priority issues:**")
            for item in parsed_report.get("priority_issues", []):
                st.write(f"- {item}")
            close_card()

            section_header("🔗 Sender Correlation Overview")
            c1, c2, c3 = st.columns(3)
            with c1:
                st.metric("Expected", len(parsed_report.get("expected_records", [])))
            with c2:
                st.metric("Needs Review", len(parsed_report.get("needs_review_records", [])))
            with c3:
                st.metric("High Risk", len(parsed_report.get("high_risk_records", [])))

            section_header("🔥 Top Sending Sources (by Volume)")
            open_card()
            for item in parsed_report.get("top_sources", []):
                st.write(f"- {item['source_ip']} → {item['count']} messages")
            close_card()

            section_header("⚠️ Top Failing Sources")
            open_card()
            for item in parsed_report.get("failing_sources", []):
                st.write(
                    f"- {item['source_ip']} → {item['count']} messages "
                    f"(SPF: {item['spf_result']}, DKIM: {item['dkim_result']})"
                )
            close_card()

            section_header("🧠 Sender Inventory Correlation")
            sender_corr_df = pd.DataFrame(correlated_sender_inventory)

            open_card()
            if not sender_corr_df.empty:
                st.dataframe(sender_corr_df, use_container_width=True)

                new_sender_rows = sender_corr_df[
                    (sender_corr_df["header_from_status"] == "new") |
                    (sender_corr_df["envelope_from_status"] == "new") |
                    (sender_corr_df["dkim_domain_status"] == "new")
                ]

                if not new_sender_rows.empty:
                    st.warning("Some DMARC report sender domains were not found in the saved sender inventory.")
                else:
                    st.success("All correlated DMARC sender domains were already known in the sender inventory.")
            else:
                st.info("No sender inventory correlation data available.")
            close_card()

            section_header("🚨 High Risk Correlated Records")
            high_risk_df = pd.DataFrame(parsed_report.get("high_risk_records", []))
            open_card()
            if not high_risk_df.empty:
                st.dataframe(high_risk_df, use_container_width=True)
            else:
                st.success("No high-risk correlated records found in this report.")
            close_card()

            section_header("⚠️ Needs Review Correlated Records")
            review_df = pd.DataFrame(parsed_report.get("needs_review_records", []))
            open_card()
            if not review_df.empty:
                st.dataframe(review_df, use_container_width=True)
            else:
                st.info("No needs-review correlated records found in this report.")
            close_card()

            section_header("📬 Grouped by Header From Domain")
            header_from_df = pd.DataFrame(parsed_report.get("grouped_header_from", []))
            open_card()
            if not header_from_df.empty:
                st.dataframe(header_from_df, use_container_width=True)
            else:
                st.info("No Header From grouping data available.")
            close_card()

            section_header("📨 Grouped by Envelope From Domain")
            envelope_from_df = pd.DataFrame(parsed_report.get("grouped_envelope_from", []))
            open_card()
            if not envelope_from_df.empty:
                st.dataframe(envelope_from_df, use_container_width=True)
            else:
                st.info("No Envelope From grouping data available.")
            close_card()

            section_header("Parsed Records")
            open_card()
            if records:
                df = pd.DataFrame(records)
                st.dataframe(df, use_container_width=True)
            else:
                st.info("No record rows were found in this XML report.")
            close_card()

            section_header("📤 Export DMARC Report Analysis")
            open_card()
            report_json = json.dumps(parsed_report, indent=2)

            st.download_button(
                label="Download DMARC Report JSON",
                data=report_json,
                file_name="dmarc_report_analysis.json",
                mime="application/json"
            )

            if records:
                csv_data = pd.DataFrame(records).to_csv(index=False)

                st.download_button(
                    label="Download DMARC Records CSV",
                    data=csv_data,
                    file_name="dmarc_report_records.csv",
                    mime="text/csv"
                )
            close_card()

st.markdown(
    '<div class="footer-text">Built for troubleshooting, sender visibility, and actionable authentication analysis.</div>',
    unsafe_allow_html=True
)