import xml.etree.ElementTree as ET
from datetime import datetime


def safe_find_text(element, path, default=""):
    found = element.find(path)
    if found is not None and found.text is not None:
        return found.text.strip()
    return default


def format_unix_date(value: str):
    try:
        return datetime.utcfromtimestamp(int(value)).strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return value


def parse_dmarc_aggregate_xml(file_content: bytes):
    try:
        root = ET.fromstring(file_content)
    except Exception as exc:
        return {
            "error": f"Could not parse XML file: {exc}"
        }

    report_metadata = root.find("report_metadata")
    policy_published = root.find("policy_published")

    metadata = {
        "org_name": safe_find_text(report_metadata, "org_name"),
        "email": safe_find_text(report_metadata, "email"),
        "report_id": safe_find_text(report_metadata, "report_id"),
        "date_begin": format_unix_date(safe_find_text(report_metadata, "date_range/begin")),
        "date_end": format_unix_date(safe_find_text(report_metadata, "date_range/end")),
    }

    policy = {
        "domain": safe_find_text(policy_published, "domain"),
        "adkim": safe_find_text(policy_published, "adkim"),
        "aspf": safe_find_text(policy_published, "aspf"),
        "p": safe_find_text(policy_published, "p"),
        "sp": safe_find_text(policy_published, "sp"),
        "pct": safe_find_text(policy_published, "pct"),
    }

    records = []
    total_messages = 0
    failed_dmarc_count = 0
    failed_spf_count = 0
    failed_dkim_count = 0

    for record in root.findall("record"):
        row = record.find("row")
        identifiers = record.find("identifiers")
        auth_results = record.find("auth_results")

        source_ip = safe_find_text(row, "source_ip")
        count = int(safe_find_text(row, "count", "0") or 0)
        disposition = safe_find_text(row, "policy_evaluated/disposition")
        dkim_result = safe_find_text(row, "policy_evaluated/dkim")
        spf_result = safe_find_text(row, "policy_evaluated/spf")
        header_from = safe_find_text(identifiers, "header_from")

        envelope_from = ""
        header_d = ""

        spf_auth = auth_results.find("spf") if auth_results is not None else None
        dkim_auth = auth_results.find("dkim") if auth_results is not None else None

        if spf_auth is not None:
            envelope_from = safe_find_text(spf_auth, "domain")

        if dkim_auth is not None:
            header_d = safe_find_text(dkim_auth, "domain")

        record_data = {
            "source_ip": source_ip,
            "count": count,
            "disposition": disposition,
            "dkim_result": dkim_result,
            "spf_result": spf_result,
            "header_from": header_from,
            "envelope_from": envelope_from,
            "dkim_domain": header_d,
        }

        total_messages += count

        if disposition.lower() != "none":
            failed_dmarc_count += count

        if spf_result.lower() != "pass":
            failed_spf_count += count

        if dkim_result.lower() != "pass":
            failed_dkim_count += count

        records.append(record_data)

    summary = {
        "total_records": len(records),
        "total_messages": total_messages,
        "failed_dmarc_count": failed_dmarc_count,
        "failed_spf_count": failed_spf_count,
        "failed_dkim_count": failed_dkim_count,
    }

    findings = []

    if failed_dmarc_count > 0:
        findings.append(f"{failed_dmarc_count} messages were affected by DMARC policy actions other than none.")
    else:
        findings.append("No messages showed DMARC policy action beyond 'none' in this report.")

    if failed_spf_count > 0:
        findings.append(f"{failed_spf_count} messages had SPF results other than pass.")

    if failed_dkim_count > 0:
        findings.append(f"{failed_dkim_count} messages had DKIM results other than pass.")

    if not findings:
        findings.append("No obvious issues detected in this report.")

    # 🔥 Top offending sources (by volume)
    top_sources = sorted(
        records,
        key=lambda x: x["count"],
        reverse=True
    )[:5]

    # 🔥 Top failing sources (SPF or DKIM issues)
    failing_sources = sorted(
        [r for r in records if r["spf_result"] != "pass" or r["dkim_result"] != "pass"],
        key=lambda x: x["count"],
        reverse=True
    )[:5]

    # 🔥 Group by header_from domain
    header_from_summary = {}
    for r in records:
        key = r["header_from"] or "(unknown)"
        if key not in header_from_summary:
            header_from_summary[key] = {
                "header_from": key,
                "total_messages": 0,
                "spf_failures": 0,
                "dkim_failures": 0,
            }

        header_from_summary[key]["total_messages"] += r["count"]

        if r["spf_result"].lower() != "pass":
            header_from_summary[key]["spf_failures"] += r["count"]

        if r["dkim_result"].lower() != "pass":
            header_from_summary[key]["dkim_failures"] += r["count"]

    grouped_header_from = sorted(
        header_from_summary.values(),
        key=lambda x: x["total_messages"],
        reverse=True
    )

    # 🔥 Group by envelope_from domain
    envelope_from_summary = {}
    for r in records:
        key = r["envelope_from"] or "(unknown)"
        if key not in envelope_from_summary:
            envelope_from_summary[key] = {
                "envelope_from": key,
                "total_messages": 0,
                "failing_messages": 0,
            }

        envelope_from_summary[key]["total_messages"] += r["count"]

        if r["spf_result"].lower() != "pass" or r["dkim_result"].lower() != "pass":
            envelope_from_summary[key]["failing_messages"] += r["count"]

    grouped_envelope_from = sorted(
        envelope_from_summary.values(),
        key=lambda x: x["total_messages"],
        reverse=True
    )

    # 🔥 Priority issue summary
    priority_issues = []

    if grouped_header_from:
        top_header = grouped_header_from[0]
        priority_issues.append(
            f'Top visible From domain in this report: {top_header["header_from"]} '
            f'with {top_header["total_messages"]} messages.'
        )

    if grouped_envelope_from:
        top_env = max(grouped_envelope_from, key=lambda x: x["failing_messages"])
        if top_env["failing_messages"] > 0:
            priority_issues.append(
                f'Top failing envelope sender domain: {top_env["envelope_from"]} '
                f'with {top_env["failing_messages"]} failing messages.'
            )

    if failing_sources:
        top_fail = failing_sources[0]
        priority_issues.append(
            f'Top failing source IP: {top_fail["source_ip"]} '
            f'with {top_fail["count"]} messages '
            f'(SPF: {top_fail["spf_result"]}, DKIM: {top_fail["dkim_result"]}).'
        )

        correlated_records = []

    for r in records:
        risk_flags = []

        spf_result = (r.get("spf_result") or "").lower()
        dkim_result = (r.get("dkim_result") or "").lower()
        header_from = r.get("header_from") or ""
        envelope_from = r.get("envelope_from") or ""
        dkim_domain = r.get("dkim_domain") or ""

        if spf_result != "pass":
            risk_flags.append("SPF did not pass")

        if dkim_result != "pass":
            risk_flags.append("DKIM did not pass")

        if spf_result != "pass" and dkim_result != "pass":
            risk_flags.append("Both SPF and DKIM failed or did not pass")

        if not envelope_from:
            risk_flags.append("Envelope sender domain was not present in auth results")

        if not dkim_domain:
            risk_flags.append("DKIM auth domain was not present in auth results")

        if header_from and envelope_from and header_from != envelope_from:
            risk_flags.append("Header From and envelope sender domains differ")

        if header_from and dkim_domain and header_from != dkim_domain:
            risk_flags.append("Header From and DKIM auth domains differ")

        if not risk_flags:
            correlation_status = "expected"
        elif "Both SPF and DKIM failed or did not pass" in risk_flags:
            correlation_status = "high_risk"
        else:
            correlation_status = "needs_review"

        correlated_records.append({
            "source_ip": r.get("source_ip", ""),
            "count": r.get("count", 0),
            "header_from": header_from,
            "envelope_from": envelope_from,
            "dkim_domain": dkim_domain,
            "spf_result": r.get("spf_result", ""),
            "dkim_result": r.get("dkim_result", ""),
            "correlation_status": correlation_status,
            "risk_flags": risk_flags
        })

    high_risk_records = [x for x in correlated_records if x["correlation_status"] == "high_risk"]
    needs_review_records = [x for x in correlated_records if x["correlation_status"] == "needs_review"]
    expected_records = [x for x in correlated_records if x["correlation_status"] == "expected"]

    return {
        "metadata": metadata,
        "policy": policy,
        "summary": summary,
        "records": records,
        "findings": findings,
        "top_sources": top_sources,
        "failing_sources": failing_sources,
        "grouped_header_from": grouped_header_from,
        "grouped_envelope_from": grouped_envelope_from,
        "priority_issues": priority_issues,
        "correlated_records": correlated_records,
        "high_risk_records": high_risk_records,
        "needs_review_records": needs_review_records,
        "expected_records": expected_records,
    }