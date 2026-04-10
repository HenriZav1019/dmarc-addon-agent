import re
from email import policy
from email.parser import Parser
from urllib.parse import urlparse
from services.dns_checks import find_dmarc_record, find_spf_record, check_dkim_selector


def extract_domain(value: str) -> str:
    if not value:
        return ""

    value = value.strip()

    email_match = re.search(r'[\w\.-]+@([\w\.-]+\.\w+)', value)
    if email_match:
        return email_match.group(1).lower()

    domain_match = re.search(r'([\w\.-]+\.\w+)', value)
    if domain_match:
        return domain_match.group(1).lower()

    return ""


def get_header_value(message, header_name: str) -> str:
    value = message.get(header_name)
    return value.strip() if value else ""


def get_all_header_values(message, header_name: str) -> list[str]:
    values = message.get_all(header_name, [])
    return [v.strip() for v in values if v and v.strip()]


def parse_authentication_results(auth_results: list[str]) -> dict:
    joined = " | ".join(auth_results).lower()

    result = {
        "spf_result": "unknown",
        "dkim_result": "unknown",
        "dmarc_result": "unknown",
        "spf_domain": "",
        "dkim_domain": "",
        "dmarc_domain": "",
    }

    spf_match = re.search(r"\bspf=(pass|fail|softfail|neutral|none|temperror|permerror)\b", joined)
    if spf_match:
        result["spf_result"] = spf_match.group(1)

    dkim_match = re.search(r"\bdkim=(pass|fail|none|neutral|temperror|permerror)\b", joined)
    if dkim_match:
        result["dkim_result"] = dkim_match.group(1)

    dmarc_match = re.search(r"\bdmarc=(pass|fail|none|bestguesspass|temperror|permerror)\b", joined)
    if dmarc_match:
        result["dmarc_result"] = dmarc_match.group(1)

    spf_domain_match = re.search(r"smtp\.mailfrom=([^\s;]+)", joined)
    if spf_domain_match:
        result["spf_domain"] = extract_domain(spf_domain_match.group(1))

    dkim_domain_match = re.search(r"header\.d=([^\s;]+)", joined)
    if dkim_domain_match:
        result["dkim_domain"] = extract_domain(dkim_domain_match.group(1))

    dmarc_domain_match = re.search(r"header\.from=([^\s;]+)", joined)
    if dmarc_domain_match:
        result["dmarc_domain"] = extract_domain(dmarc_domain_match.group(1))

    return result


def parse_received_spf(received_spf: str) -> dict:
    text = (received_spf or "").strip()

    result = {
        "result": "unknown",
        "mailfrom_domain": "",
        "ip": "",
        "raw": text,
    }

    lowered = text.lower()

    spf_match = re.search(r"\b(pass|fail|softfail|neutral|none|temperror|permerror)\b", lowered)
    if spf_match:
        result["result"] = spf_match.group(1)

    mailfrom_match = re.search(r"envelope-from[=:\s<\"]+([^>\s;\"]+)", text, re.IGNORECASE)
    if mailfrom_match:
        result["mailfrom_domain"] = extract_domain(mailfrom_match.group(1))

    if not result["mailfrom_domain"]:
        domain_match = re.search(r"domain of\s+([^\s]+)", text, re.IGNORECASE)
        if domain_match:
            result["mailfrom_domain"] = extract_domain(domain_match.group(1))

    ip_match = re.search(r"client-ip=([0-9a-fA-F\.:]+)", text, re.IGNORECASE)
    if ip_match:
        result["ip"] = ip_match.group(1)

    return result


def parse_dkim_signature(dkim_signature: str) -> dict:
    result = {
        "domain": "",
        "selector": "",
        "algorithm": "",
        "canonicalization": "",
        "raw": dkim_signature.strip() if dkim_signature else "",
    }

    if not dkim_signature:
        return result

    d_match = re.search(r"\bd=([^;]+)", dkim_signature, re.IGNORECASE)
    s_match = re.search(r"\bs=([^;]+)", dkim_signature, re.IGNORECASE)
    a_match = re.search(r"\ba=([^;]+)", dkim_signature, re.IGNORECASE)
    c_match = re.search(r"\bc=([^;]+)", dkim_signature, re.IGNORECASE)

    if d_match:
        result["domain"] = extract_domain(d_match.group(1))
    if s_match:
        result["selector"] = s_match.group(1).strip()
    if a_match:
        result["algorithm"] = a_match.group(1).strip()
    if c_match:
        result["canonicalization"] = c_match.group(1).strip()

    return result


def extract_urls_from_header_values(values: list[str]) -> list[str]:
    urls = []
    for value in values:
        found = re.findall(r'https?://[^\s>,]+', value, re.IGNORECASE)
        urls.extend(found)
    return urls


def get_domain_from_urls(urls: list[str]) -> list[str]:
    domains = []
    for url in urls:
        try:
            parsed = urlparse(url)
            if parsed.netloc:
                domains.append(parsed.netloc.lower())
        except Exception:
            continue
    return domains


def get_org_domain(domain: str) -> str:
    if not domain:
        return ""

    parts = domain.lower().split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return domain.lower()

def build_header_sender_mapping(
    from_domain: str,
    return_path_domain: str,
    reply_to_domain: str,
    parsed_dkim: dict,
    parsed_received_spf: dict,
    dns_checks: dict
):
    spf_data = dns_checks.get("spf_domain", {})
    spf_analysis = spf_data.get("spf_analysis", {})

    dkim_domain = parsed_dkim.get("domain", "")
    dkim_selector = parsed_dkim.get("selector", "")
    spf_mailfrom = parsed_received_spf.get("mailfrom_domain", "")

    include_domains = spf_analysis.get("include_domains", [])
    direct_ip4 = spf_analysis.get("ip4_list", [])
    direct_ip6 = spf_analysis.get("ip6_list", [])
    expanded_ip4 = spf_analysis.get("expanded_ip4", [])
    expanded_ip6 = spf_analysis.get("expanded_ip6", [])

    observed_domains = []
    for item in [from_domain, return_path_domain, reply_to_domain, dkim_domain, spf_mailfrom]:
        if item and item not in observed_domains:
            observed_domains.append(item)

    needs_review = []

    if from_domain and return_path_domain and from_domain != return_path_domain:
        needs_review.append("Visible From domain and Return-Path domain are different. Confirm this is expected.")

    if dkim_selector and not dns_checks.get("dkim"):
        needs_review.append("A DKIM selector was seen in headers, but live DNS validation did not confirm it.")

    if not include_domains and not direct_ip4 and not direct_ip6:
        needs_review.append("No SPF sender sources were extracted from the validated SPF record.")
    
    risk_flags = []

    # 🚨 From vs Return-Path mismatch
    if from_domain and return_path_domain and from_domain != return_path_domain:
        risk_flags.append("From domain does not match Return-Path domain (possible third-party or spoofing scenario).")

    # 🚨 DKIM misalignment
    if from_domain and dkim_domain and from_domain != dkim_domain:
        risk_flags.append("DKIM domain is not aligned with From domain.")

    # 🚨 SPF mailfrom misalignment
    if from_domain and spf_mailfrom and from_domain != spf_mailfrom:
        risk_flags.append("SPF mailfrom domain is not aligned with From domain.")

    # 🚨 DKIM selector not validated
    if dkim_selector and not dns_checks.get("dkim"):
        risk_flags.append("DKIM selector found in headers but not validated via DNS.")

    # 🚨 From domain not in SPF include domains
    if from_domain and include_domains and from_domain not in include_domains:
        risk_flags.append("From domain not found in SPF include domains (may indicate external sender).")

    shadow_signals = []

    if from_domain and return_path_domain and from_domain != return_path_domain:
        shadow_signals.append("Return-Path domain differs from visible From domain.")

    if from_domain and dkim_domain and from_domain != dkim_domain:
        shadow_signals.append("DKIM domain differs from visible From domain.")

    if from_domain and spf_mailfrom and from_domain != spf_mailfrom:
        shadow_signals.append("SPF mailfrom domain differs from visible From domain.")

    if reply_to_domain and from_domain and reply_to_domain != from_domain:
        shadow_signals.append("Reply-To domain differs from visible From domain.")

    possible_shadow_sender = len(shadow_signals) >= 2

    return {
        "observed_domains": observed_domains,
        "from_domain": from_domain,
        "return_path_domain": return_path_domain,
        "reply_to_domain": reply_to_domain,
        "dkim_domain": dkim_domain,
        "dkim_selector": dkim_selector,
        "spf_mailfrom_domain": spf_mailfrom,
        "spf_include_domains": include_domains,
        "spf_direct_ip4": direct_ip4,
        "spf_direct_ip6": direct_ip6,
        "spf_expanded_ip4": expanded_ip4,
        "spf_expanded_ip6": expanded_ip6,
        "needs_review": needs_review,
        "risk_flags": risk_flags,
        "shadow_signals": shadow_signals,
        "possible_shadow_sender": possible_shadow_sender
    }

def analyze_headers(raw_headers: str):
    try:
        message = Parser(policy=policy.default).parsestr(raw_headers)
    except Exception as exc:
        return {
            "error": f"Could not parse headers: {exc}",
            "summary": ["The header format could not be parsed."]
        }

    from_header = get_header_value(message, "From")
    reply_to = get_header_value(message, "Reply-To")
    return_path = get_header_value(message, "Return-Path")
    subject = get_header_value(message, "Subject")
    list_unsubscribe_values = get_all_header_values(message, "List-Unsubscribe")
    auth_results = get_all_header_values(message, "Authentication-Results")
    received_spf = get_header_value(message, "Received-SPF")
    dkim_signature = get_header_value(message, "DKIM-Signature")
    received_headers = get_all_header_values(message, "Received")

    from_domain = extract_domain(from_header)
    reply_to_domain = extract_domain(reply_to)
    return_path_domain = extract_domain(return_path)

    parsed_auth = parse_authentication_results(auth_results)
    parsed_received_spf = parse_received_spf(received_spf)
    parsed_dkim = parse_dkim_signature(dkim_signature)

    list_unsub_urls = extract_urls_from_header_values(list_unsubscribe_values)
    list_unsub_domains = get_domain_from_urls(list_unsub_urls)

    visible_from_org = get_org_domain(from_domain)
    dkim_org = get_org_domain(parsed_dkim["domain"] or parsed_auth["dkim_domain"])
    spf_org = get_org_domain(parsed_received_spf["mailfrom_domain"] or parsed_auth["spf_domain"])

    alignment = {
        "spf_aligned": bool(visible_from_org and spf_org and visible_from_org == spf_org),
        "dkim_aligned": bool(visible_from_org and dkim_org and visible_from_org == dkim_org),
    }

    summary = []
    findings = []

    dmarc_result = parsed_auth["dmarc_result"]
    spf_result = parsed_auth["spf_result"]
    dkim_result = parsed_auth["dkim_result"]

    if dmarc_result == "pass":
        summary.append("DMARC passed based on Authentication-Results.")
    elif dmarc_result == "fail":
        summary.append("DMARC failed based on Authentication-Results.")
    else:
        summary.append("DMARC result was not clearly found in Authentication-Results.")

    if spf_result != "unknown":
        summary.append(f"SPF result: {spf_result}.")
    elif parsed_received_spf["result"] != "unknown":
        summary.append(f"SPF result inferred from Received-SPF: {parsed_received_spf['result']}.")
    else:
        summary.append("SPF result was not clearly found.")

    if dkim_result != "unknown":
        summary.append(f"DKIM result: {dkim_result}.")
    elif parsed_dkim["domain"]:
        summary.append("DKIM-Signature was found, but pass/fail result was not clearly shown.")
    else:
        summary.append("No clear DKIM result was found.")

    if from_domain:
        findings.append(f'Visible From domain: {from_domain}')
    if return_path_domain:
        findings.append(f"Return-Path domain: {return_path_domain}")
    if parsed_received_spf["mailfrom_domain"]:
        findings.append(f"Envelope sender / SPF mailfrom domain: {parsed_received_spf['mailfrom_domain']}")
    elif parsed_auth["spf_domain"]:
        findings.append(f"SPF mailfrom domain from Authentication-Results: {parsed_auth['spf_domain']}")

    if parsed_dkim["domain"]:
        findings.append(f"DKIM signing domain: {parsed_dkim['domain']}")
    elif parsed_auth["dkim_domain"]:
        findings.append(f"DKIM signing domain from Authentication-Results: {parsed_auth['dkim_domain']}")

    if parsed_dkim["selector"]:
        findings.append(f"DKIM selector: {parsed_dkim['selector']}")
    if parsed_dkim["algorithm"]:
        findings.append(f"DKIM algorithm: {parsed_dkim['algorithm']}")
    if parsed_received_spf["ip"]:
        findings.append(f"Client IP from Received-SPF: {parsed_received_spf['ip']}")

    if from_domain and visible_from_org:
        findings.append(f"Organizational domain of visible From: {visible_from_org}")

    if from_domain and from_domain != visible_from_org:
        findings.append(
            f"This appears to be a subdomain. Mailbox providers may apply the organizational domain policy of {visible_from_org}."
        )

    if alignment["spf_aligned"]:
        findings.append("SPF appears aligned with the visible From domain.")
    else:
        findings.append("SPF does not appear aligned with the visible From domain.")

    if alignment["dkim_aligned"]:
        findings.append("DKIM appears aligned with the visible From domain.")
    else:
        findings.append("DKIM does not appear aligned with the visible From domain.")

    if reply_to_domain:
        findings.append(f"Reply-To domain: {reply_to_domain}")

    if list_unsubscribe_values:
        findings.append("List-Unsubscribe header is present.")

    if list_unsub_domains:
        findings.append(f"List-Unsubscribe domains: {', '.join(sorted(set(list_unsub_domains)))}")

    findings.append(f"Received header count: {len(received_headers)}")

    remediation = []

    if dmarc_result == "fail":
        remediation.append("Check whether either SPF or DKIM is both passing and aligned with the visible From domain.")

    if not alignment["spf_aligned"]:
        remediation.append("Review the envelope sender / return-path domain and make sure it aligns with the visible From domain when SPF is the intended auth path.")

    if not alignment["dkim_aligned"]:
        remediation.append("Review the DKIM signing domain and selector. Make sure the signing domain aligns with the visible From domain.")

    if dkim_result == "unknown" and parsed_dkim["domain"]:
        remediation.append("A DKIM-Signature exists, but the final result is unclear. Review Authentication-Results from the receiving system.")

    if not auth_results:
        remediation.append("Authentication-Results header was not found. Results may be incomplete because many receivers add this header after delivery.")

    if not received_spf:
        remediation.append("Received-SPF header was not found. Some providers do not include it, so rely on Authentication-Results when available.")

    # 🔥 DNS ENRICHMENT (NEW)

    dns_checks = {}

    # DMARC check on exact From domain
    if from_domain:
        dns_checks["dmarc_from_domain"] = find_dmarc_record(from_domain)

    # DMARC fallback to organizational domain
    org_domain_dmarc = None
    if from_domain and visible_from_org and from_domain != visible_from_org:
        org_domain_dmarc = find_dmarc_record(visible_from_org)
        dns_checks["dmarc_org_domain"] = org_domain_dmarc

        exact_dmarc = dns_checks.get("dmarc_from_domain", {})
        if exact_dmarc.get("status") != "ok" and org_domain_dmarc.get("status") == "ok":
            findings.append(
                f'No DMARC record found for subdomain "{from_domain}". '
                f'The organizational domain appears to be "{visible_from_org}".'
            )
            findings.append(
                f'Inbox receivers may apply the DMARC policy from "{visible_from_org}".'
            )
            remediation.append(
                f'Review whether "{from_domain}" should publish its own DMARC record or rely on the organizational domain policy at "{visible_from_org}".'
            )

    # SPF check
    spf_domain_to_check = parsed_received_spf["mailfrom_domain"] or parsed_auth["spf_domain"]
    if spf_domain_to_check:
        dns_checks["spf_domain"] = find_spf_record(spf_domain_to_check)

    # DKIM check
    if parsed_dkim["domain"] and parsed_dkim["selector"]:
        dns_checks["dkim"] = check_dkim_selector(
            parsed_dkim["domain"],
            parsed_dkim["selector"]
        )

        sender_mapping = build_header_sender_mapping(
        from_domain,
        return_path_domain,
        reply_to_domain,
        parsed_dkim,
        parsed_received_spf,
        dns_checks
    )    

    return {
        "dns_checks": dns_checks,
        "from_header": from_header,
        "subject": subject,
        "from_domain": from_domain,
        "org_domain": visible_from_org,
        "return_path": return_path,
        "return_path_domain": return_path_domain,
        "reply_to": reply_to,
        "reply_to_domain": reply_to_domain,
        "authentication_results": auth_results,
        "received_spf": parsed_received_spf,
        "dkim_signature": parsed_dkim,
        "list_unsubscribe": list_unsubscribe_values,
        "list_unsubscribe_domains": sorted(set(list_unsub_domains)),
        "received_count": len(received_headers),
        "spf": {
            "result": spf_result if spf_result != "unknown" else parsed_received_spf["result"],
            "domain": parsed_received_spf["mailfrom_domain"] or parsed_auth["spf_domain"],
            "aligned": alignment["spf_aligned"],
        },
        "dkim": {
            "result": dkim_result,
            "domain": parsed_dkim["domain"] or parsed_auth["dkim_domain"],
            "selector": parsed_dkim["selector"],
            "algorithm": parsed_dkim["algorithm"],
            "aligned": alignment["dkim_aligned"],
        },
        "dmarc": {
            "result": dmarc_result,
            "header_from_domain": parsed_auth["dmarc_domain"] or from_domain,
        },
        "findings": findings,
        "summary": summary,
        "remediation": remediation,
        "sender_mapping": sender_mapping,
    }