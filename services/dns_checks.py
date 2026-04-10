import base64
import dns.resolver

def get_txt_records(name: str):
    try:
        answers = dns.resolver.resolve(name, "TXT")
        records = []
        for rdata in answers:
            parts = []
            for item in rdata.strings:
                parts.append(item.decode("utf-8"))
            records.append("".join(parts))
        return {"found": True, "records": records}
    except Exception as exc:
        return {"found": False, "records": [], "error": str(exc)}
    
def expand_spf_includes(domain, visited=None, depth=0, max_depth=5):
    if visited is None:
        visited = set()

    if depth > max_depth or domain in visited:
        return {
            "ip4": [],
            "ip6": [],
            "includes": []
        }

    visited.add(domain)

    record = get_txt_records(domain)
    spf_record = None

    for r in record:
        if r.lower().startswith("v=spf1"):
            spf_record = r
            break

    if not spf_record:
        return {
            "ip4": [],
            "ip6": [],
            "includes": []
        }

    parts = spf_record.split()

    ip4 = []
    ip6 = []
    includes = []

    for part in parts:
        part = part.strip()

        if part.startswith(("ip4:", "+ip4:", "-ip4:", "~ip4:", "?ip4:")):
            ip4.append(part.split(":", 1)[1])

        elif part.startswith(("ip6:", "+ip6:", "-ip6:", "~ip6:", "?ip6:")):
            ip6.append(part.split(":", 1)[1])

        elif part.startswith(("include:", "+include:", "-include:", "~include:", "?include:")):
            include_domain = part.split(":", 1)[1]
            includes.append(include_domain)

    all_ip4 = list(ip4)
    all_ip6 = list(ip6)

    for inc in includes:
        result = expand_spf_includes(inc, visited, depth + 1, max_depth)
        all_ip4.extend(result["ip4"])
        all_ip6.extend(result["ip6"])

    return {
        "ip4": list(set(all_ip4)),
        "ip6": list(set(all_ip6)),
        "includes": includes
    }    

def analyze_spf_record(spf_record: str):
    if not spf_record:
        return {
            "lookup_count": 0,
            "include_count": 0,
            "a_count": 0,
            "mx_count": 0,
            "exists_count": 0,
            "redirect_count": 0,
            "status": "unknown",
            "details": "No SPF record provided.",
            "ip4_list": [],
            "ip6_list": [],
            "include_domains": [],
            "a_mechanisms": [],
            "mx_mechanisms": [],
            "exists_mechanisms": [],
            "redirect_target": ""
        }

    parts = [p.strip() for p in spf_record.split() if p.strip()]

    include_count = 0
    a_count = 0
    mx_count = 0
    exists_count = 0
    redirect_count = 0

    ip4_list = []
    ip6_list = []
    include_domains = []
    a_mechanisms = []
    mx_mechanisms = []
    exists_mechanisms = []
    redirect_target = ""

    for part in parts:
        lower_part = part.lower()

        # remove SPF qualifiers if present
        if lower_part[:1] in ["+", "-", "~", "?"]:
            lower_part = lower_part[1:]
            cleaned_part = part[1:]
        else:
            cleaned_part = part

        cleaned_lower = lower_part

        if cleaned_lower.startswith("ip4:"):
            ip4_list.append(cleaned_part.split(":", 1)[1])

        elif cleaned_lower.startswith("ip6:"):
            ip6_list.append(cleaned_part.split(":", 1)[1])

        elif cleaned_lower.startswith("include:"):
            include_count += 1
            include_domains.append(cleaned_part.split(":", 1)[1])

        elif cleaned_lower == "a":
            a_count += 1
            a_mechanisms.append("(current domain)")
        elif cleaned_lower.startswith("a:"):
            a_count += 1
            a_mechanisms.append(cleaned_part.split(":", 1)[1])

        elif cleaned_lower == "mx":
            mx_count += 1
            mx_mechanisms.append("(current domain)")
        elif cleaned_lower.startswith("mx:"):
            mx_count += 1
            mx_mechanisms.append(cleaned_part.split(":", 1)[1])

        elif cleaned_lower.startswith("exists:"):
            exists_count += 1
            exists_mechanisms.append(cleaned_part.split(":", 1)[1])

        elif cleaned_lower.startswith("redirect="):
            redirect_count += 1
            redirect_target = cleaned_part.split("=", 1)[1]

    lookup_count = include_count + a_count + mx_count + exists_count + redirect_count

    if lookup_count >= 10:
        status = "high"
        details = f"Estimated SPF DNS lookups: {lookup_count}. This may exceed the SPF 10-lookup limit and cause permerror."
    elif lookup_count >= 7:
        status = "warning"
        details = f"Estimated SPF DNS lookups: {lookup_count}. This is getting close to the SPF 10-lookup limit."
    else:
        status = "low"
        details = f"Estimated SPF DNS lookups: {lookup_count}. Current record appears within a safer range."

        expanded = expand_spf_includes(redirect_target if redirect_target else "")

        expanded_ip4 = expanded.get("ip4", [])
        expanded_ip6 = expanded.get("ip6", [])    
        
    optimization_findings = []
    optimization_recommendations = []

    duplicate_includes = sorted({x for x in include_domains if include_domains.count(x) > 1})
    duplicate_ip4 = sorted({x for x in ip4_list if ip4_list.count(x) > 1})
    duplicate_ip6 = sorted({x for x in ip6_list if ip6_list.count(x) > 1})

    if duplicate_includes:
        optimization_findings.append(
            f"Duplicate include domains detected: {', '.join(duplicate_includes)}"
        )
        optimization_recommendations.append(
            "Remove duplicate include mechanisms to simplify the SPF record."
        )

    if duplicate_ip4:
        optimization_findings.append(
            f"Duplicate ip4 entries detected: {', '.join(duplicate_ip4)}"
        )
        optimization_recommendations.append(
            "Remove duplicate ip4 entries from the SPF record."
        )

    if duplicate_ip6:
        optimization_findings.append(
            f"Duplicate ip6 entries detected: {', '.join(duplicate_ip6)}"
        )
        optimization_recommendations.append(
            "Remove duplicate ip6 entries from the SPF record."
        )

    if include_count >= 5:
        optimization_findings.append(
            f"High number of include mechanisms detected: {include_count}"
        )
        optimization_recommendations.append(
            "Review whether all include domains are still required. Too many includes increase lookup risk."
        )

    if lookup_count >= 7:
        optimization_recommendations.append(
            "Reduce DNS-lookup-triggering mechanisms where possible before the SPF record gets too close to the 10-lookup limit."
        )

    if redirect_target:
        optimization_findings.append(
            f"Redirect modifier present: {redirect_target}"
        )
        optimization_recommendations.append(
            "Confirm that the redirect target is intentional and still maintained."
        )

    if not ip4_list and not ip6_list and include_count == 0 and a_count == 0 and mx_count == 0 and exists_count == 0 and redirect_count == 0:
        optimization_findings.append("SPF record appears unusually minimal or incomplete.")
        optimization_recommendations.append(
            "Review whether the SPF record includes all legitimate sending methods."
        )

    if not optimization_findings:
        optimization_findings.append("No obvious SPF optimization issues were detected in the direct record.")

    if not optimization_recommendations:
        optimization_recommendations.append("Current SPF structure does not show obvious cleanup needs in the direct record.")    
    
    return {
        "lookup_count": lookup_count,
        "include_count": include_count,
        "a_count": a_count,
        "mx_count": mx_count,
        "exists_count": exists_count,
        "redirect_count": redirect_count,
        "status": status,
        "details": details,
        "ip4_list": ip4_list,
        "ip6_list": ip6_list,
        "include_domains": include_domains,
        "a_mechanisms": a_mechanisms,
        "mx_mechanisms": mx_mechanisms,
        "exists_mechanisms": exists_mechanisms,
        "redirect_target": redirect_target,
        "expanded_ip4": expanded_ip4,
        "expanded_ip6": expanded_ip6,
        "optimization_findings": optimization_findings,
        "optimization_recommendations": optimization_recommendations,
    }

def find_spf_record(domain: str):
    result = get_txt_records(domain)
    if not result["found"]:
        return {
            "status": "not_found",
            "record": None,
            "details": result.get("error", "No TXT records found"),
            "spf_analysis": {
                "lookup_count": 0,
                "include_count": 0,
                "a_count": 0,
                "mx_count": 0,
                "exists_count": 0,
                "redirect_count": 0,
                "status": "unknown",
                "details": "No SPF record found."
            }
        }

    spf_records = [r for r in result["records"] if r.lower().startswith("v=spf1")]
    if not spf_records:
        return {
            "status": "not_found",
            "record": None,
            "details": "No SPF record found",
            "spf_analysis": {
                "lookup_count": 0,
                "include_count": 0,
                "a_count": 0,
                "mx_count": 0,
                "exists_count": 0,
                "redirect_count": 0,
                "status": "unknown",
                "details": "No SPF record found."
            }
        }

    if len(spf_records) > 1:
        analysis = analyze_spf_record(spf_records[0])
        return {
            "status": "warning",
            "record": spf_records[0],
            "details": "Multiple SPF records found",
            "spf_analysis": analysis
        }

    analysis = analyze_spf_record(spf_records[0])

    return {
        "status": "ok",
        "record": spf_records[0],
        "details": "SPF record found",
        "spf_analysis": analysis
    }

def find_dmarc_record(domain: str):
    dmarc_domain = f"_dmarc.{domain}"
    result = get_txt_records(dmarc_domain)

    if not result["found"]:
        return {
            "status": "not_found",
            "record": None,
            "details": result.get("error", "No DMARC record found")
        }

    dmarc_records = [r for r in result["records"] if r.lower().startswith("v=dmarc1")]
    if not dmarc_records:
        return {
            "status": "not_found",
            "record": None,
            "details": "No DMARC record found"
        }

    record = dmarc_records[0]
    policy = "unknown"
    for part in record.split(";"):
        part = part.strip().lower()
        if part.startswith("p="):
            policy = part.split("=", 1)[1]
            break

    return {
        "status": "ok",
        "record": record,
        "policy": policy,
        "details": "DMARC record found"
    }

def estimate_dkim_key_length(dkim_record: str):
    try:
        parts = [p.strip() for p in dkim_record.split(";") if p.strip()]
        p_value = ""

        for part in parts:
            if part.lower().startswith("p="):
                p_value = part.split("=", 1)[1].strip()
                break

        if not p_value:
            return {
                "key_found": False,
                "key_length_bits": None,
                "strength": "missing",
                "details": "DKIM public key (p=) was not found."
            }

        padded = p_value + "=" * (-len(p_value) % 4)
        decoded = base64.b64decode(padded)

        key_length_bits = len(decoded) * 8

        if key_length_bits >= 2048:
            strength = "strong"
            details = f"Estimated DKIM key length is {key_length_bits} bits."
        elif key_length_bits >= 1024:
            strength = "warning"
            details = f"Estimated DKIM key length is {key_length_bits} bits. Consider moving to 2048-bit."
        else:
            strength = "weak"
            details = f"Estimated DKIM key length is {key_length_bits} bits. This appears weak."

        return {
            "key_found": True,
            "key_length_bits": key_length_bits,
            "strength": strength,
            "details": details
        }

    except Exception as exc:
        return {
            "key_found": False,
            "key_length_bits": None,
            "strength": "unknown",
            "details": f"Could not estimate DKIM key length: {exc}"
        }

def check_dkim_selector(domain: str, selector: str):
    dkim_name = f"{selector}._domainkey.{domain}"
    result = get_txt_records(dkim_name)

    if not result["found"]:
        return {
            "selector": selector,
            "status": "not_found",
            "record": None,
            "details": result.get("error", "Selector not found"),
            "key_info": {
                "key_found": False,
                "key_length_bits": None,
                "strength": "missing",
                "details": "No DKIM record found."
            }
        }

    dkim_records = [r for r in result["records"] if "v=DKIM1" in r or "p=" in r]
    if not dkim_records:
        return {
            "selector": selector,
            "status": "warning",
            "record": None,
            "details": "TXT found but does not look like DKIM",
            "key_info": {
                "key_found": False,
                "key_length_bits": None,
                "strength": "unknown",
                "details": "TXT record found, but DKIM public key could not be identified."
            }
        }

    record = dkim_records[0]
    key_info = estimate_dkim_key_length(record)

    return {
        "selector": selector,
        "status": "ok",
        "record": record,
        "details": "DKIM selector found",
        "key_info": key_info
    }

def calculate_health_score(dmarc: dict, spf: dict, dkim_results: list):
    score = 100
    reasons = []

    # DMARC
    if dmarc.get("status") != "ok":
        score -= 35
        reasons.append("DMARC record missing or invalid.")
    else:
        policy = str(dmarc.get("policy", "")).lower()
        if policy == "none":
            score -= 10
            reasons.append("DMARC policy is set to none.")
        elif policy == "quarantine":
            score -= 5
            reasons.append("DMARC policy is quarantine, not full reject.")
        elif policy == "reject":
            reasons.append("DMARC policy is reject.")
        else:
            score -= 8
            reasons.append("DMARC policy is unclear.")

    # SPF
    if spf.get("status") == "not_found":
        score -= 25
        reasons.append("SPF record missing.")
    elif spf.get("status") == "warning":
        score -= 15
        reasons.append("Multiple SPF records found.")
    else:
        reasons.append("SPF record found.")

    spf_analysis = spf.get("spf_analysis", {})
    spf_risk = spf_analysis.get("status", "unknown")
    if spf_risk == "high":
        score -= 15
        reasons.append("SPF lookup count is high and may cause permerror.")
    elif spf_risk == "warning":
        score -= 8
        reasons.append("SPF lookup count is getting close to the limit.")
    elif spf_risk == "low":
        reasons.append("SPF lookup count appears healthy.")

    # DKIM
    if not dkim_results:
        score -= 15
        reasons.append("No DKIM selectors were tested.")
    else:
        bad_selectors = 0
        weak_keys = 0

        for item in dkim_results:
            if item.get("status") != "ok":
                bad_selectors += 1

            key_info = item.get("key_info", {})
            strength = key_info.get("strength", "unknown")

            if strength == "weak":
                weak_keys += 1
            elif strength == "warning":
                weak_keys += 0.5

        if bad_selectors > 0:
            score -= min(20, bad_selectors * 10)
            reasons.append(f"{bad_selectors} DKIM selector(s) missing or invalid.")
        else:
            reasons.append("All tested DKIM selectors were found.")

        if weak_keys > 0:
            score -= min(15, int(weak_keys * 8))
            reasons.append("One or more DKIM keys appear weak or below preferred strength.")
        else:
            reasons.append("DKIM key strength looks healthy for tested selectors.")

    # Clamp score
    if score < 0:
        score = 0
    if score > 100:
        score = 100

    # Label
    if score >= 90:
        label = "Excellent"
    elif score >= 75:
        label = "Good"
    elif score >= 55:
        label = "Fair"
    else:
        label = "Poor"

    return {
        "score": score,
        "label": label,
        "reasons": reasons
    }

def get_policy_progression_recommendation(dmarc: dict, spf: dict, dkim_results: list, health: dict):
    recommendations = []

    dmarc_status = dmarc.get("status", "unknown")
    current_policy = str(dmarc.get("policy", "")).lower()
    health_score = health.get("score", 0)

    spf_ok = spf.get("status") == "ok"
    spf_analysis = spf.get("spf_analysis", {})
    spf_risk = spf_analysis.get("status", "unknown")

    dkim_valid_count = 0
    dkim_weak_found = False

    for item in dkim_results:
        if item.get("status") == "ok":
            dkim_valid_count += 1

        key_info = item.get("key_info", {})
        if key_info.get("strength") in ["weak", "warning"]:
            dkim_weak_found = True

    if dmarc_status != "ok":
        recommendations.append("No valid DMARC record was found. Start by publishing a DMARC record with p=none for monitoring.")
        recommendations.append("Before moving beyond p=none, confirm that SPF and DKIM are working for all approved senders.")
        return recommendations

    if current_policy == "none":
        if health_score >= 80 and spf_ok and spf_risk != "high" and dkim_valid_count > 0 and not dkim_weak_found:
            recommendations.append("Current DMARC policy is p=none. Based on the current posture, consider moving to p=quarantine next.")
            recommendations.append("Before changing policy, confirm that all legitimate senders are passing SPF or DKIM alignment.")
        else:
            recommendations.append("Current DMARC policy is p=none. Stay at monitoring mode for now until SPF/DKIM posture improves.")
            recommendations.append("Focus first on SPF health, valid DKIM selectors, and stronger DKIM keys before moving to p=quarantine.")

    elif current_policy == "quarantine":
        if health_score >= 90 and spf_ok and spf_risk == "low" and dkim_valid_count > 0 and not dkim_weak_found:
            recommendations.append("Current DMARC policy is p=quarantine. Posture looks strong enough to consider moving to p=reject.")
            recommendations.append("Before moving to p=reject, verify that all legitimate third-party senders are fully aligned.")
        else:
            recommendations.append("Current DMARC policy is p=quarantine. Keep this policy for now while improving remaining SPF/DKIM issues.")
            recommendations.append("Do not move to p=reject until authentication results are consistently healthy.")

    elif current_policy == "reject":
        recommendations.append("Current DMARC policy is p=reject. This is the strongest enforcement posture.")
        recommendations.append("Continue monitoring SPF complexity, DKIM key strength, and new senders to avoid future delivery problems.")

    else:
        recommendations.append("DMARC policy was found, but it is unclear. Review the DMARC record syntax and confirm the intended enforcement stage.")

    return recommendations

def get_common_dkim_selectors():
    return [
        "selector1",
        "selector2",
        "default",
        "google",
        "dkim",
        "s1",
        "s2",
        "k1",
        "mail",
        "m1",
        "m2"
    ]

def build_domain_sender_mapping(domain: str, spf: dict, dkim_results: list):
    spf_analysis = spf.get("spf_analysis", {})

    include_domains = spf_analysis.get("include_domains", [])
    direct_ip4 = spf_analysis.get("ip4_list", [])
    direct_ip6 = spf_analysis.get("ip6_list", [])
    expanded_ip4 = spf_analysis.get("expanded_ip4", [])
    expanded_ip6 = spf_analysis.get("expanded_ip6", [])

    valid_dkim = []
    invalid_dkim = []

    for item in dkim_results:
        selector = item.get("selector", "")
        status = item.get("status", "unknown")

        if status == "ok":
            valid_dkim.append(selector)
        else:
            invalid_dkim.append(selector)

    needs_review = []

    if not include_domains and not direct_ip4 and not direct_ip6:
        needs_review.append("No obvious SPF sender sources were identified.")

    if invalid_dkim:
        needs_review.append(f"Some DKIM selectors did not validate: {', '.join(invalid_dkim)}")

    if not valid_dkim:
        needs_review.append("No valid DKIM selectors were identified from the tested list.")

    return {
        "domain": domain,
        "spf_include_domains": include_domains,
        "spf_direct_ip4": direct_ip4,
        "spf_direct_ip6": direct_ip6,
        "spf_expanded_ip4": expanded_ip4,
        "spf_expanded_ip6": expanded_ip6,
        "dkim_valid_selectors": valid_dkim,
        "dkim_invalid_selectors": invalid_dkim,
        "needs_review": needs_review
    }

def analyze_domain(domain: str, selectors: list[str]):
    dmarc = find_dmarc_record(domain)
    spf = find_spf_record(domain)

    auto_discovered = False

    if selectors:
        selectors_to_test = selectors
    else:
        selectors_to_test = get_common_dkim_selectors()
        auto_discovered = True

    dkim_results = [check_dkim_selector(domain, s) for s in selectors_to_test]

    summary = []

    if dmarc["status"] != "ok":
        summary.append("Critical: DMARC record missing.")
    else:
        summary.append(f"DMARC policy is {dmarc.get('policy', 'unknown')}.")

    if spf["status"] == "not_found":
        summary.append("Critical: SPF record missing.")
    elif spf["status"] == "warning":
        summary.append("Warning: Multiple SPF records found.")
    else:
        summary.append("SPF record found.")

    valid_dkim = [x["selector"] for x in dkim_results if x["status"] == "ok"]
    missing_dkim = [x["selector"] for x in dkim_results if x["status"] != "ok"]

    if auto_discovered:
        if valid_dkim:
            summary.append(f"Auto-discovered DKIM selectors found: {', '.join(valid_dkim)}")
        else:
            summary.append("No common DKIM selectors were auto-discovered.")
    else:
        if selectors:
            if missing_dkim:
                summary.append(f"Warning: DKIM selectors not found or invalid: {', '.join(missing_dkim)}")
            else:
                summary.append("All provided DKIM selectors were found.")
        else:
            summary.append("No DKIM selectors were provided for testing.")

    health = calculate_health_score(dmarc, spf, dkim_results)
    policy_recommendations = get_policy_progression_recommendation(dmarc, spf, dkim_results, health)
    sender_mapping = build_domain_sender_mapping(domain, spf, dkim_results)

    return {
        "dmarc": dmarc,
        "spf": spf,
        "dkim": dkim_results,
        "summary": summary,
        "health": health,
        "policy_recommendations": policy_recommendations,
        "auto_discovered": auto_discovered,
        "valid_dkim_selectors": valid_dkim,
        "missing_dkim_selectors": missing_dkim,
        "sender_mapping": sender_mapping
    }