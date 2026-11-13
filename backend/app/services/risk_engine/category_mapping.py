"""Provider normalization and distinct logical-signal coverage registry."""
from app.schemas.risk import NormalizedSignal
from app.services.risk_engine.thresholds import classify_risk

RELIABILITY = {"FFraud": .82, "IP-DB": .78, "VirusTotal": .84}

LOGICAL_SIGNALS = {
    "ip_reputation": [
        ("ip_reputation", "IP Reputation", ("Fraud score", "Abuse confidence"), ("FFraud", "IP-DB")),
        ("abuse_history", "Abuse History", ("Known abuser", "Recent abuse"), ("FFraud",)),
        ("community_reputation", "Community Reputation", ("Community reputation",), ("VirusTotal",)),
    ],
    "network_anonymity": [
        ("vpn", "VPN", ("VPN",), ("FFraud",)), ("proxy", "Proxy", ("Proxy",), ("FFraud",)),
        ("tor", "Tor", ("Tor",), ("FFraud",)),
        ("network_type", "Network Type", ("Network type",), ("IP-DB",)),
    ],
    "malicious_infrastructure": [
        ("malicious_scan", "Malicious Scan", ("Malicious scan ratio",), ("VirusTotal",)),
        ("blacklist", "Blacklist", ("Blacklist sources",), ("IP-DB",)),
        ("dnsbl", "DNSBL", ("DNSBL",), ("IP-DB",)),
    ],
    "geographic_risk": [
        ("user_transaction_country_comparison", "User/Transaction Country Comparison", ("Country Mismatch",), ("Transaction Context",)),
        ("ip_transaction_country_comparison", "IP/Transaction Country Comparison", ("IP Country Mismatch",), ("Resolved IP Country",)),
    ],
    "transaction_behavior": [
        ("transaction_amount", "Transaction Amount", ("Transaction Amount",), ("Transaction Context",)),
        ("transaction_velocity", "Transaction Velocity", ("Transaction Velocity",), ("Transaction Context",)),
    ],
    "account_characteristics": [("account_age", "Account Age", ("Account Age",), ("Transaction Context",))],
}

DIMENSION_NAMES = {"ip_reputation":"IP Reputation Risk","network_anonymity":"Network Anonymity Risk","malicious_infrastructure":"Malicious Infrastructure Risk","geographic_risk":"Geographic Consistency Risk","transaction_behavior":"Transaction Behaviour Risk","account_characteristics":"Account Profile Risk"}


def _signal(provider, category, factor, value, score, confidence=1.0):
    return NormalizedSignal(provider=provider, category=category, factor=factor, value=value, risk_score=score, confidence=confidence, missing=score is None)


def normalize_provider(provider: str, raw: dict) -> list[NormalizedSignal]:
    out=[]; conf=RELIABILITY[provider]
    def add(category, factor, value, score, confidence=conf): out.append(_signal(provider,category,factor,value,score,confidence))
    if provider == "FFraud":
        completeness={"high":1.0,"medium":.75,"low":.5}.get(str(raw.get("confidence","")).lower(),conf)
        score=raw.get("fraud_score")
        if isinstance(score,(int,float)) and not isinstance(score,bool) and 0 <= score <= 100:
            add("ip_reputation","Fraud score",score,float(score),completeness)
        for field,label,category,level in [("vpn","VPN","network_anonymity",80),("proxy","Proxy","network_anonymity",80),("tor","Tor","network_anonymity",90),("hosting","Hosting","malicious_infrastructure",55),("is_abuser","Known abuser","ip_reputation",90),("recent_abuse","Recent abuse","ip_reputation",75)]:
            if isinstance(raw.get(field),bool): add(category,label,raw[field],level if raw[field] else 0,completeness)
        if "threat_tags" in raw and isinstance(raw["threat_tags"],list) and raw["threat_tags"]: add("malicious_infrastructure","Threat tags",raw["threat_tags"],70,completeness)
    elif provider == "IP-DB":
        score=raw.get("abuseConfidenceScore")
        if isinstance(score,(int,float)) and not isinstance(score,bool) and 0 <= score <= 100: add("ip_reputation","Abuse confidence",score,float(score))
        if isinstance(raw.get("blacklistSources"),list) and raw["blacklistSources"]: add("malicious_infrastructure","Blacklist sources",raw["blacklistSources"],85)
        network=raw.get("networkType")
        if isinstance(network,str) and network.strip():
            kind=network.strip().lower(); score=85 if kind in {"vpn","tor","proxy"} else 55 if kind in {"hosting","datacenter"} else None
            if score is not None: add("network_anonymity","Network type",network,score)
    else:
        attrs=raw.get("data",{}).get("attributes",{})
        if not isinstance(attrs,dict): return out
        reputation=attrs.get("reputation")
        if isinstance(reputation,(int,float)) and not isinstance(reputation,bool): add("ip_reputation","Community reputation",reputation,min(100,max(0,-float(reputation))))
        stats=attrs.get("last_analysis_stats")
        if isinstance(stats,dict):
            keys=("malicious","suspicious","harmless","undetected","timeout")
            if all(isinstance(stats.get(k),int) and stats[k]>=0 for k in keys if k in stats) and any(k in stats for k in keys):
                total=sum(stats.get(k,0) for k in keys); bad=stats.get("malicious",0)+.5*stats.get("suspicious",0)
                add("malicious_infrastructure","Malicious scan ratio",stats,min(100,bad/total*400) if total else None,min(1,RELIABILITY[provider]+total/100))
    return out


def evidence_coverage(category: dict, provider_states: dict[str, str] | None = None) -> dict:
    key=category["category"]; registry=LOGICAL_SIGNALS[key]
    evidence=category.get("evidence",[])
    present={(item.get("factor"), p) for item in evidence if item.get("score") is not None for p in item.get("providers",[])}
    available=[]; missing=[]
    for signal_id,label,factors,providers in registry:
        if any((factor,provider) in present for factor in factors for provider in providers): available.append({"signal_id":signal_id,"display_name":label})
        else: missing.append({"signal_id":signal_id,"display_name":label})
    states=provider_states or {}
    relevant={p for row in registry for p in row[3] if p in states}
    failed=bool(relevant) and all(states[p] not in {"success","mock"} for p in relevant)
    status="Provider Unavailable" if failed and not available else "Insufficient Data" if not available else "Limited Data" if len(available)<len(registry) else "Sufficient Data"
    score=category.get("score")
    return {"dimension_id":key,"dimension_name":DIMENSION_NAMES[key],"risk_score":score,"risk_level":classify_risk(score) if score is not None else "N/A","evidence_status":status,"available_signal_types":available,"missing_signal_types":missing,"valid_signal_count":len(available),"total_expected_signal_count":len(registry),"evidence_coverage":len(available)/len(registry) if registry else 0,"supporting_evidence":evidence}
