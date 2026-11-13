from app.services.risk_engine.category_mapping import evidence_coverage, normalize_provider
from app.services.risk_engine.geography import country_observations, compare_transaction_country, normalize_country


def test_coverage_counts_logical_types_not_duplicate_providers():
    cat={"category":"ip_reputation","score":30,"evidence":[{"factor":"Fraud score","score":30,"providers":["FFraud","IP-DB"]}]}
    out=evidence_coverage(cat,{"FFraud":"success","IP-DB":"success","VirusTotal":"success"})
    assert out["valid_signal_count"]==1 and out["total_expected_signal_count"]==3
    assert out["evidence_coverage"]==1/3


def test_coverage_ignores_context_only_and_null_evidence():
    cat={"category":"geographic_risk","score":None,"evidence":[{"factor":"Context: ASN","score":None,"providers":["IP-DB"]}]}
    out=evidence_coverage(cat,{"FFraud":"success","IP-DB":"success","VirusTotal":"success"})
    assert out["valid_signal_count"]==0 and out["evidence_coverage"]==0
    assert out["evidence_status"]=="Insufficient Data"


def test_country_code_name_and_provider_conflict_resolution():
    assert normalize_country("United States")=="US"
    assert normalize_country("ZZ") is None
    same=country_observations([{"provider":"IP-DB","raw_result":{"countryCode":"US"}},{"provider":"VirusTotal","raw_result":{"data":{"attributes":{"country":"United States"}}}}])
    assert same["provider_consistency"]=="CONSISTENT"
    assert compare_transaction_country(same,"US")=="MATCH"
    conflict=country_observations([{"provider":"IP-DB","raw_result":{"countryCode":"US"}},{"provider":"VirusTotal","raw_result":{"data":{"attributes":{"country":"CA"}}}}])
    assert conflict["provider_consistency"]=="INCONSISTENT" and conflict["resolved_ip_country"] is None
    assert compare_transaction_country(conflict,"US")=="INCONCLUSIVE"


def test_transaction_amount_and_velocity_are_distinct_registry_signals():
    out=evidence_coverage({"category":"transaction_behavior","score":1,"evidence":[{"factor":"Transaction Amount","score":1,"providers":["Transaction Context"]}]})
    assert out["valid_signal_count"]==1 and out["total_expected_signal_count"]==2
