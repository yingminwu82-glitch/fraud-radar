"""Conservative, deterministic country normalization and provider resolution."""
import re

ISO_ALPHA2 = set("AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ BA BB BD BE BF BG BH BI BJ BL BM BN BO BQ BR BS BT BV BW BY BZ CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV CW CX CY CZ DE DJ DK DM DO DZ EC EE EG EH ER ES ET FI FJ FK FM FO FR GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GS GT GU GW GY HK HM HN HR HT HU ID IE IL IM IN IO IQ IR IS IT JE JM JO JP KE KG KH KI KM KN KP KR KW KY KZ LA LB LC LI LK LR LS LT LU LV LY MA MC MD ME MF MG MH MK ML MM MN MO MP MQ MR MS MT MU MV MW MX MY MZ NA NC NE NF NG NI NL NO NP NR NU NZ OM PA PE PF PG PH PK PL PM PN PR PS PT PW PY QA RE RO RS RU RW SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS ST SV SX SY SZ TC TD TF TG TH TJ TK TL TM TN TO TR TT TV TW TZ UA UG UM US UY UZ VA VC VE VG VI VN VU WF WS YE YT ZA ZM ZW".split())
NAMES = {"united states":"US","united states of america":"US","usa":"US","united kingdom":"GB","uk":"GB","canada":"CA","china":"CN","japan":"JP","germany":"DE","france":"FR","india":"IN","australia":"AU","singapore":"SG","hong kong":"HK","south korea":"KR","korea, republic of":"KR"}

def normalize_country(value):
    if not isinstance(value,str): return None
    text=re.sub(r"\s+"," ",value.strip()).casefold()
    if not text: return None
    if len(text)==2 and text.upper() in ISO_ALPHA2: return text.upper()
    return NAMES.get(text)

def country_observations(provider_results):
    rows=[]
    for row in provider_results or []:
        raw=row.get("raw_result") or {}; provider=row.get("provider")
        attrs=raw.get("data",{}).get("attributes",{}) if isinstance(raw.get("data"),dict) else {}
        geo=raw.get("geo") if isinstance(raw.get("geo"),dict) else {}
        value=raw.get("countryCode") or raw.get("countryName") or geo.get("country_code") or geo.get("country") or attrs.get("country")
        code=normalize_country(value)
        rows.append({"provider":provider,"original_value":value,"country_code":code,"valid":code is not None})
    valid=[r for r in rows if r["valid"]]
    unique={r["country_code"] for r in valid}
    if not valid: consistency="INSUFFICIENT_DATA"; resolved=None
    elif len(valid)==1: consistency="LIMITED_DATA"; resolved=valid[0]["country_code"]
    elif len(unique)==1: consistency="CONSISTENT"; resolved=next(iter(unique))
    else: consistency="INCONSISTENT"; resolved=None
    return {"observations":rows,"provider_consistency":consistency,"resolved_ip_country":resolved}

def compare_transaction_country(resolution, transaction_country):
    target=normalize_country(transaction_country)
    ip_country=resolution.get("resolved_ip_country")
    if not target or not ip_country or resolution.get("provider_consistency")=="INCONSISTENT": return "INCONCLUSIVE"
    return "MATCH" if target==ip_country else "MISMATCH"
