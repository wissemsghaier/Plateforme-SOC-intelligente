import json

def to_obj(x):
    if isinstance(x, dict):
        return x
    if isinstance(x, str):
        try:
            return json.loads(x)
        except Exception:
            return {}
    return {}

ml_resp = to_obj(r"""$call_ml_api""")
enr = to_obj(r"""$build_ml_enrichment.message""")

status = ml_resp.get("status")
body = ml_resp.get("body")
body_obj = to_obj(body)

ml = body_obj if (status == 200 or str(status) == "200") else {}

# fallback niveau Wazuh depuis enrichment.alert.rule.level
rule_level = 0
try:
    rule_level = int(((enr.get("alert") or {}).get("rule") or {}).get("level") or 0)
except Exception:
    rule_level = 0

try:
    risk = float(ml["risk_score"])
    ml_status = "ok"
except Exception:
    risk = min(rule_level * 6, 100)
    ml_status = "unavailable"

misp_hits = int(enr.get("enrichment", {}).get("misp_hits", 0) or 0)
vt_mal = int(enr.get("enrichment", {}).get("vt_malicious", 0) or 0)

if misp_hits > 0:
    risk = max(risk, 60)
if vt_mal > 0:
    risk = max(risk, 80)
risk = min(risk, 100)

if risk >= 80:
    bucket, severity = "critical", 4
elif risk >= 60:
    bucket, severity = "high", 3
elif risk >= 40:
    bucket, severity = "medium", 2
else:
    bucket, severity = "low", 1

print(json.dumps({
    "risk_score": risk,
    "bucket": bucket,
    "severity": severity,
    "ml_status": ml_status,
    "category": ml.get("category", "unknown"),
    "confidence": ml.get("confidence"),
    "countermeasure": ml.get("countermeasure"),
}))