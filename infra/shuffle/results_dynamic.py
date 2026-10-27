import json
import ast

raw = r'''$getjobresult_3'''

def load_jobs(text):
    try:
        return json.loads(text, strict=False)
    except Exception:
        return ast.literal_eval(text)

jobs = load_jobs(raw)
if isinstance(jobs, dict):
    jobs = [jobs]
if not isinstance(jobs, list):
    raise Exception("Format inattendu: liste de jobs attendue")

abuse_score = None
abuse_reports = None
misp_count = 0
vt_malicious = 0
vt_suspicious = 0
vt_harmless = 0
vt_undetected = 0

for j in jobs:
    body = (j or {}).get("body", {}) or {}
    analyzer = str(body.get("analyzerName", ""))
    status = body.get("status", "Unknown")
    full = (((body.get("report", {}) or {}).get("full", {})) or {})

    if status != "Success":
        continue

    # AbuseIPDB
    if "AbuseIPDB" in analyzer:
        values = full.get("values") or []
        if values and isinstance(values[0], dict):
            data = values[0].get("data", {}) or {}
            abuse_score = data.get("abuseConfidenceScore", 0)
            abuse_reports = data.get("totalReports", 0)

    # MISP
    elif "MISP" in analyzer:
        uuids = set()
        for inst in full.get("results") or []:
            if isinstance(inst, dict):
                for ev in inst.get("result") or []:
                    if isinstance(ev, dict) and ev.get("uuid"):
                        uuids.add(ev["uuid"])
        misp_count = len(uuids)

    # VirusTotal
    elif "VirusTotal" in analyzer:
        stats = ((full.get("attributes", {}) or {}).get("last_analysis_stats", {}) or {})
        vt_malicious = stats.get("malicious", 0) or 0
        vt_suspicious = stats.get("suspicious", 0) or 0
        vt_harmless = stats.get("harmless", 0) or 0
        vt_undetected = stats.get("undetected", 0) or 0

# Sévérité simple
severity = "LOW"
if (isinstance(abuse_score, (int, float)) and abuse_score >= 50) or vt_malicious > 0 or vt_suspicious > 0:
    severity = "HIGH"
elif (isinstance(abuse_score, (int, float)) and abuse_score > 0) or misp_count > 0:
    severity = "MEDIUM"

# Résumé court Telegram
lines = []
lines.append("🚨 SOC Alert Summary")
lines.append(f"Case: $exec._id")
lines.append(f"Observable: $exec.data ($exec.dataType)")
lines.append(f"AbuseIPDB score/reports: {abuse_score if abuse_score is not None else 'N/A'}/{abuse_reports if abuse_reports is not None else 'N/A'}")
lines.append(f"MISP matches: {misp_count}")
lines.append(f"VT m/s/h/u: {vt_malicious}/{vt_suspicious}/{vt_harmless}/{vt_undetected}")
lines.append(f"Severity: {severity}")
lines.append("Decision required: APPROVE or REJECT")

print("\n".join(lines))