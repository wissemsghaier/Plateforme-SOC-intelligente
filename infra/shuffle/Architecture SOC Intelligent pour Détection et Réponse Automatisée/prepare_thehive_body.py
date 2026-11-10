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

decision = to_obj(r"""$dedup_decision.message""")
event = to_obj(r"""$normalize_event.message""")
enr = to_obj(r"""$build_ml_enrichment.message""")
prio = to_obj(r"""$priority_policy.message""")
misp = to_obj(r"""$misp_lookup.message""")
cortex = to_obj(r"""$cortex_analyze.message""")

action = decision.get("action")
if action not in ("create", "update"):
    raise ValueError("Decision inattendue: action absente ou invalide")

metadata = decision.get("metadata") or {}
metadata_tags = metadata.get("tags") or []
metadata_custom_fields = metadata.get("customFields") or {}

rule_id = event.get("rule_id", "unknown")
rule_desc = event.get("rule_description") or "Alerte reseau"
alert_id = event.get("alert_id", "unknown")
timestamp = event.get("timestamp", "unknown")

src_ip = event.get("src_ip", "n/a")
dst_ip = event.get("dst_ip", "n/a")
dst_port = event.get("dst_port", "n/a")
protocol = event.get("protocol", "n/a")
sid = event.get("sid", "n/a")
sensor = event.get("sensor", "n/a")

category = prio.get("category", "unknown")
confidence = prio.get("confidence")
risk_score = prio.get("risk_score", 0)
bucket = str(prio.get("bucket", "low")).lower()
severity = int(prio.get("severity", 1))
ml_status = prio.get("ml_status", "unavailable")
countermeasure = prio.get("countermeasure") or "Aucune recommandation"

# borne sécurité TheHive severity
if severity < 1:
    severity = 1
elif severity > 4:
    severity = 4

tags = list(metadata_tags)
extra_tags = [
    f"ml:{category}",
    f"risk:{bucket}",
    f"rule:{rule_id}",
]
for t in extra_tags:
    if t not in tags:
        tags.append(t)

verdict_lines = []
for v in cortex.get("verdicts", []) or []:
    analyzer = v.get("analyzer", "unknown")
    ip = v.get("ip", "n/a")
    level = v.get("level", "n/a")
    value = v.get("value", "n/a")
    verdict_lines.append(f"- {analyzer} ({ip}) : {level} {value}")
verdicts = "\n".join(verdict_lines) if verdict_lines else "- aucun"

misp_status = misp.get("status", "unknown")
misp_hits = misp.get("misp_hits", 0)
misp_event_ids = misp.get("event_ids") or []
misp_event_ids_text = ", ".join(map(str, misp_event_ids)) if misp_event_ids else "aucun"

cortex_status = cortex.get("status", "unknown")
enrichment_status = enr.get("enrichment_status", "unknown")

description = f"""### Evenement reseau
- Regle : {rule_id} - {rule_desc}
- SID : {sid}
- Source : {src_ip} -> Destination : {dst_ip}:{dst_port} ({protocol})
- Capteur : {sensor}
- Alerte Wazuh : {alert_id} ({timestamp})

### Analyse ML ({ml_status})
- Categorie : {category} (confiance {confidence})
- Score de risque : {risk_score} -> {bucket.upper()}
- Contre-mesure : {countermeasure}

### MISP ({misp_status})
- Correspondances : {misp_hits}
- Evenements : {misp_event_ids_text}

### Cortex ({cortex_status})
{verdicts}

Enrichissement : {enrichment_status}
"""

if action == "create":
    source_ref = decision.get("source_ref")
    if not source_ref:
        raise ValueError("source_ref absent pour action=create")

    body = {
        "type": "wazuh",
        "source": "wazuh",
        "sourceRef": source_ref,
        "title": f"[WAZUH] {rule_id} - {rule_desc}",
        "description": description,
        "severity": severity,
        "tags": tags,
        "customFields": metadata_custom_fields,
    }

else:  # update
    target_alert_id = decision.get("target_alert_id")
    if not target_alert_id:
        raise ValueError("Identifiant TheHive absent pour action=update")

    body = {
        "addTags": tags,
        "customFields": metadata_custom_fields,
    }

print(json.dumps({
    "action": action,
    "target_alert_id": decision.get("target_alert_id"),
    "body": json.dumps(body, ensure_ascii=False),
}, ensure_ascii=False))