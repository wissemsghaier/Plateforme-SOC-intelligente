import json

raw = json.loads(r"""$exec""")

if not isinstance(raw, dict):
    raise ValueError("Payload Wazuh invalide")

alert = raw.get("_source") or raw.get("all_fields") or raw
rule = alert.get("rule") or {}
decoder = alert.get("decoder") or {}
data = alert.get("data") or {}

groups = rule.get("groups") or []
if not isinstance(groups, list):
    raise ValueError("Format rule.groups invalide")

decoder_name = str(decoder.get("name") or "").lower()
sid = str(data.get("suricata_sid") or "").strip()

recognized = (
    "suricata" in [str(group).lower() for group in groups]
    or "suricata" in decoder_name
    or bool(sid)
)

if recognized and (not sid or sid.upper() == "NULL"):
    raise ValueError(
        "Evenement Suricata reconnu mais signature SID absente"
    )

print(json.dumps({
    "eligible": recognized,
    "reason": (
        "suricata_network_alert"
        if recognized else "outside_network_scope"
    ),
    "rule_id": str(rule.get("id") or ""),
    "decoder": decoder_name,
    "sid": sid,
}))