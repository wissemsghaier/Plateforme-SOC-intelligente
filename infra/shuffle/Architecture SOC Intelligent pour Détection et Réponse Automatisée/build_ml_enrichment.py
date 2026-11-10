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

def to_int(value, default=0):
    try:
        n = int(float(value))
        return n if n >= 0 else default
    except Exception:
        return default

def pick(*values):
    for v in values:
        if v not in (None, "", "NULL"):
            return v
    return None

# Entrées
event = to_obj(r"""$normalize_event.message""")
misp = to_obj(r"""$misp_lookup.message""")
cortex = to_obj(r"""$cortex_analyze.message""")
exec_data = to_obj(r"""$exec""")

all_fields = (exec_data.get("all_fields") or {})
exec_rule = (all_fields.get("rule") or {})
exec_agent = (all_fields.get("agent") or {})
exec_data_fields = (all_fields.get("data") or {})

base_alert = event.get("alert") if isinstance(event.get("alert"), dict) else {}
base_rule = (base_alert.get("rule") or {})
base_agent = (base_alert.get("agent") or {})
base_agent_os = (base_agent.get("os") or {})
base_data = (base_alert.get("data") or {})

# Valeurs robustes (plusieurs sources)
rule_id = pick(base_rule.get("id"), event.get("rule_id"), exec_rule.get("id"))
rule_level = to_int(pick(base_rule.get("level"), event.get("rule_level"), exec_rule.get("level")), 0)
rule_fired = to_int(pick(base_rule.get("firedtimes"), event.get("rule_firedtimes"), exec_rule.get("firedtimes")), 1)

timestamp = pick(base_alert.get("timestamp"), event.get("timestamp"), all_fields.get("timestamp"))
agent_name = pick(base_agent.get("name"), event.get("agent_name"), exec_agent.get("name"), "")
agent_os_name = pick(base_agent_os.get("name"), event.get("agent_os_name"), "")
src_ip = pick(base_data.get("srcip"), event.get("src_ip"), exec_data_fields.get("srcip"))

# Alert final pour ML
alert_for_ml = {
    "timestamp": timestamp,
    "rule": {
        "id": rule_id,
        "level": rule_level,
        "firedtimes": rule_fired,
    },
    "agent": {
        "name": agent_name,
        "os": {"name": agent_os_name},
    },
    "data": {
        "srcip": src_ip
    },
}

# Enrichment (ce que ton ML utilise)
enrichment = {
    "misp_hits": to_int(misp.get("misp_hits", 0), 0),
    "vt_malicious": to_int(cortex.get("vt_malicious", 0), 0),
}

partial = (misp.get("status") == "error") or (cortex.get("status") in ("error", "partial"))
enrichment_status = "partial" if partial else "complete"

print(json.dumps({
    "alert": alert_for_ml,
    "enrichment": enrichment,
    "enrichment_status": enrichment_status
}, ensure_ascii=False))